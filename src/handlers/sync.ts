import { MatrixError } from "../errors.ts";
import { matchesRoomEventFilter } from "../event-filter.ts";
import { pduToClientEvent, toStripped } from "../events.ts";
import { getIgnoredInviteSenders } from "../ignored-invites.ts";
import { getIgnoredUsers } from "../ignored-users.ts";
import { evaluatePushRules, getOrInitRules } from "../push-rules.ts";
import { bundleAggregations } from "../relations.ts";
import type { Handler } from "../router.ts";
import type { Storage } from "../storage/interface.ts";
import type { ClientEvent, PDU, StrippedStateEvent } from "../types/events.ts";
import type {
	RoomEventFilter,
	StateFilter,
	SyncFilter,
} from "../types/filters.ts";
import type { DeviceId, EventId, RoomId, UserId } from "../types/index.ts";
import type { PushRulesContent } from "../types/push.ts";
import type { RoomPowerLevelsContent } from "../types/state-events.ts";
import type {
	DeviceLists,
	InvitedRoom,
	JoinedRoom,
	KnockedRoom,
	LeftRoom,
	RoomSummary,
	SyncResponse,
	UnreadNotificationCounts,
} from "../types/sync.ts";

/**
 * Build the `rooms.knock` entry for a room the user has knocked on. Prefers the
 * stripped state stashed on the knock event's `unsigned.knock_room_state` (set
 * for federated knocks); otherwise falls back to the room's stripped state, and
 * always ensures the knocking user's own member event (carrying the knock
 * `reason`) is present.
 */
const buildKnockRoom = async (
	storage: Storage,
	roomId: RoomId,
	userId: UserId,
): Promise<KnockedRoom> => {
	const memberEvt = await storage.getStateEvent(
		roomId,
		"m.room.member",
		userId,
	);
	// Over federation, MSC4311's `knock_room_state` carries *full* PDUs, so strip
	// them before handing them to the client (the client-facing `knock_state`
	// must be stripped state events — no origin_server_ts, auth_events, etc.).
	// toStripped is a no-op shape-wise on state that is already stripped.
	const knockRoomState = (
		memberEvt?.event.unsigned as Record<string, unknown> | undefined
	)?.knock_room_state as
		| Array<{ content: unknown; sender: string; state_key?: string; type: string }>
		| undefined;
	const events: StrippedStateEvent[] =
		knockRoomState && knockRoomState.length > 0
			? knockRoomState.map((e) => toStripped(e))
			: await storage.getStrippedState(roomId);
	if (
		memberEvt &&
		!events.some((e) => e.type === "m.room.member" && e.state_key === userId)
	) {
		events.push(toStripped(memberEvt.event, userId));
	}
	return { knock_state: { events } };
};

/**
 * MSC4429: build the `org.matrix.msc4429.users` section — profile-field updates
 * for users the syncer shares a room with, limited to the opted-in `profileFields`.
 * On an initial sync (since 0) this yields the current values of those fields;
 * on an incremental sync only fields changed in the window (since, nextBatch].
 * A user who left the last shared room is reported with `profile_updates: null`
 * so the client drops their cached profile. Returns undefined when the client
 * did not opt in or there is nothing to report.
 */
const buildProfileUsers = async (
	storage: Storage,
	userId: UserId,
	seenUsers: Set<UserId>,
	newlyLeftUsers: Set<UserId>,
	since: number,
	nextBatch: number,
	profileFields: string[] | undefined,
): Promise<
	| Record<string, { profile_updates: Record<string, unknown> | null }>
	| undefined
> => {
	if (!profileFields || profileFields.length === 0) return undefined;
	const fieldSet = new Set(profileFields);
	const updates = await storage.getProfileUpdatesSince(since, nextBatch);
	const perUser = new Map<string, Record<string, unknown>>();
	for (const u of updates) {
		if (!fieldSet.has(u.field)) continue;
		if (!seenUsers.has(u.userId as UserId)) continue;
		const fields = perUser.get(u.userId) ?? {};
		fields[u.field] = u.value; // later entries win; null means cleared
		perUser.set(u.userId, fields);
	}
	const out: Record<
		string,
		{ profile_updates: Record<string, unknown> | null }
	> = {};
	for (const [uid, fields] of perUser) out[uid] = { profile_updates: fields };
	// A user who left the last room we shared is advertised as null.
	for (const u of newlyLeftUsers) {
		if (u === userId) continue;
		if (seenUsers.has(u)) continue;
		out[u] = { profile_updates: null };
	}
	return Object.keys(out).length > 0 ? out : undefined;
};

export const DEFAULT_TIMELINE_LIMIT = 20;
export const MAX_TIMEOUT = 30000;

interface ResolvedFilter {
	timelineLimit: number;
	lazyLoadMembers: boolean;
	includeLeave: boolean;
	/**
	 * MSC3773: when set via `room.timeline.unread_thread_notifications`, joined
	 * rooms carry a per-thread `unread_thread_notifications` breakdown and
	 * `unread_notifications` reflects only the main timeline. When unset, the
	 * thread counts are folded into `unread_notifications`.
	 */
	unreadThreadNotifications: boolean;
	timelineFilter?: RoomEventFilter;
	stateFilter?: StateFilter;
	/** MSC4429: profile fields the client opted into receiving updates for. */
	profileFields?: string[];
}

const resolveFilter = async (
	storage: Storage,
	userId: UserId,
	filterParam: string | null,
): Promise<ResolvedFilter> => {
	const defaults: ResolvedFilter = {
		timelineLimit: DEFAULT_TIMELINE_LIMIT,
		lazyLoadMembers: false,
		includeLeave: false,
		unreadThreadNotifications: false,
	};
	if (filterParam === null) return defaults;

	let filter: SyncFilter | undefined;
	if (filterParam.startsWith("{")) {
		try {
			filter = JSON.parse(filterParam) as SyncFilter;
		} catch {
			return defaults;
		}
	} else {
		// It's a filter ID
		const stored = await storage.getFilter(userId, filterParam);
		if (stored) {
			filter = stored as SyncFilter;
		}
	}

	if (!filter) return defaults;

	return {
		timelineLimit: filter.room?.timeline?.limit ?? DEFAULT_TIMELINE_LIMIT,
		lazyLoadMembers: filter.room?.state?.lazy_load_members ?? false,
		includeLeave: filter.room?.include_leave ?? false,
		unreadThreadNotifications:
			filter.room?.timeline?.unread_thread_notifications ?? false,
		timelineFilter: filter.room?.timeline,
		stateFilter: filter.room?.state,
		profileFields:
			filter.profile_fields?.ids ??
			filter["org.matrix.msc4429.profile_fields"]?.ids,
	};
};

/**
 * Apply a sync timeline filter to a list of timeline events. `limit` is handled
 * separately by the caller; this only applies type/sender/url predicates.
 */
const applyTimelineFilter = (
	events: ClientEvent[],
	filter: RoomEventFilter | undefined,
): ClientEvent[] => {
	if (!filter) return events;
	return events.filter((e) => matchesRoomEventFilter(e, filter));
};

/**
 * Detect a non-contiguous gap in a room's stored timeline (Synapse's
 * `get_timeline_gaps` / `record_event_timeline_gap`).
 *
 * Background: events arriving via federation backfill / `get_missing_events`
 * can be inserted into the room with sequential *stream* positions even though
 * the DAG behind them is NOT fully known to us. In TestSyncTimelineGap a remote
 * sends one event referencing ~50 prior events; our server fills the gap via
 * `get_missing_events` but only obtains a recent subset (the spec lets the
 * remote return a bounded window). The result is a "hole" in the DAG: the
 * oldest backfilled event references `prev_events` we never fetched and do not
 * have stored. Stream order alone makes the timeline look contiguous, but it is
 * not — there is unseen history behind that event.
 *
 * We detect this by scanning the room's full forward-ordered timeline for an
 * event whose `prev_events` are not all present in storage (a "broken
 * backlink"). The create event (no prev_events) is exempt. Such an event, and
 * everything after it, is disconnected from earlier history by a gap.
 *
 * Returns the stream position of the gap — events with `streamPos > gapPos`
 * lie *after* the gap and are contiguously connected to the latest events;
 * events at or before it lie *before* the gap. Returns `undefined` when the
 * timeline is fully contiguous (the common case, so normal rooms are
 * unaffected). The *earliest* broken backlink within the window defines the
 * gap, so the entire connected component of recent events (e.g. the bounded
 * batch we did fetch via `get_missing_events`, plus the event that referenced
 * them) is delivered after the gap rather than collapsing to just the newest
 * event (which typically also references the same unseen history).
 */
const detectTimelineGap = async (
	storage: Storage,
	roomId: RoomId,
): Promise<number | undefined> => {
	// The full forward timeline, carrying stream positions. Both state events
	// (via setStateEvent → storeEvent) and message events live here, so this is
	// the complete set of locally-known event IDs — a prev_event absent from it
	// is genuinely unfetched history, not a state event we happen to track
	// separately.
	const window = await storage.getEventsByRoomSince(roomId, 0, 100000);
	const present = new Set<EventId>(window.events.map((e) => e.eventId));
	for (const { event, streamPos } of window.events) {
		const prevs = (event.prev_events ?? []) as EventId[];
		if (prevs.length === 0) continue; // create event / no backlink to break
		const broken = prevs.some((p) => !present.has(p));
		if (broken) {
			// The gap sits immediately before this, the *earliest* event whose DAG
			// backlink is broken. Everything from here to `now` is the contiguous
			// "after gap" segment we can serve (later events may also reference the
			// same unseen history, but they are reachable from this point forward).
			// We return on the first broken backlink so the whole connected
			// component after the gap is preserved, rather than collapsing to just
			// the newest event (which typically also references the unseen history).
			return streamPos - 1;
		}
	}
	return undefined;
};

/**
 * MSC4115: compute the syncing user's membership as of each event in the room.
 *
 * Walks the room's full forward-ordered timeline tracking the user's membership.
 * Returns a map from eventId -> the user's membership "at" that event. For the
 * user's own membership events, the membership reflects the state *after* the
 * event is applied (so the user's own join event reports "join"). For all other
 * events it reflects the membership in effect immediately before the event.
 *
 * Defaults to "leave" before the user has any membership in the room.
 */
const computeMembershipMap = async (
	storage: Storage,
	roomId: RoomId,
	userId: UserId,
): Promise<Map<EventId, string>> => {
	const all = await storage.getEventsByRoom(roomId, 100000, undefined, "f");
	const map = new Map<EventId, string>();
	let current = "leave";
	for (const { event, eventId } of all.events) {
		if (event.type === "m.room.member" && event.state_key === userId) {
			// The user's own membership transition: the new membership applies to
			// this event and all subsequent events.
			const membership = (event.content as Record<string, unknown>).membership;
			if (typeof membership === "string") current = membership;
			map.set(eventId, current);
		} else {
			map.set(eventId, current);
		}
	}
	return map;
};

/**
 * Stamp `unsigned.membership` (MSC4115) onto each client event using a precomputed
 * membership map. Events not present in the map (should not happen) default to
 * "leave".
 */
const stampMembership = (
	events: ClientEvent[],
	membershipMap: Map<EventId, string>,
): void => {
	for (const ev of events) {
		const membership = membershipMap.get(ev.event_id as EventId) ?? "leave";
		const unsigned = (ev.unsigned ?? {}) as Record<string, unknown>;
		unsigned.membership = membership;
		(ev as { unsigned?: unknown }).unsigned = unsigned;
	}
};

const collectJoinedUsers = async (
	storage: Storage,
	roomId: RoomId,
): Promise<UserId[]> => {
	const members = await storage.getMemberEvents(roomId);
	return members
		.filter(
			(m) =>
				(m.event.content as Record<string, unknown>).membership === "join" &&
				m.event.state_key,
		)
		.map((m) => m.event.state_key as UserId);
};

/**
 * Build `m.presence` events for a set of users.
 *
 * `users` is the set to emit for:
 *   - INITIAL sync: every user sharing a room with the syncer (all `seenUsers`).
 *   - INCREMENTAL sync: only users the syncer NEWLY shares a room with in this
 *     window (the same newly-joined/invited set used for `device_lists.changed`).
 *     Already-shared users with no presence change are NOT re-emitted, so a
 *     subsequent sync with no membership change carries an empty `presence`.
 *
 * A user with no stored presence still produces an event with the Matrix default
 * `presence: "online"` (an active user). This means a user who never called
 * /presence (e.g. someone who just joined and is being synced) still appears in
 * the recipient's `presence.events`.
 */
const buildPresenceEvents = async (
	storage: Storage,
	users: Set<UserId>,
): Promise<ClientEvent[]> => {
	const events: ClientEvent[] = [];
	for (const uid of users) {
		const p = await storage.getPresence(uid);
		// Synthesize a default-online presence when storage has none, so users
		// who never explicitly set presence still appear.
		const content: Record<string, unknown> = {
			presence: p?.presence ?? "online",
		};
		if (p?.status_msg) content.status_msg = p.status_msg;
		if (p?.last_active_ts)
			content.last_active_ago = Date.now() - p.last_active_ts;
		events.push({
			type: "m.presence",
			content,
			sender: uid,
		} as unknown as ClientEvent);
	}
	return events;
};

interface ReceiptRecord {
	eventId: string;
	receiptType: string;
	userId: string;
	ts: number;
	/**
	 * MSC4102/threaded receipts: the thread root event ID, or the literal
	 * "main" for the main timeline. Absent for unthreaded receipts. Storage may
	 * not yet persist this field (see report), in which case it is undefined and
	 * the receipt is emitted unthreaded.
	 */
	threadId?: string;
}

const buildReceiptContent = (
	receipts: ReceiptRecord[],
): Record<string, unknown> => {
	const content: Record<
		string,
		Record<string, Record<string, { ts: number; thread_id?: string }>>
	> = {};
	for (const { eventId, receiptType, userId, ts, threadId } of receipts) {
		if (!content[eventId]) content[eventId] = {};
		const eventContent = content[eventId] as Record<
			string,
			Record<string, { ts: number; thread_id?: string }>
		>;
		if (!eventContent[receiptType]) eventContent[receiptType] = {};
		const receipt: { ts: number; thread_id?: string } = { ts };
		// Per MSC4102, a threaded receipt carries `thread_id` (a thread root event
		// ID or "main"); an unthreaded receipt omits it entirely.
		if (threadId !== undefined) receipt.thread_id = threadId;
		(
			eventContent[receiptType] as Record<
				string,
				{ ts: number; thread_id?: string }
			>
		)[userId] = receipt;
	}
	return content;
};

const buildEphemeralEvents = async (
	storage: Storage,
	roomId: RoomId,
	forUserId: UserId,
	// Whether to emit an `m.typing` event even when nobody is currently typing.
	// An empty typing notification is only meaningful as a *change* (a typing-stop
	// in an incremental sync). Emitting it unconditionally adds a spurious empty
	// `m.typing` to every room's ephemeral on a full sync — TestACLsForEDUs checks
	// a quiet room has zero ephemeral events. So only force it when typing changed.
	typingChanged = false,
): Promise<ClientEvent[]> => {
	const typingUsers = await storage.getTypingUsers(roomId);
	const events: ClientEvent[] = [];
	if (typingUsers.length > 0 || typingChanged) {
		events.push({
			type: "m.typing",
			content: { user_ids: typingUsers },
		} as unknown as ClientEvent);
	}
	const receipts = await storage.getReceipts(roomId);
	// Filter private receipts: m.read.private only visible to the owning user
	const visibleReceipts = receipts.filter(
		(r) => r.receiptType !== "m.read.private" || r.userId === forUserId,
	);
	if (visibleReceipts.length > 0) {
		events.push({
			type: "m.receipt",
			content: buildReceiptContent(visibleReceipts),
		} as unknown as ClientEvent);
	}
	return events;
};

/**
 * The "main timeline" thread sentinel (MSC3771). An event that is not part of
 * any thread belongs to the main timeline; threaded read receipts for it carry
 * `thread_id: "main"`.
 */
const MAIN_TIMELINE = "main";

/**
 * MSC3771: determine which thread a notifiable event counts towards.
 *
 * Mirrors Synapse `RelationsWorkerStore.get_thread_id`: walk *up* the relation
 * chain from this event towards its root (following `m.relates_to.event_id`). If
 * any link in that chain is an `m.thread` relation, the event counts towards that
 * thread (identified by the thread root's event ID — the deepest `m.thread`
 * parent). Otherwise it belongs to the main timeline.
 *
 * `relations` maps an event ID to its parent (the event it relates to) and the
 * relation type. The walk is depth-bounded (Synapse bounds at depth 3) to avoid
 * cycles in malformed data.
 */
const threadIdForEvent = (
	eventId: string,
	relations: Map<string, { parentId: string; relType: string }>,
): string => {
	let foundThreadRoot: string | undefined;
	let currentId = eventId;
	for (let depth = 0; depth <= 3; depth++) {
		const rel = relations.get(currentId);
		if (!rel) break;
		if (rel.relType === "m.thread") {
			// Record the thread root; keep walking in case a deeper m.thread exists
			// (it should not, but matches Synapse's ORDER BY depth DESC preference).
			foundThreadRoot = rel.parentId;
		}
		currentId = rel.parentId;
	}
	return foundThreadRoot ?? MAIN_TIMELINE;
};

interface ThreadedNotifResult {
	main: UnreadNotificationCounts;
	/** Per-thread breakdown keyed by thread root event ID (excludes main). */
	threads: Map<string, UnreadNotificationCounts>;
}

/**
 * MSC3771/MSC3773: compute per-thread unread notification counts for a room.
 *
 * For each notifiable event (sender !== user, evaluating to `notify`), determine
 * its thread via {@link threadIdForEvent} and count it only if it is *unread*
 * relative to the user's read receipts. Following Synapse's
 * `_get_unread_counts_by_receipt_txn`, an event in thread T is unread iff its
 * position is strictly after BOTH:
 *   - the user's threaded receipt for T (if any), and
 *   - the user's most recent unthreaded receipt (which acts as a floor across
 *     every thread, including main).
 *
 * Event ordering is the room's forward timeline index (a per-room total order),
 * which is sufficient for "after the receipt" comparisons. The full room timeline
 * is scanned (not just the sync window) so counts remain correct as history grows.
 */
const computeThreadedNotificationCounts = async (
	storage: Storage,
	roomId: RoomId,
	userId: UserId,
	userRules: PushRulesContent,
	ignoredUsers: Set<UserId>,
): Promise<ThreadedNotifResult> => {
	const all = await storage.getEventsByRoom(roomId, 100000, undefined, "f");
	const ordered = all.events;

	// Forward-timeline index per event ID — our per-room total ordering.
	const orderOf = new Map<string, number>();
	// Relation graph: child event ID -> { parent, relType }.
	const relations = new Map<string, { parentId: string; relType: string }>();
	for (let i = 0; i < ordered.length; i++) {
		const { event, eventId } = ordered[i]!;
		orderOf.set(eventId, i);
		const relatesTo = (event.content as Record<string, unknown>)[
			"m.relates_to"
		] as { rel_type?: string; event_id?: string } | undefined;
		if (relatesTo?.rel_type && relatesTo.event_id) {
			relations.set(eventId, {
				parentId: relatesTo.event_id,
				relType: relatesTo.rel_type,
			});
		}
	}

	// Receipt cutoffs. `threadReceiptPos` maps a thread ID (root event ID or
	// "main") to the ordering of that thread's threaded read receipt.
	// `unthreadedReceiptPos` is the ordering of the most recent unthreaded read
	// receipt, applied as a floor across all threads.
	const receipts = await storage.getReceipts(roomId);
	const threadReceiptPos = new Map<string, number>();
	let unthreadedReceiptPos = -1;
	for (const r of receipts) {
		if (r.userId !== userId) continue;
		if (r.receiptType !== "m.read" && r.receiptType !== "m.read.private")
			continue;
		const pos = orderOf.get(r.eventId);
		if (pos === undefined) continue;
		if (r.threadId === undefined) {
			if (pos > unthreadedReceiptPos) unthreadedReceiptPos = pos;
		} else {
			const existing = threadReceiptPos.get(r.threadId);
			if (existing === undefined || pos > existing)
				threadReceiptPos.set(r.threadId, pos);
		}
	}

	const profile = await storage.getProfile(userId);
	const displayName = profile?.displayname ?? undefined;
	const memberEvents = await storage.getMemberEvents(roomId);
	const memberCount = memberEvents.filter(
		(m) => (m.event.content as Record<string, unknown>).membership === "join",
	).length;
	const plEvent = await storage.getStateEvent(
		roomId,
		"m.room.power_levels",
		"",
	);
	const powerLevels = plEvent
		? (plEvent.event.content as unknown as RoomPowerLevelsContent)
		: undefined;
	const getSenderPl = (sender: UserId): number => {
		if (!powerLevels) return 0;
		return powerLevels.users?.[sender] ?? powerLevels.users_default ?? 0;
	};

	const main: UnreadNotificationCounts = {
		notification_count: 0,
		highlight_count: 0,
	};
	const threads = new Map<string, UnreadNotificationCounts>();

	for (const { event, eventId } of ordered) {
		if (event.sender === userId) continue;
		if (ignoredUsers.has(event.sender as UserId)) continue;
		const pos = orderOf.get(eventId)!;
		const threadId = threadIdForEvent(eventId, relations);
		const threadReceipt = threadReceiptPos.get(threadId) ?? -1;
		// Unread iff strictly after both the thread receipt and the unthreaded floor.
		if (pos <= threadReceipt || pos <= unthreadedReceiptPos) continue;

		const result = evaluatePushRules(userRules, {
			event,
			userId,
			displayName,
			memberCount,
			powerLevels,
			senderPowerLevel: getSenderPl(event.sender),
		});
		if (!result.notify) continue;

		const bucket =
			threadId === MAIN_TIMELINE
				? main
				: (threads.get(threadId) ??
					(() => {
						const c: UnreadNotificationCounts = {
							notification_count: 0,
							highlight_count: 0,
						};
						threads.set(threadId, c);
						return c;
					})());
		bucket.notification_count = (bucket.notification_count ?? 0) + 1;
		if (result.highlight)
			bucket.highlight_count = (bucket.highlight_count ?? 0) + 1;
	}

	return { main, threads };
};

/**
 * Apply the MSC3771/MSC3773 threaded notification breakdown to a joined-room
 * object, replacing the legacy single `unread_notifications` block.
 *
 * - When the client requested `unread_thread_notifications` (via the sync
 *   filter), `unread_notifications` reflects only the main timeline and a
 *   per-thread `unread_thread_notifications` map (excluding empty threads) is
 *   attached.
 * - Otherwise the thread counts are folded into `unread_notifications` so the
 *   single block reflects the whole room (Synapse handlers/sync.py).
 */
const applyThreadedNotifications = (
	room: JoinedRoom,
	counts: ThreadedNotifResult,
	wantThreadBreakdown: boolean,
): void => {
	const mainNotif = counts.main.notification_count ?? 0;
	const mainHl = counts.main.highlight_count ?? 0;

	if (wantThreadBreakdown) {
		room.unread_notifications = {
			notification_count: mainNotif,
			highlight_count: mainHl,
		};
		const threadMap: Record<string, UnreadNotificationCounts> = {};
		for (const [threadId, c] of counts.threads) {
			if ((c.notification_count ?? 0) === 0 && (c.highlight_count ?? 0) === 0)
				continue;
			threadMap[threadId] = {
				notification_count: c.notification_count ?? 0,
				highlight_count: c.highlight_count ?? 0,
			};
		}
		// Only attach the field when at least one thread has notifications, so a
		// fully-read room reports no `unread_thread_notifications` at all.
		if (Object.keys(threadMap).length > 0) {
			room.unread_thread_notifications = threadMap;
		}
	} else {
		let notif = mainNotif;
		let hl = mainHl;
		for (const c of counts.threads.values()) {
			notif += c.notification_count ?? 0;
			hl += c.highlight_count ?? 0;
		}
		room.unread_notifications = {
			notification_count: notif,
			highlight_count: hl,
		};
	}
};

const buildRoomSummary = async (
	storage: Storage,
	roomId: RoomId,
	userId: UserId,
): Promise<RoomSummary> => {
	const members = await storage.getMemberEvents(roomId);
	let joinedCount = 0;
	let invitedCount = 0;
	const heroes: UserId[] = [];

	for (const m of members) {
		const membership = (m.event.content as Record<string, unknown>)
			.membership as string;
		const stateKey = m.event.state_key as UserId;
		if (membership === "join") {
			joinedCount++;
			if (stateKey !== userId && heroes.length < 5) {
				heroes.push(stateKey);
			}
		} else if (membership === "invite") {
			invitedCount++;
			if (stateKey !== userId && heroes.length < 5) {
				heroes.push(stateKey);
			}
		}
	}

	return {
		"m.heroes": heroes.length > 0 ? heroes : undefined,
		"m.joined_member_count": joinedCount,
		"m.invited_member_count": invitedCount,
	};
};

/**
 * Build the `rooms.leave` entry for a room the user has left or been banned
 * from. Archived rooms must only contain history from before the user left,
 * so we reconstruct the room state as of the user's leave event and only
 * include timeline events up to (and including) that point.
 *
 * Returns undefined when there is nothing to report (e.g. the leave event is
 * not yet visible, or — for incremental sync — the leave did not happen in
 * this sync window).
 */
const buildLeaveRoom = async (
	storage: Storage,
	roomId: RoomId,
	userId: UserId,
	filter: ResolvedFilter,
	/**
	 * For incremental sync, only emit the room if the user's leave/ban event is
	 * newer than this stream position. Pass undefined for initial sync.
	 */
	since: number | undefined,
): Promise<LeftRoom | undefined> => {
	// Pull the full forward-ordered event list for the room. Archived rooms in
	// this server are small, so reading the whole timeline is acceptable.
	const all = await storage.getEventsByRoom(roomId, 100000, undefined, "f");
	const ordered = all.events;

	// Find the user's own leave/ban membership event (the most recent one).
	let leaveIdx = -1;
	for (let i = 0; i < ordered.length; i++) {
		const ev = ordered[i]!.event;
		if (ev.type === "m.room.member" && ev.state_key === userId) {
			const membership = (ev.content as Record<string, unknown>).membership;
			if (membership === "leave" || membership === "ban") {
				leaveIdx = i;
			}
		}
	}
	if (leaveIdx === -1) return undefined;

	const leaveEventId = ordered[leaveIdx]!.eventId;
	// For incremental sync, only report rooms where the leave event is new in
	// this sync window. getEventsByRoomSince returns events with stream_pos >
	// since, so if the leave event appears there it happened during the window.
	let sinceEventIds: Set<EventId> | undefined;
	if (since !== undefined) {
		const sinceRes = await storage.getEventsByRoomSince(roomId, since, 100000);
		sinceEventIds = new Set(sinceRes.events.map((e) => e.eventId));
		if (!sinceEventIds.has(leaveEventId)) return undefined;
	}

	// Events up to and including the user's leave.
	const upToLeave = ordered.slice(0, leaveIdx + 1);

	// Reconstruct state as of the leave point by folding all state events from
	// the room's history up to the leave.
	const stateAtLeave = new Map<string, { event: PDU; eventId: EventId }>();
	for (const entry of upToLeave) {
		if (entry.event.state_key !== undefined) {
			const key = `${entry.event.type}\x1f${entry.event.state_key}`;
			stateAtLeave.set(key, entry);
		}
	}

	// Timeline candidates: events up to the leave. For incremental sync, only
	// include events that are new in this window (stream_pos > since); for
	// initial sync, include the whole history up to the leave.
	const timelineCandidates =
		sinceEventIds === undefined
			? upToLeave
			: upToLeave.filter((e) => sinceEventIds!.has(e.eventId));

	// Timeline: tail of the candidates, limited, then type-filtered.
	const tail = timelineCandidates.slice(
		Math.max(0, timelineCandidates.length - filter.timelineLimit),
	);
	const limited = timelineCandidates.length > filter.timelineLimit;
	let timelineClientEvents = tail.map((e) =>
		pduToClientEvent(e.event, e.eventId),
	);
	timelineClientEvents = applyTimelineFilter(
		timelineClientEvents,
		filter.timelineFilter,
	);
	const timelineIds = new Set(tail.map((e) => e.eventId));

	// State section.
	//  - Initial sync: the full room state as of the leave point, minus what is
	//    already in the timeline.
	//  - Incremental sync: only the state changes within this window (i.e. state
	//    events newer than `since`) that fell outside the limited timeline. This
	//    keeps incremental responses to a delta, matching Synapse.
	const stateCandidates =
		sinceEventIds === undefined
			? [...stateAtLeave.values()]
			: [...stateAtLeave.values()].filter((e) => sinceEventIds!.has(e.eventId));
	let stateEntries = stateCandidates.filter((e) => !timelineIds.has(e.eventId));
	if (filter.stateFilter) {
		stateEntries = stateEntries.filter((e) =>
			matchesRoomEventFilter(
				pduToClientEvent(e.event, e.eventId),
				filter.stateFilter,
			),
		);
	}
	const stateClientEvents = stateEntries.map((e) =>
		pduToClientEvent(e.event, e.eventId),
	);

	// prev_batch must always be present so clients can paginate the archived
	// timeline. The current stream position is a valid backward-pagination
	// token here.
	const prevBatch = String(await storage.getStreamPosition());
	const room: LeftRoom = {
		state:
			stateClientEvents.length > 0 ? { events: stateClientEvents } : undefined,
		timeline: {
			events: timelineClientEvents,
			limited,
			prev_batch: prevBatch,
		},
	};
	return room;
};

/**
 * MSC4222: attach the `state_after` block (both the stable `state_after` key and
 * the unstable `org.matrix.msc4222.state_after` key) to a joined-room object, and
 * blank out the legacy `state` block (MSC4222 replaces it when use_state_after is
 * set). `JoinedRoom` does not declare these unstable keys, so we cast.
 */
const attachStateAfter = (
	room: JoinedRoom,
	stateAfterEvents: ClientEvent[],
): void => {
	const block = { events: stateAfterEvents };
	const r = room as JoinedRoom & {
		state_after?: { events: ClientEvent[] };
		"org.matrix.msc4222.state_after"?: { events: ClientEvent[] };
	};
	// MSC4222 replaces `state` with `state_after`; omit the legacy block.
	r.state = undefined;
	r.state_after = block;
	r["org.matrix.msc4222.state_after"] = block;
};

const buildInitialSync = async (
	storage: Storage,
	userId: UserId,
	deviceId: DeviceId,
	nextBatch: number,
	filter: ResolvedFilter,
	useStateAfter: boolean,
): Promise<SyncResponse> => {
	const userRooms = await storage.getRoomsForUserWithMembership(userId);

	const join: Record<RoomId, JoinedRoom> = {};
	const invite: Record<RoomId, InvitedRoom> = {};
	const knock: Record<RoomId, KnockedRoom> = {};
	const leave: Record<RoomId, LeftRoom> = {};
	const userRules = await getOrInitRules(storage, userId);
	const ignoredUsers = await getIgnoredUsers(storage, userId);
	const ignoredInviteSenders = await getIgnoredInviteSenders(storage, userId);

	for (const { roomId, membership } of userRooms) {
		// A forgotten room must not appear in an initial sync at all.
		const forgottenMarker = await storage.getRoomAccountData(
			userId,
			roomId,
			"m.internal.forgotten",
		);
		if ((forgottenMarker as { forgotten?: boolean } | undefined)?.forgotten) {
			continue;
		}
		// MSC3706: an EAGER (non-lazy-loading) sync omits a partial-state room until
		// its resync completes — we cannot present the full member list yet. A
		// lazy-loading sync surfaces it immediately. (synapse hides the room from
		// eager syncs while partial-state.)
		if (
			membership === "join" &&
			!filter.lazyLoadMembers &&
			(await storage.getRoomPartialState(roomId))
		) {
			continue;
		}
		if (membership === "join") {
			// Load the FULL room timeline (ascending, by stream/recency order), TRUNCATE
			// to the most-recent `timelineLimit` events FIRST, then apply the sync
			// timeline filter to that tail. This mirrors Synapse's initial-sync
			// `_load_filtered_recents`, which selects the recent window by ordering and
			// filters it — it does NOT filter the room's entire history and then keep the
			// last N of whatever survived. The distinction matters when an event arrives
			// late (high stream position) but is older by the room ordering, e.g. a state
			// event forked at an earlier point in the DAG: it must NOT win the limited
			// timeline tail over genuinely newer messages. Such a state event is then the
			// current head and surfaces in the `state` block via `getAllState`
			// (TestSyncOmitsStateChangeOnFilteredEvents). Rooms are small here so loading
			// the whole timeline and slicing in-memory is fine.
			const fullWindow = await storage.getEventsByRoomSince(roomId, 0, 100000);

			const allState = await storage.getAllState(roomId);

			// Detect a non-contiguous DAG gap (events backfilled via federation
			// `get_missing_events` with unseen history behind them). On initial sync
			// we only deliver events *after* the most recent gap and force `limited`,
			// so the client paginates the unreachable history (Synapse
			// `_load_filtered_recents`, gap_token branch).
			const gapPos = await detectTimelineGap(storage, roomId);

			let candidates = fullWindow.events
				.filter((e) => gapPos === undefined || e.streamPos > gapPos)
				.map((e) => ({
					streamPos: e.streamPos,
					clientEvent: pduToClientEvent(e.event, e.eventId),
				}));

			if (ignoredUsers.size > 0) {
				candidates = candidates.filter(
					(e) =>
						e.clientEvent.state_key !== undefined ||
						!ignoredUsers.has(e.clientEvent.sender),
				);
			}

			// Truncate to the timeline limit (most-recent events by stream order) BEFORE
			// filtering. `limited` reflects whether older history was dropped, or a gap
			// exists behind the delivered window.
			const limited =
				gapPos !== undefined || candidates.length > filter.timelineLimit;
			const recentWindow = limited
				? candidates.slice(candidates.length - filter.timelineLimit)
				: candidates;

			// Apply the timeline filter to the truncated tail. State events removed here
			// still surface in the `state` block, since that block is computed as current
			// state minus the delivered timeline (Synapse `_calculate_state`: `state =
			// current_state - timeline_contains`, where `timeline_contains` is the
			// post-filter timeline actually sent down). An event filtered out of the tail
			// (or never in the tail at all) therefore reappears in `state` when it is
			// current state.
			const kept = filter.timelineFilter
				? recentWindow.filter((e) =>
						matchesRoomEventFilter(e.clientEvent, filter.timelineFilter),
					)
				: recentWindow;
			const timelineClientEvents = kept.map((e) => e.clientEvent);

			// Events still present in the timeline after filtering are already known
			// to the client, so they are excluded from the `state` block.
			const timelineEventIds = new Set(
				timelineClientEvents.map((e) => e.event_id as EventId),
			);
			let stateEntries = allState.filter(
				(e) => !timelineEventIds.has(e.eventId),
			);

			// When lazy_load_members is enabled, only include member events
			// for users who appear in the timeline
			if (filter.lazyLoadMembers) {
				const timelineSenders = new Set<string>();
				for (const ev of timelineClientEvents) {
					timelineSenders.add(ev.sender);
					if (ev.type === "m.room.member" && ev.state_key) {
						timelineSenders.add(ev.state_key);
					}
				}
				stateEntries = stateEntries.filter(
					(e) =>
						e.event.type !== "m.room.member" ||
						timelineSenders.has(e.event.state_key ?? ""),
				);
			}

			const stateEvents = stateEntries.map((e) =>
				pduToClientEvent(e.event, e.eventId),
			);

			await bundleAggregations(storage, timelineClientEvents, userId);

			// MSC4115: stamp the syncing user's membership onto each timeline event.
			const membershipMap = await computeMembershipMap(storage, roomId, userId);
			stampMembership(timelineClientEvents, membershipMap);

			// prev_batch is always present. For a limited timeline it points just
			// before the first kept event (so /messages?dir=b backfills the older —
			// and any filtered-out — history); for an unlimited timeline it is the
			// current stream position, which is also a valid `at` token for
			// GET /members?at=… (state as of this sync).
			const firstKeptStreamPos =
				kept.length > 0 ? kept[0]!.streamPos : undefined;
			const prevBatch =
				limited && firstKeptStreamPos !== undefined
					? String(firstKeptStreamPos - 1)
					: String(await storage.getStreamPosition());

			const summary = await buildRoomSummary(storage, roomId, userId);

			join[roomId] = {
				summary,
				state: stateEvents.length > 0 ? { events: stateEvents } : undefined,
				timeline: {
					events: timelineClientEvents,
					limited,
					prev_batch: prevBatch,
				},
			};

			// MSC3771/MSC3773: compute per-thread unread notification counts over
			// the full room timeline relative to the user's read receipts, then
			// attach either a folded `unread_notifications` block or the per-thread
			// breakdown depending on the sync filter.
			const threadedCounts = await computeThreadedNotificationCounts(
				storage,
				roomId,
				userId,
				userRules,
				ignoredUsers,
			);
			applyThreadedNotifications(
				join[roomId] as JoinedRoom,
				threadedCounts,
				filter.unreadThreadNotifications,
			);

			if (useStateAfter) {
				// MSC4222 initial sync: state_after is the full current room state
				// (the state *after* the returned timeline batch). Unlike the legacy
				// `state` block, timeline state events are NOT excluded — state_after
				// must reflect the complete post-timeline state.
				let stateAfterEntries = allState;
				if (filter.lazyLoadMembers) {
					// Keep member events only for senders/targets present in the
					// timeline (mirrors the lazy-load behaviour of the legacy block).
					const timelineSenders = new Set<string>();
					for (const ev of timelineClientEvents) {
						timelineSenders.add(ev.sender);
						if (ev.type === "m.room.member" && ev.state_key) {
							timelineSenders.add(ev.state_key);
						}
					}
					stateAfterEntries = stateAfterEntries.filter(
						(e) =>
							e.event.type !== "m.room.member" ||
							timelineSenders.has(e.event.state_key ?? ""),
					);
				}
				attachStateAfter(
					join[roomId] as JoinedRoom,
					stateAfterEntries.map((e) => pduToClientEvent(e.event, e.eventId)),
				);
			}
		} else if (membership === "invite") {
			const stripped = await storage.getStrippedState(roomId);
			const inviterEvent = stripped.find(
				(e) =>
					e.type === "m.room.member" &&
					e.state_key === userId &&
					(e.content as Record<string, unknown>).membership === "invite",
			);
			const inviter = inviterEvent?.sender as UserId | undefined;
			if (
				inviter &&
				(ignoredUsers.has(inviter) || ignoredInviteSenders.has(inviter))
			)
				continue;
			invite[roomId] = { invite_state: { events: stripped } };
		} else if (membership === "knock") {
			knock[roomId] = await buildKnockRoom(storage, roomId as RoomId, userId);
		} else if (
			(membership === "leave" || membership === "ban") &&
			filter.includeLeave
		) {
			const leftRoom = await buildLeaveRoom(
				storage,
				roomId,
				userId,
				filter,
				undefined,
			);
			if (leftRoom) leave[roomId] = leftRoom;
		}
	}

	const globalData = await storage.getAllGlobalAccountData(userId);
	const accountDataEvents = globalData.map(
		(d) => ({ type: d.type, content: d.content }) as unknown as ClientEvent,
	);

	const seenUsers = new Set<UserId>();
	for (const roomId of Object.keys(join)) {
		const roomData = await storage.getAllRoomAccountData(userId, roomId);
		// Always emit account_data.events (even empty) so clients can rely on the
		// path existing for a joined room.
		(join[roomId] as JoinedRoom).account_data = {
			events: roomData.map(
				(d) => ({ type: d.type, content: d.content }) as unknown as ClientEvent,
			),
		};

		(join[roomId] as JoinedRoom).ephemeral = {
			events: await buildEphemeralEvents(storage, roomId as RoomId, userId),
		};

		const users = await collectJoinedUsers(storage, roomId as RoomId);
		for (const u of users) seenUsers.add(u);
	}

	const presenceEvents = await buildPresenceEvents(storage, seenUsers);

	const toDeviceEvents = await storage.getToDeviceMessages(userId, deviceId);
	if (toDeviceEvents.length > 0) {
		await storage.clearToDeviceMessages(userId, deviceId);
	}

	const otkCounts = await storage.getOneTimeKeyCounts(userId, deviceId);
	const fallbackKeyTypes = await storage.getFallbackKeyTypes(userId, deviceId);

	return {
		next_batch: String(nextBatch),
		account_data:
			accountDataEvents.length > 0 ? { events: accountDataEvents } : undefined,
		presence:
			presenceEvents.length > 0 ? { events: presenceEvents } : undefined,
		rooms: {
			join: Object.keys(join).length > 0 ? join : undefined,
			invite: Object.keys(invite).length > 0 ? invite : undefined,
			knock: Object.keys(knock).length > 0 ? knock : undefined,
			leave: Object.keys(leave).length > 0 ? leave : undefined,
		},
		to_device:
			toDeviceEvents.length > 0 ? { events: toDeviceEvents } : undefined,
		device_one_time_keys_count: otkCounts,
		device_unused_fallback_key_types: fallbackKeyTypes,
		"org.matrix.msc4429.users": await buildProfileUsers(
			storage,
			userId,
			seenUsers,
			new Set<UserId>(),
			0,
			nextBatch,
			filter.profileFields,
		),
	};
};
const buildIncrementalSync = async (
	storage: Storage,
	userId: UserId,
	deviceId: DeviceId,
	since: number,
	nextBatch: number,
	fullState: boolean,
	filter: ResolvedFilter,
	useStateAfter: boolean,
): Promise<SyncResponse> => {
	const userRooms = await storage.getRoomsForUserWithMembership(userId);

	const join: Record<RoomId, JoinedRoom> = {};
	const invite: Record<RoomId, InvitedRoom> = {};
	const knock: Record<RoomId, KnockedRoom> = {};
	const leave: Record<RoomId, LeftRoom> = {};
	const seenUsers = new Set<UserId>();
	// Users who newly joined/were invited/knocked on a room we share within this
	// sync window. Per the spec and Synapse's
	// `DeviceHandler.generate_sync_entry_for_device_list` (Step 1b), these users
	// must appear in `device_lists.changed` even if they did not upload keys —
	// the syncing client needs to fetch their device list because it now shares a
	// room with them. See handlers/device.py:755-762.
	const newlyJoinedOrInvitedUsers = new Set<UserId>();
	// Users who left a room we share within this window (their final membership
	// transition in the window is leave/ban), plus all users in rooms WE left
	// this window. Per Synapse `DeviceHandler.get_user_ids_changed`
	// (handlers/device.py:769-780) these become `device_lists.left` once we
	// confirm they no longer share ANY currently-joined room with us.
	const newlyLeftUsers = new Set<UserId>();
	const userRules = await getOrInitRules(storage, userId);
	const ignoredUsers = await getIgnoredUsers(storage, userId);
	const ignoredInviteSenders = await getIgnoredInviteSenders(storage, userId);

	for (const { roomId, membership } of userRooms) {
		// MSC3706: omit a partial-state room from an eager (non-lazy) sync until
		// its resync completes (see initial-sync rationale above).
		if (
			membership === "join" &&
			!filter.lazyLoadMembers &&
			(await storage.getRoomPartialState(roomId))
		) {
			continue;
		}
		if (membership === "join") {
			// Determine whether the syncing user *newly joined* this room within the
			// current window (their own join member event has stream_pos > since).
			// Synapse treats such a room specially (handlers/sync.py
			// `_load_filtered_recents`): it ignores the `since` token when loading the
			// timeline (so the user receives a backlog of recent history they couldn't
			// see before joining) and always marks the batch `limited` so the client
			// paginates the gap. A plain delta from `since` would only show events that
			// arrived after the join, omitting pre-join history the user is now allowed
			// to read.
			const windowForJoinCheck = await storage.getEventsByRoomSince(
				roomId,
				since,
				100000,
			);
			let selfNewlyJoinedRoom = false;
			for (const { event } of windowForJoinCheck.events) {
				if (
					event.type === "m.room.member" &&
					event.state_key === userId &&
					(event.content as Record<string, unknown>).membership === "join"
				) {
					selfNewlyJoinedRoom = true;
				}
			}

			// MSC3706: a room whose partial-state resync completed within this window
			// must surface its now-known member state in the `state` block (the peer
			// asked an eager sync and we previously hid the room). The resynced member
			// events were stored at recent stream positions; keep them OUT of the
			// timeline delta so they land in `state` rather than appearing as live
			// timeline activity.
			const unPartialStatedAt = await storage.getRoomUnPartialStatedAt(roomId);
			const unPartialStatedThisWindow =
				unPartialStatedAt !== undefined && unPartialStatedAt > since;

			// Build the candidate timeline (ascending, carrying stream positions). For
			// a newly-joined room we load the whole room history (like an initial
			// sync); otherwise the delta since `since`. We then apply the sync
			// timeline filter BEFORE truncating to the limit (Synapse
			// `_load_filtered_recents`), so `limited` reflects the post-filter set.
			let candidates: { streamPos: number; clientEvent: ClientEvent }[];
			// A gap reported by storage (more events than the limit existed in the
			// raw window) forces `limited` even if the filter shrinks the set, so the
			// client paginates the dropped history.
			let storageGap: boolean;
			if (selfNewlyJoinedRoom || unPartialStatedThisWindow) {
				// Whole room history; truncation/limited handled below. A newly-joined
				// room is always limited so the client paginates the pre-join gap.
				// MSC3706: an un-partial-stated room is treated the same — while it was
				// partial it was hidden from this (eager) sync and the token advanced
				// past its events, so we must re-deliver its recent timeline now,
				// otherwise events sent during the resync are lost to the client.
				const fullWindow = await storage.getEventsByRoomSince(
					roomId,
					0,
					100000,
				);
				candidates = fullWindow.events.map((e) => ({
					streamPos: e.streamPos,
					clientEvent: pduToClientEvent(e.event, e.eventId),
				}));
				storageGap = true;
			} else {
				// Detect a non-contiguous DAG gap in the room (events backfilled via
				// federation `get_missing_events` with unseen history behind them —
				// TestSyncTimelineGap). Mirrors Synapse `_load_filtered_recents`: when a
				// gap falls within this sync window `(since, now]`, we must (a) mark the
				// batch `limited` so the client paginates the hole, and (b) only return
				// events *after* the gap, dropping pre-gap events from the delta even
				// though they share the same stream window.
				const gapPos = await detectTimelineGap(storage, roomId);
				const gapInWindow = gapPos !== undefined && gapPos >= since;
				// When there's a gap in the window, ignore `since` and load events from
				// just after the gap; otherwise load the plain delta since `since`. In
				// both cases we read the full set (no storage-side truncation) so the
				// timeline filter is applied before we truncate to the limit.
				const loadFrom = gapInWindow ? gapPos : since;
				const res = await storage.getEventsByRoomSince(
					roomId,
					loadFrom,
					100000,
				);
				candidates = res.events.map((e) => ({
					streamPos: e.streamPos,
					clientEvent: pduToClientEvent(e.event, e.eventId),
				}));
				// A gap forces `limited` even if the (post-gap) delta is under the limit,
				// so the client knows there is unreachable history behind this batch.
				storageGap = gapInWindow;
			}

			// MSC3706: keep the RESYNCED member events out of the timeline (they are
			// state we just learned, not live activity) so they appear in `state`.
			// Only member events at or before the un-partial-state point are resync
			// state; a member event that arrived AFTER it (e.g. a remote user
			// rejoining once the join completed) is live timeline activity and must
			// stay in the timeline (TestPartialStateJoin Device_list_tracking rejoin).
			if (unPartialStatedThisWindow) {
				candidates = candidates.filter(
					(e) =>
						e.clientEvent.type !== "m.room.member" ||
						e.streamPos > unPartialStatedAt,
				);
			}

			if (ignoredUsers.size > 0) {
				candidates = candidates.filter(
					(e) =>
						e.clientEvent.state_key !== undefined ||
						!ignoredUsers.has(e.clientEvent.sender),
				);
			}

			// Apply the timeline filter. State events removed by the filter must
			// still be reported in the `state` block (see Synapse `_calculate_state`),
			// so the exclusion set below is computed from the filtered timeline.
			const filteredCandidates = filter.timelineFilter
				? candidates.filter((e) =>
						matchesRoomEventFilter(e.clientEvent, filter.timelineFilter),
					)
				: candidates;

			// Truncate to the timeline limit, keeping the most-recent events.
			const limited =
				storageGap || filteredCandidates.length > filter.timelineLimit;
			const kept =
				filteredCandidates.length > filter.timelineLimit
					? filteredCandidates.slice(
							filteredCandidates.length - filter.timelineLimit,
						)
					: filteredCandidates;
			const newEvents = kept;
			const timelineClientEvents = kept.map((e) => e.clientEvent);

			await bundleAggregations(storage, timelineClientEvents, userId);

			// MSC4115: stamp the syncing user's membership onto each timeline event.
			if (timelineClientEvents.length > 0) {
				const membershipMap = await computeMembershipMap(
					storage,
					roomId,
					userId,
				);
				stampMembership(timelineClientEvents, membershipMap);
			}

			// Event IDs surviving the timeline filter — these are already delivered to
			// the client and must be excluded from the `state` block.
			const filteredTimelineIds = new Set(
				timelineClientEvents.map((e) => e.event_id as EventId),
			);

			let stateClientEvents: ClientEvent[] = [];
			if (fullState || selfNewlyJoinedRoom || unPartialStatedThisWindow) {
				// A full-state request, a room the user newly joined this window, or a
				// room whose partial-state resync just completed, gets the complete
				// current room state (minus events already in the timeline) as its
				// `state` block — the same shape as an initial sync.
				const allState = await storage.getAllState(roomId);
				let stateEntries = allState.filter(
					(e) => !filteredTimelineIds.has(e.eventId),
				);

				if (filter.lazyLoadMembers) {
					const timelineSenders = new Set<string>();
					for (const ev of timelineClientEvents) {
						timelineSenders.add(ev.sender);
						if (ev.type === "m.room.member" && ev.state_key) {
							timelineSenders.add(ev.state_key);
						}
					}
					stateEntries = stateEntries.filter(
						(e) =>
							e.event.type !== "m.room.member" ||
							timelineSenders.has(e.event.state_key ?? ""),
					);
				}

				stateClientEvents = stateEntries.map((e) =>
					pduToClientEvent(e.event, e.eventId),
				);
			} else {
				// Incremental (delta) sync: report state events that arrived within
				// this window (since, nextBatch] but did NOT survive the timeline
				// filter (e.g. excluded by not_types) or fell outside the limited
				// timeline tail. Without this, a state change filtered out of the
				// timeline would silently never reach the client.
				const windowRes = await storage.getEventsByRoomSince(
					roomId,
					since,
					100000,
				);
				const stateDelta = windowRes.events.filter(
					(e) =>
						e.event.state_key !== undefined &&
						!filteredTimelineIds.has(e.eventId),
				);
				stateClientEvents = stateDelta.map((e) =>
					pduToClientEvent(e.event, e.eventId),
				);

				// Lazy-loading during a partial-state join: also surface the
				// m.room.member event for each sender in this window's timeline whose
				// membership sits below `since` — in particular a remote member we
				// learned (as historical state) only from receiving their events, who
				// would otherwise be invisible to a gappy/incremental lazy-load until
				// the resync completes. Gated to partial-state rooms so ordinary
				// lazy-loading (which relies on the client's own membership cache) is
				// unaffected.
				if (
					filter.lazyLoadMembers &&
					(await storage.getRoomPartialState(roomId))
				) {
					const seenMembers = new Set(
						stateClientEvents
							.filter((e) => e.type === "m.room.member")
							.map((e) => e.state_key ?? ""),
					);
					const timelineSenders = new Set(
						timelineClientEvents.map((e) => e.sender),
					);
					const allState = await storage.getAllState(roomId);
					for (const e of allState) {
						if (
							e.event.type === "m.room.member" &&
							timelineSenders.has(e.event.state_key ?? "") &&
							!seenMembers.has(e.event.state_key ?? "") &&
							!filteredTimelineIds.has(e.eventId)
						) {
							stateClientEvents.push(pduToClientEvent(e.event, e.eventId));
							seenMembers.add(e.event.state_key ?? "");
						}
					}
				}
			}

			// For a limited timeline, prev_batch points just before the first kept
			// event so /messages?dir=b backfills the gap. When not limited we point at
			// `since` (the start of this delta), which is also a valid pagination
			// token; this keeps prev_batch always present like Synapse.
			const prevBatch =
				limited && newEvents.length > 0
					? String(newEvents[0]!.streamPos - 1)
					: String(since);

			// Emit an `m.typing` event only when someone is typing or when typing
			// CHANGED since `since` (covers an explicit stop → empty list). This
			// avoids re-reporting an unchanged room on every incremental sync.
			const typingChangedAt = await storage.getTypingChangedAt(roomId);
			const typingChanged = since === undefined || typingChangedAt > since;
			const ephemeralEvents = await buildEphemeralEvents(
				storage,
				roomId,
				userId,
				typingChanged,
			);

			// Only treat ephemeral data as a reason to include the room when it
			// carries a change: a typing change (incl. a stop), or any receipt event.
			const hasEphemeralContent = ephemeralEvents.some((e) => {
				if (e.type === "m.receipt") return true;
				if (e.type === "m.typing") return typingChanged;
				return false;
			});

			if (
				timelineClientEvents.length > 0 ||
				stateClientEvents.length > 0 ||
				hasEphemeralContent
			) {
				const summary = await buildRoomSummary(storage, roomId, userId);

				join[roomId] = {
					summary,
					state:
						stateClientEvents.length > 0
							? { events: stateClientEvents }
							: undefined,
					timeline: {
						events: timelineClientEvents,
						limited,
						prev_batch: prevBatch,
					},
					ephemeral: { events: ephemeralEvents },
				};

				// MSC3771/MSC3773: per-thread unread notification counts, computed
				// over the full room timeline relative to read receipts.
				const threadedCounts = await computeThreadedNotificationCounts(
					storage,
					roomId,
					userId,
					userRules,
					ignoredUsers,
				);
				applyThreadedNotifications(
					join[roomId] as JoinedRoom,
					threadedCounts,
					filter.unreadThreadNotifications,
				);

				if (useStateAfter) {
					// MSC4222 incremental sync: state_after is the set of state events
					// that changed within this window (since, nextBatch]. Critically,
					// this INCLUDES state events that also appear in the timeline — e.g.
					// a delayed state event that fires arrives as a timeline event on the
					// waking long-poll and must also surface in state_after. We pull the
					// full window (not just the limited timeline tail) and keep events
					// carrying a state_key.
					const windowRes = await storage.getEventsByRoomSince(
						roomId,
						since,
						100000,
					);
					const stateDelta = windowRes.events.filter(
						(e) => e.event.state_key !== undefined,
					);
					attachStateAfter(
						join[roomId] as JoinedRoom,
						stateDelta.map((e) => pduToClientEvent(e.event, e.eventId)),
					);
				}
			}

			const users = await collectJoinedUsers(storage, roomId);
			for (const u of users) seenUsers.add(u);

			// Step 1b (Synapse handlers/device.py:755-762): scan this shared room's
			// membership transitions within the window (since, nextBatch] for users
			// who newly joined / were invited / are knocking. Their device lists must
			// be surfaced in `device_lists.changed` so the client fetches their keys,
			// independent of whether they pushed a device-list update. This covers the
			// federation room-join case where a remote user joins a room we're in: the
			// inbound member event lands in this window but the user may never upload
			// keys to us.
			const memberWindow = await storage.getEventsByRoomSince(
				roomId,
				since,
				100000,
			);
			let selfNewlyJoined = false;
			// Track each user's FINAL membership transition within the window so a
			// leave-then-rejoin nets to "joined" (Synapse discards a room from
			// newly_left when a later join arrives — handlers/device.py:610-614,
			// 673-677). We walk events in chronological (stream) order.
			const finalMembershipInWindow = new Map<UserId, string>();
			for (const { event } of memberWindow.events) {
				if (event.type !== "m.room.member" || !event.state_key) continue;
				const m = (event.content as Record<string, unknown>).membership;
				finalMembershipInWindow.set(event.state_key as UserId, m as string);
				if (m === "join" || m === "invite" || m === "knock") {
					newlyJoinedOrInvitedUsers.add(event.state_key as UserId);
					if (event.state_key === userId && m === "join") {
						selfNewlyJoined = true;
					}
				}
			}
			// Other users whose final transition in this still-shared room is
			// leave/ban are candidates for `device_lists.left`. Self is excluded
			// here; if self left, the room would be in our leave/ban branch and
			// handled as a `newly_left_room` below.
			for (const [u, m] of finalMembershipInWindow) {
				if (u === userId) continue;
				if (m === "leave" || m === "ban") {
					newlyLeftUsers.add(u);
				}
			}
			// If WE newly joined this room in this window, every user currently in
			// the room is a "newly shared" user from our perspective — we must learn
			// all their device lists. Synapse handlers/device.py:756-758 adds
			// `get_users_in_room(room_id)` for each `newly_joined_rooms` entry. Their
			// own member events predate the window, so the per-event scan above would
			// otherwise miss them.
			if (selfNewlyJoined) {
				for (const u of users) newlyJoinedOrInvitedUsers.add(u);
			}
		} else if (membership === "invite") {
			const { events: newEvents } = await storage.getEventsByRoomSince(
				roomId,
				since,
				filter.timelineLimit,
			);
			const membershipChanged = newEvents.some(
				(e) => e.event.type === "m.room.member" && e.event.state_key === userId,
			);
			if (membershipChanged) {
				const stripped = await storage.getStrippedState(roomId);
				const inviterEvent = stripped.find(
					(e) =>
						e.type === "m.room.member" &&
						e.state_key === userId &&
						(e.content as Record<string, unknown>).membership === "invite",
				);
				const inviter = inviterEvent?.sender as UserId | undefined;
				if (
					inviter &&
					(ignoredUsers.has(inviter) || ignoredInviteSenders.has(inviter))
				)
					continue;
				invite[roomId] = { invite_state: { events: stripped } };
			}
		} else if (membership === "knock") {
			const { events: newEvents } = await storage.getEventsByRoomSince(
				roomId,
				since,
				filter.timelineLimit,
			);
			const membershipChanged = newEvents.some(
				(e) => e.event.type === "m.room.member" && e.event.state_key === userId,
			);
			if (membershipChanged) {
				knock[roomId] = await buildKnockRoom(storage, roomId as RoomId, userId);
			}
		} else if (membership === "leave" || membership === "ban") {
			// Emit a leave room when the user newly left within this sync window.
			// buildLeaveRoom only returns a value when the user's leave/ban event
			// is newer than `since`, which matches the "newly left" semantics —
			// so this fires for both include_leave filters and the default case.
			const leftRoom = await buildLeaveRoom(
				storage,
				roomId,
				userId,
				filter,
				since,
			);
			if (leftRoom) {
				leave[roomId] = leftRoom;
				// `newly_left_rooms`: we left this room within the window. Every user
				// still joined to it becomes a `device_lists.left` candidate — we can
				// no longer observe their devices through this room. Synapse
				// handlers/device.py:770-772 does the same via get_users_in_room.
				// Survivors who share another joined room with us are filtered out
				// after the loop.
				const leftRoomUsers = await collectJoinedUsers(
					storage,
					roomId as RoomId,
				);
				for (const u of leftRoomUsers) {
					if (u !== userId) newlyLeftUsers.add(u);
				}
			}
		}
	}

	// Account data changed within this sync window. Global entries go to the
	// top-level account_data; room entries attach to the joined room (creating a
	// minimal join entry if the room is not otherwise present in this response).
	// Tombstones (content `{}`, MSC3391 deletions) are included by the *Since
	// methods so clients can clear deleted account data.
	const globalAccountDataSince = await storage.getGlobalAccountDataSince(
		userId,
		since,
	);
	const accountDataEvents = globalAccountDataSince.map(
		(d) => ({ type: d.type, content: d.content }) as unknown as ClientEvent,
	);

	const joinedRoomIds = new Set(
		userRooms.filter((r) => r.membership === "join").map((r) => r.roomId),
	);
	const roomAccountDataSince = await storage.getRoomAccountDataSince(
		userId,
		since,
	);
	const roomAccountDataByRoom = new Map<RoomId, ClientEvent[]>();
	for (const d of roomAccountDataSince) {
		// Only surface room account-data for rooms the user is currently joined to.
		if (!joinedRoomIds.has(d.roomId)) continue;
		let list = roomAccountDataByRoom.get(d.roomId);
		if (!list) {
			list = [];
			roomAccountDataByRoom.set(d.roomId, list);
		}
		list.push({ type: d.type, content: d.content } as unknown as ClientEvent);
	}
	for (const [roomId, events] of roomAccountDataByRoom) {
		let room = join[roomId];
		if (!room) {
			// Room has only account-data changes in this window; still surface it.
			room = {} as JoinedRoom;
			join[roomId] = room;
		}
		room.account_data = { events };
	}

	// Presence (incremental): emit `m.presence` ONLY for users the syncer newly
	// shares a room with in this window (the same set used for
	// `device_lists.changed`). Already-shared users with no change are not
	// re-emitted, so a subsequent unchanged sync carries an empty `presence`
	// block. Self is excluded — a client does not receive its own presence here.
	const presenceUsers = new Set<UserId>();
	// Users newly sharing a room with us this window get their (default-online)
	// presence...
	for (const u of newlyJoinedOrInvitedUsers) {
		if (u !== userId) presenceUsers.add(u);
	}
	// ...and any already-shared user whose presence actually changed since the
	// `since` token gets their updated presence (TestPresence). Without this an
	// explicit presence change never reaches other members of a shared room.
	for (const u of seenUsers) {
		if (u === userId) continue;
		if (presenceUsers.has(u)) continue;
		if ((await storage.getPresenceChangedAt(u)) > since) presenceUsers.add(u);
	}
	const presenceEvents = await buildPresenceEvents(storage, presenceUsers);

	const toDeviceEvents = await storage.getToDeviceMessages(userId, deviceId);
	if (toDeviceEvents.length > 0) {
		await storage.clearToDeviceMessages(userId, deviceId);
	}

	const otkCounts = await storage.getOneTimeKeyCounts(userId, deviceId);
	const fallbackKeyTypes = await storage.getFallbackKeyTypes(userId, deviceId);

	// Device-list changes (`device_lists.changed`). Per Synapse's
	// `DeviceHandler.generate_sync_entry_for_device_list` this is the union of:
	//   1a. users whose device keys changed within this window (since, nextBatch]
	//       and who currently share a joined room with the syncer; and
	//   1b. users who newly joined / were invited / knocked on a room we share in
	//       this window (collected above), regardless of whether their keys
	//       changed.
	// The syncer themselves is intentionally NOT excluded: a client must learn of
	// its own other devices (e.g. a second login), so self is reported when self's
	// keys changed or self newly joined. `seenUsers` holds every user sharing a
	// joined room with us (including self).
	const changedDeviceUsers = await storage.getChangedDeviceUsers(
		since,
		nextBatch,
	);
	const changed = new Set<UserId>();
	for (const u of changedDeviceUsers) {
		if (seenUsers.has(u)) changed.add(u);
	}
	for (const u of newlyJoinedOrInvitedUsers) {
		changed.add(u);
	}
	const changedDeviceLists = [...changed];

	// Device-list removals (`device_lists.left`). Per Synapse
	// `get_user_ids_changed` (handlers/device.py:774-780): a candidate that
	// transitioned to leave/ban in a still-shared room, or was in a room we
	// ourselves left this window, is reported in `left` only if it no longer
	// shares ANY currently-joined room with us. `seenUsers` is exactly the set of
	// users in our currently-joined rooms, so a candidate present there still
	// shares a room and must be filtered out. Self is never reported.
	const left: UserId[] = [];
	for (const u of newlyLeftUsers) {
		if (u === userId) continue;
		if (seenUsers.has(u)) continue;
		left.push(u);
	}

	const deviceLists: DeviceLists | undefined =
		changedDeviceLists.length > 0 || left.length > 0
			? { changed: changedDeviceLists, left }
			: undefined;

	return {
		next_batch: String(nextBatch),
		device_lists: deviceLists,
		account_data:
			accountDataEvents.length > 0 ? { events: accountDataEvents } : undefined,
		presence:
			presenceEvents.length > 0 ? { events: presenceEvents } : undefined,
		rooms: {
			join: Object.keys(join).length > 0 ? join : undefined,
			invite: Object.keys(invite).length > 0 ? invite : undefined,
			knock: Object.keys(knock).length > 0 ? knock : undefined,
			leave: Object.keys(leave).length > 0 ? leave : undefined,
		},
		to_device:
			toDeviceEvents.length > 0 ? { events: toDeviceEvents } : undefined,
		device_one_time_keys_count: otkCounts,
		device_unused_fallback_key_types: fallbackKeyTypes,
		"org.matrix.msc4429.users": await buildProfileUsers(
			storage,
			userId,
			seenUsers,
			newlyLeftUsers,
			since,
			nextBatch,
			filter.profileFields,
		),
	};
};
// Whether an incremental sync response carries nothing for the client — used by
// the long-poll loop to decide whether to keep waiting. Mirrors the streams a
// client actually observes; an empty response is just `next_batch`.
const isEmptySyncResponse = (r: SyncResponse): boolean =>
	!r.rooms?.join &&
	!r.rooms?.invite &&
	!r.rooms?.knock &&
	!r.rooms?.leave &&
	!r.to_device?.events?.length &&
	!r.device_lists?.changed?.length &&
	!r.device_lists?.left?.length &&
	!r.account_data?.events?.length &&
	!r.presence?.events?.length &&
	!r["org.matrix.msc4429.users"];

export const getSync =
	(storage: Storage, _serverName: string): Handler =>
	async (req) => {
		const userId = req.userId as UserId;
		const deviceId = req.deviceId as DeviceId;
		const sinceStr = req.query.get("since");
		let since = sinceStr !== null ? parseInt(sinceStr, 10) : undefined;
		const timeout = Math.min(
			Math.max(parseInt(req.query.get("timeout") ?? "0", 10), 0),
			MAX_TIMEOUT,
		);
		const fullState = req.query.get("full_state") === "true";
		// MSC4222: clients opt in via `use_state_after=true` (stable) or the unstable
		// `org.matrix.msc4222.use_state_after=true`. When set, joined rooms carry a
		// `state_after` block (and the unstable key) instead of `state`.
		const useStateAfter =
			req.query.get("use_state_after") === "true" ||
			req.query.get("org.matrix.msc4222.use_state_after") === "true";
		const filterParam = req.query.get("filter");

		// `set_presence` lets a client set its presence as a side effect of /sync.
		// Only act when explicitly provided (omitting it must not clobber presence).
		const setPresence = req.query.get("set_presence");
		if (
			setPresence === "online" ||
			setPresence === "unavailable" ||
			setPresence === "offline"
		) {
			await storage.setPresence(userId, setPresence);
		}

		// Validate since token
		if (since !== undefined) {
			const currentPos = await storage.getStreamPosition();
			if (since < 0) {
				throw new MatrixError("M_UNKNOWN_POS", "Invalid sync token", 400);
			}
			// A `since` ahead of our current position is legitimate after a server
			// restart: the client holds a token issued before the restart, and our
			// restored stream counter can land slightly behind it. Clamp to the
			// current position and proceed rather than rejecting — mirrors dendrite's
			// requestpool, which sets Since = currentPos instead of erroring.
			if (since > currentPos) {
				since = currentPos;
			}
		}

		// Resolve filter (inline JSON or filter ID)
		const filter = await resolveFilter(storage, userId, filterParam);

		// Long-poll loop. A bare waitForEvents wakes on ANY stream advance, but a
		// sync must only return once it has something to deliver — otherwise an
		// internal, client-invisible bump (e.g. a partial-state room's hidden
		// activity) returns an empty response immediately, defeating the long poll.
		// So keep re-waiting until the computed response is non-empty or the
		// timeout elapses. Initial syncs and timeout=0 syncs return at once.
		const deadline = Date.now() + timeout;
		let waitFrom = since;
		let response: SyncResponse;
		while (true) {
			if (waitFrom !== undefined && timeout > 0) {
				const remaining = deadline - Date.now();
				if (remaining > 0) await storage.waitForEvents(waitFrom, remaining);
			}

			const nextBatch = await storage.getStreamPosition();
			response =
				since === undefined
					? await buildInitialSync(
							storage,
							userId,
							deviceId,
							nextBatch,
							filter,
							useStateAfter,
						)
					: await buildIncrementalSync(
							storage,
							userId,
							deviceId,
							since,
							nextBatch,
							fullState,
							filter,
							useStateAfter,
						);

			if (
				since === undefined ||
				timeout === 0 ||
				Date.now() >= deadline ||
				!isEmptySyncResponse(response)
			) {
				break;
			}
			// Nothing to deliver yet — wait for the next change past where we are now.
			waitFrom = nextBatch;
		}

		return { status: 200, body: response };
	};
