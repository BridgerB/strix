import {
	findAppserviceForUser,
	parseRegistrations,
} from "../appservice/registration.ts";
import {
	badAlias,
	badJson,
	forbidden,
	invalidParam,
	MatrixError,
	missingParam,
	notFound,
} from "../errors.ts";
import {
	matchesRoomEventFilter,
	parseRoomEventFilter,
} from "../event-filter.ts";
import {
	buildEvent,
	canonicalJson,
	checkEventAuth,
	computeContentHash,
	computeEventId,
	getMembership,
	getPowerLevels,
	getUserPowerLevel,
	isWorldReadable,
	KEY_SEP,
	pduToClientEvent,
	redactEvent,
	requireJoinedOrWorldReadable,
	requireJoinedRoom,
	selectAuthEvents,
} from "../events.ts";
import type { FederationClient } from "../federation/client.ts";
import { fanoutEvent } from "../federation/outbound.ts";
import { verifyOriginSignature } from "../federation/verify.ts";
import { getIgnoredUsers } from "../ignored-users.ts";
import { dispatchPushNotifications } from "../push-notify.ts";
import { bundleAggregations, indexRelation } from "../relations.ts";
import type { Handler } from "../router.ts";
import type { SigningKey } from "../signing.ts";
import { signEvent } from "../signing.ts";
import type { Storage } from "../storage/interface.ts";
import type {
	EventId,
	PDU,
	RoomAlias,
	RoomId,
	UserId,
} from "../types/index.ts";
import type { JsonObject } from "../types/json.ts";
import { parseLimit } from "./query-params.ts";
import { migrateRoomPushRules } from "./room-upgrade.ts";
import { FORGOTTEN_ROOM_MARKER } from "./rooms.ts";

/**
 * Access control for single-event fetch endpoints (`/event/:eventId`,
 * `/context/:eventId`). Per the spec these endpoints hide the existence of
 * rooms/events the requester cannot see, so every "you can't see this" case —
 * whether the room is missing, the user isn't a member, or the room is not
 * world-readable — must surface as HTTP 404 (M_NOT_FOUND) rather than 403.
 *
 * This intentionally differs from `requireJoinedOrWorldReadable`, which throws
 * 403/404 in a way appropriate for listing endpoints (e.g. `/messages`,
 * `/state`, `/members`). We resolve access here locally instead of editing the
 * shared helper so we don't change behaviour for those other callers.
 */
const requireCanReadEventOr404 = async (
	storage: Storage,
	roomId: string,
	userId: string | undefined,
): Promise<void> => {
	const room = await storage.getRoom(roomId);
	if (!room) throw notFound("Event not found");
	if (userId && getMembership(room, userId as UserId) === "join") return;
	if (isWorldReadable(room)) return;
	throw notFound("Event not found");
};

/**
 * Per-event history-visibility check for single-event fetch endpoints
 * (`/event/:eventId`, `/context/:eventId`). Even when the requester is currently
 * joined, the room's `m.room.history_visibility` constrains *which* events they
 * may read:
 *
 *   - `world_readable` / `shared`: every event is visible.
 *   - `invited`: only events from when the user was invited or joined.
 *   - `joined`: only events from when the user was joined.
 *
 * To enforce `joined`/`invited` we replay the room timeline up to (and
 * including) the target event and track the requester's membership at that
 * point. If their membership at the event's position does not grant access, the
 * event is hidden — surfaced as 404 to match `requireCanReadEventOr404`.
 *
 * `world_readable`/`shared` rooms (the common case) short-circuit without any
 * timeline walk.
 */
const requireHistoryVisibleOr404 = async (
	storage: Storage,
	roomId: string,
	eventId: string,
	userId: string | undefined,
): Promise<void> => {
	const room = await storage.getRoom(roomId);
	if (!room) throw notFound("Event not found");

	const hvEvent = room.state_events.get("m.room.history_visibility\x1f");
	const visibility =
		hvEvent &&
		typeof (hvEvent.content as Record<string, unknown>).history_visibility ===
			"string"
			? ((hvEvent.content as Record<string, unknown>)
					.history_visibility as string)
			: "shared";

	// shared / world_readable place no per-event restriction beyond the
	// room-level access check already performed by requireCanReadEventOr404.
	if (visibility !== "joined" && visibility !== "invited") return;
	if (!userId) throw notFound("Event not found");

	// Walk the full timeline in ascending stream order, tracking this user's
	// membership and the active history_visibility, until we reach the target
	// event. We then decide based on the membership/visibility at that point.
	const all = await storage.getEventsByRoomSince(
		roomId as RoomId,
		0,
		1_000_000,
	);
	let membership: string | undefined;
	let activeVisibility = "shared";
	let found = false;

	for (const e of all.events) {
		const ev = e.event;

		if (
			ev.type === "m.room.history_visibility" &&
			ev.state_key === "" &&
			typeof (ev.content as Record<string, unknown>).history_visibility ===
				"string"
		) {
			activeVisibility = (ev.content as Record<string, unknown>)
				.history_visibility as string;
		}

		// The target event is visible if, at the moment it was sent, the
		// requester's membership satisfies the then-active visibility. For
		// `joined` they must already be joined; for `invited`, joined or
		// invited. (Membership is evaluated *before* applying the target event
		// itself, so a user's own join event is not retroactively visible under
		// `joined`.)
		if (e.eventId === eventId) {
			found = true;
			if (activeVisibility === "joined" && membership !== "join") {
				throw notFound("Event not found");
			}
			if (
				activeVisibility === "invited" &&
				membership !== "join" &&
				membership !== "invite"
			) {
				throw notFound("Event not found");
			}
			break;
		}

		if (ev.type === "m.room.member" && ev.state_key === userId) {
			const m = (ev.content as Record<string, unknown>).membership;
			if (typeof m === "string") membership = m;
		}
	}

	// If the event isn't in the timeline at all, leave the not-found decision to
	// the caller's getEvent lookup.
	if (!found) return;
};

/** A well-formed room alias is `#localpart:server_name`. */
const isWellFormedAlias = (alias: unknown): alias is string => {
	if (typeof alias !== "string" || !alias.startsWith("#")) return false;
	const colon = alias.indexOf(":");
	return colon > 1 && colon < alias.length - 1;
};

/**
 * Validate the content of an `m.room.canonical_alias` event: every alias listed
 * (the primary `alias` and each of `alt_aliases`) must be well-formed and must
 * resolve, in the local directory, to this room. Throws M_INVALID_PARAM for a
 * malformed alias and M_BAD_ALIAS for one that is missing or points elsewhere.
 */
const validateCanonicalAlias = async (
	storage: Storage,
	roomId: string,
	content: JsonObject,
): Promise<void> => {
	const candidates: unknown[] = [];
	if (content.alias !== undefined) candidates.push(content.alias);
	if (Array.isArray(content.alt_aliases))
		candidates.push(...content.alt_aliases);

	for (const candidate of candidates) {
		if (!isWellFormedAlias(candidate)) {
			throw invalidParam(`Invalid alias: ${String(candidate)}`);
		}
		const resolved = await storage.getRoomByAlias(candidate as RoomAlias);
		if (!resolved || resolved.room_id !== (roomId as RoomId)) {
			throw badAlias(`Alias ${candidate} does not point to this room`);
		}
	}
};

/**
 * Resolve the `?ts=<ms>` query param for an event send. Per the Client-Server
 * spec, application services may backdate (or post-date) events by supplying a
 * `ts` query parameter giving the desired `origin_server_ts` in milliseconds.
 * This is the mechanism bridges use to import historical messages and is what
 * the MSC3030 jump-to-date (`/timestamp_to_event`) tests exercise.
 *
 * We only honour `ts` when the authenticated requester is an application service
 * user (their user ID falls within a registered AS user namespace). Regular
 * users never get to set `origin_server_ts`. Returns `undefined` when no valid
 * override applies, in which case `buildEvent` uses `Date.now()` as normal.
 */
const resolveTsOverride = (req: {
	query: URLSearchParams;
	userId?: string;
}): number | undefined => {
	const tsStr = req.query.get("ts");
	if (tsStr === null) return undefined;
	if (!req.userId) return undefined;

	const registrations = parseRegistrations();
	if (!findAppserviceForUser(req.userId, registrations)) return undefined;

	const ts = parseInt(tsStr, 10);
	if (Number.isNaN(ts)) throw invalidParam("'ts' must be an integer");
	return ts;
};

/**
 * Apply an `origin_server_ts` override to a freshly built event. Because the
 * timestamp is part of the hashed/signed content, the content hash, event ID and
 * signature must all be recomputed — this mirrors `buildEvent` exactly, just
 * with the caller-supplied timestamp instead of `Date.now()`. Returns the new
 * (event, eventId) pair; the original `eventId` is no longer valid.
 */
const applyTsOverride = (
	event: PDU,
	originServerTs: number,
	serverName: string,
	signingKey?: SigningKey,
	roomVersion?: string,
): { event: PDU; eventId: EventId } => {
	// Build the unsigned, hash-able form: drop the prior hash/signatures so the
	// recompute below starts from clean content (buildEvent does the same).
	const rebuilt: PDU = {
		...event,
		origin_server_ts: originServerTs,
		hashes: { sha256: "" },
		signatures: { [serverName]: {} },
	};
	delete (rebuilt as { unsigned?: unknown }).unsigned;

	rebuilt.hashes = { sha256: computeContentHash(rebuilt) };
	const eventId = computeEventId(rebuilt, roomVersion);

	if (signingKey) {
		return {
			event: signEvent(rebuilt, serverName, signingKey, roomVersion),
			eventId,
		};
	}
	return { event: rebuilt, eventId };
};

export const putSendEvent =
	(
		storage: Storage,
		serverName: string,
		signingKey?: SigningKey,
		federationClient?: FederationClient,
	): Handler =>
	async (req) => {
		const roomId = req.params.roomId as string;
		const eventType = req.params.eventType as string;
		const txnId = req.params.txnId as string;
		const userId = req.userId as string;
		const deviceId = req.deviceId as string;

		// Transaction idempotency is scoped to (user, device, room, txnId): the
		// same txnId reused in the SAME room must return the SAME event, but the
		// same txnId in a DIFFERENT room must produce a new event. The storage
		// txn key is (user, device, txnId) only, so we fold the room into the
		// opaque txn-id string to scope it per-room without changing storage.
		const scopedTxnId = `${roomId}${KEY_SEP}${txnId}`;

		const existing = await storage.getTxnEventId(userId, deviceId, scopedTxnId);
		if (existing) return { status: 200, body: { event_id: existing } };

		// Validate that body is a JSON object (not array, string, number, null, etc.)
		const content = req.body ?? {};
		if (
			typeof content !== "object" ||
			content === null ||
			Array.isArray(content)
		) {
			throw badJson("Event content must be a JSON object");
		}

		const room = await requireJoinedRoom(storage, roomId, userId);

		const authEvents = selectAuthEvents(eventType, undefined, room, userId);
		// Sign the event (when a signing key is available) so it can be fanned out
		// to remote servers, which reject unsigned PDUs. Signing is additive and
		// does not change the event ID (computed over the redacted form).
		const built = buildEvent({
			roomId,
			sender: userId,
			type: eventType,
			content: content as JsonObject,
			depth: room.depth,
			prevEvents: [...room.forward_extremities],
			authEvents,
			serverName,
			signingKey,
			roomVersion: room.room_version,
		});

		// Application services may backdate events via `?ts=<ms>`. Since the
		// timestamp is hashed/signed, this re-derives the event ID and signature.
		const tsOverride = resolveTsOverride(req);
		const { event, eventId } =
			tsOverride !== undefined
				? applyTsOverride(
						built.event,
						tsOverride,
						serverName,
						signingKey,
						room.room_version,
					)
				: built;

		const eventSize = Buffer.byteLength(canonicalJson(event), "utf-8");
		if (eventSize > 65536) {
			throw new MatrixError("M_TOO_LARGE", "Event is too large", 413);
		}

		checkEventAuth(event, eventId, room);

		// Store transaction_id in unsigned for the sender. `unsigned` is excluded
		// from the signed/hashed form, so adding it after signing is safe and does
		// not invalidate the signature.
		event.unsigned = {
			...event.unsigned,
			transaction_id: txnId,
		};

		await storage.storeEvent(event, eventId);
		await indexRelation(storage, event, eventId);

		room.depth++;
		room.forward_extremities = [eventId];

		await storage.setTxnEventId(userId, deviceId, scopedTxnId, eventId);

		// Propagate to remote servers in the room (best-effort, fire-and-forget).
		if (signingKey && federationClient) {
			await fanoutEvent(
				storage,
				serverName,
				signingKey,
				federationClient,
				roomId as RoomId,
				event,
				eventId,
			);
		}

		// Push-gateway dispatch for local members with HTTP pushers. Truly
		// fire-and-forget (external gateways must not delay the send response);
		// the function swallows its own errors.
		void dispatchPushNotifications(
			storage,
			serverName,
			event,
			eventId,
			room,
		).catch(() => {});

		return { status: 200, body: { event_id: eventId } };
	};

export const putStateEvent =
	(
		storage: Storage,
		serverName: string,
		signingKey?: SigningKey,
		federationClient?: FederationClient,
	): Handler =>
	async (req) => {
		const roomId = req.params.roomId as string;
		const eventType = req.params.eventType as string;
		const stateKey = req.params.stateKey ?? "";
		const userId = req.userId as string;

		// Validate that body is a JSON object
		const rawContent = req.body ?? {};
		if (
			typeof rawContent !== "object" ||
			rawContent === null ||
			Array.isArray(rawContent)
		) {
			throw badJson("Event content must be a JSON object");
		}
		const newContent = rawContent as JsonObject;

		const room = await requireJoinedRoom(storage, roomId, userId);

		if (eventType === "m.room.canonical_alias") {
			await validateCanonicalAlias(storage, roomId, newContent);
		}

		// No-op state dedup (mirrors Synapse's `deduplicate_state_event`): if the
		// room already has a state event of this (type, state_key) whose content is
		// deep-equal to the new content AND was sent by the same user, sending it
		// again is a no-op — return the EXISTING event's ID without creating a
		// duplicate. This prevents redundant history_visibility / etc. events from
		// piling up (and is what TestInboundCanReturnMissingEvents relies on to keep
		// the DAG free of spurious no-op events).
		const existing = await storage.getStateEvent(roomId, eventType, stateKey);
		if (existing) {
			const sameContent =
				canonicalJson(existing.event.content) === canonicalJson(newContent);
			const sameSender = existing.event.sender === userId;
			if (sameContent && sameSender) {
				return { status: 200, body: { event_id: existing.eventId } };
			}
		}

		const authEvents = selectAuthEvents(eventType, stateKey, room, userId);
		// Sign the state event (when a signing key is available) for federation
		// fan-out. Signing does not change the event ID.
		const builtState = buildEvent({
			roomId,
			sender: userId,
			type: eventType,
			content: newContent,
			stateKey,
			depth: room.depth,
			prevEvents: [...room.forward_extremities],
			authEvents,
			serverName,
			signingKey,
			roomVersion: room.room_version,
		});

		// Application services may backdate state events via `?ts=<ms>`.
		const stateTsOverride = resolveTsOverride(req);
		const { event, eventId } =
			stateTsOverride !== undefined
				? applyTsOverride(
						builtState.event,
						stateTsOverride,
						serverName,
						signingKey,
						room.room_version,
					)
				: builtState;

		const stateEventSize = Buffer.byteLength(canonicalJson(event), "utf-8");
		if (stateEventSize > 65536) {
			throw new MatrixError("M_TOO_LARGE", "Event is too large", 413);
		}

		checkEventAuth(event, eventId, room);
		await storage.setStateEvent(roomId, event, eventId);

		// Manual room upgrade: a client can upgrade a room by creating the
		// replacement itself and then sending an m.room.tombstone naming it
		// (instead of calling POST /upgrade). Mirror postRoomUpgrade and copy each
		// local joined user's room-scoped push rules to the replacement room.
		// (TestPushRuleRoomUpgrade "manually upgrading a room ...".)
		if (
			eventType === "m.room.tombstone" &&
			stateKey === "" &&
			typeof (event.content as { replacement_room?: unknown })
				.replacement_room === "string"
		) {
			await migrateRoomPushRules(
				storage,
				serverName,
				room,
				roomId as RoomId,
				(event.content as { replacement_room: string })
					.replacement_room as RoomId,
			);
		}

		room.depth++;
		room.forward_extremities = [eventId];

		// Propagate to remote servers in the room (best-effort, fire-and-forget).
		if (signingKey && federationClient) {
			await fanoutEvent(
				storage,
				serverName,
				signingKey,
				federationClient,
				roomId as RoomId,
				event,
				eventId,
			);
		}

		return { status: 200, body: { event_id: eventId } };
	};

/** Throw 403 if the user has forgotten this room (read endpoints reject it). */
const assertNotForgotten = async (
	storage: Storage,
	userId: string | undefined,
	roomId: string,
): Promise<void> => {
	if (!userId) return;
	const marker = await storage.getRoomAccountData(
		userId as UserId,
		roomId as RoomId,
		FORGOTTEN_ROOM_MARKER,
	);
	if ((marker as { forgotten?: boolean } | undefined)?.forgotten === true) {
		throw forbidden(`Forgotten room ${roomId} cannot be read`);
	}
};

/**
 * SPEC-216 ("departed room" reads): a user who has left (or been banned from) a
 * room may still read it AS OF the point at which they left — but not its
 * current state, nor any events after their departure. This is the behaviour
 * Synapse implements in `RoomMemberHandler` / the `/state`, `/members`,
 * `/messages` paths (history is clamped to the user's own leave event).
 *
 * Given a requester who is NOT currently joined, this resolves whether they may
 * read the room under SPEC-216 and, if so, the stream position of their OWN last
 * `m.room.member` (leave/ban) event. We scan the room timeline in ascending
 * stream order for the requester's `state_key`, tracking the latest membership
 * event and its stream position.
 *
 * Returns:
 *   - `{ allowed: true, leavePos }` when the requester left/was banned — reads
 *     should be served as of `leavePos`.
 *   - `{ allowed: false }` when the requester is currently joined (caller should
 *     use the normal current-state path) or has no qualifying membership.
 *
 * Note this only fires for the leave/ban case; joined and world-readable access
 * is still handled by the existing `requireJoinedOrWorldReadable` callers.
 */
const resolveDepartedRead = async (
	storage: Storage,
	roomId: string,
	userId: string | undefined,
): Promise<{ allowed: true; leavePos: number } | { allowed: false }> => {
	if (!userId) return { allowed: false };

	const room = await storage.getRoom(roomId);
	if (!room) return { allowed: false };

	const membership = getMembership(room, userId as UserId);
	if (membership !== "leave" && membership !== "ban") return { allowed: false };

	// Scan ascending; keep the stream position of the user's latest membership
	// event. That position is the requester's departure point.
	const all = await storage.getEventsByRoomSince(
		roomId as RoomId,
		0,
		1_000_000,
	);
	let leavePos = 0;
	for (const e of all.events) {
		if (e.event.type !== "m.room.member") continue;
		if (e.event.state_key !== userId) continue;
		leavePos = e.streamPos;
	}

	return { allowed: true, leavePos };
};

/**
 * Compute the full room state (latest state event per (type, state_key)) as of a
 * given stream position by replaying every state event up to and including that
 * position. Used to serve `/state` and `/members` to a departed user with the
 * room as it was when they left.
 */
const stateAsOf = async (
	storage: Storage,
	roomId: string,
	at: number,
): Promise<{ event: PDU; eventId: EventId }[]> => {
	const all = await storage.getEventsByRoomSince(
		roomId as RoomId,
		0,
		1_000_000,
	);
	const latest = new Map<string, { event: PDU; eventId: EventId }>();
	for (const e of all.events) {
		if (e.streamPos > at) break;
		if (typeof e.event.state_key !== "string") continue;
		latest.set(`${e.event.type}${KEY_SEP}${e.event.state_key}`, {
			event: e.event,
			eventId: e.eventId,
		});
	}
	return [...latest.values()];
};

export const getAllState =
	(storage: Storage): Handler =>
	async (req) => {
		const roomId = req.params.roomId as string;
		await assertNotForgotten(storage, req.userId, roomId);

		// SPEC-216: a departed (left/banned) user reads state as of their leave.
		const departed = await resolveDepartedRead(storage, roomId, req.userId);
		if (departed.allowed) {
			const stateEntries = await stateAsOf(storage, roomId, departed.leavePos);
			return {
				status: 200,
				body: stateEntries.map((e) => pduToClientEvent(e.event, e.eventId)),
			};
		}

		await requireJoinedOrWorldReadable(storage, roomId, req.userId);

		const stateEntries = await storage.getAllState(roomId);
		const events = stateEntries.map((e) =>
			pduToClientEvent(e.event, e.eventId),
		);
		return { status: 200, body: events };
	};

export const getStateEvent =
	(storage: Storage): Handler =>
	async (req) => {
		const roomId = req.params.roomId as string;
		const eventType = req.params.eventType as string;
		const stateKey = req.params.stateKey ?? "";

		await assertNotForgotten(storage, req.userId, roomId);

		// SPEC-216: a departed (left/banned) user gets the state value as of their
		// leave point, not the current value.
		const departed = await resolveDepartedRead(storage, roomId, req.userId);
		let entry: { event: PDU; eventId: EventId } | undefined;
		if (departed.allowed) {
			const stateEntries = await stateAsOf(storage, roomId, departed.leavePos);
			entry = stateEntries.find(
				(e) => e.event.type === eventType && e.event.state_key === stateKey,
			);
		} else {
			await requireJoinedOrWorldReadable(storage, roomId, req.userId);
			entry = await storage.getStateEvent(roomId, eventType, stateKey);
		}
		if (!entry) throw notFound("State event not found");

		const format = req.query.get("format");
		if (format === "event") {
			return {
				status: 200,
				body: pduToClientEvent(entry.event, entry.eventId),
			};
		}

		return { status: 200, body: entry.event.content };
	};

/**
 * Outbound `/messages` backfill (mirrors Synapse's
 * `FederationHandler.maybe_backfill`). When a local user paginates backward
 * (`dir=b`) into a room whose history we only partially hold — typically after
 * joining a remote room via `send_join`, which gives us the current state but
 * not the historical timeline — there is a "gap": events we hold reference
 * `prev_events` we do not. We fill that gap by asking a remote server in the
 * room for the missing events via `GET /_matrix/federation/v1/backfill`.
 *
 * Each returned PDU is verified (content hash, origin signature, event id),
 * deduplicated against storage, persisted, and indexed for relations, exactly
 * as an inbound transaction PDU would be. We run a bounded number of rounds so
 * a hostile/large remote history cannot make a single request unbounded.
 *
 * Returns the number of new events imported across all rounds.
 */
const backfillMissingHistory = async (
	storage: Storage,
	serverName: string,
	federationClient: FederationClient,
	roomId: RoomId,
	roomVersion: string | undefined,
	maxRounds = 2,
): Promise<number> => {
	// Choose a remote server that participates in the room (excluding ourselves).
	const servers = (await storage.getServersInRoom(roomId)).filter(
		(s) => s !== serverName,
	);
	if (servers.length === 0) return 0;

	let imported = 0;

	for (let round = 0; round < maxRounds; round++) {
		// Re-read the timeline each round: previously-imported events extend the
		// known set and shift the gap boundary further back.
		const all = await storage.getEventsByRoom(
			roomId,
			1_000_000,
			undefined,
			"f",
		);
		const known = new Set<EventId>(all.events.map((e) => e.eventId));

		// The backfill "seeds" are the IDs of prev_events we reference but do not
		// hold — the earliest edge of our known DAG. These are exactly the events
		// the remote should walk back from. Synapse seeds from the room's
		// backward extremities; the unknown prev_events are their analogue here.
		const seeds = new Set<EventId>();
		for (const { event } of all.events) {
			for (const prev of event.prev_events) {
				if (!known.has(prev)) seeds.add(prev);
			}
		}
		if (seeds.size === 0) break; // No gap — nothing to backfill.

		const v = [...seeds].slice(0, 10);
		const qs = v.map((id) => `v=${encodeURIComponent(id)}`).join("&");
		const path = `/_matrix/federation/v1/backfill/${encodeURIComponent(
			roomId,
		)}?${qs}&limit=100`;

		let roundImported = 0;
		for (const server of servers) {
			let res: { status: number; body: unknown };
			try {
				res = await federationClient.request(server, "GET", path);
			} catch {
				continue; // Try the next server.
			}
			if (
				res.status !== 200 ||
				typeof res.body !== "object" ||
				res.body === null
			)
				continue;

			const pdus = (res.body as { pdus?: unknown }).pdus;
			if (!Array.isArray(pdus)) continue;

			for (const raw of pdus) {
				if (!raw || typeof raw !== "object") continue;
				const event = raw as PDU;
				if (event.room_id !== roomId) continue;

				// Verify content hash, then recompute the event id from the content
				// (v4+ event IDs are content hashes) and reject mismatches.
				let eventId: EventId;
				try {
					const expectedHash = computeContentHash(event);
					if (event.hashes?.sha256 !== expectedHash) continue;
					eventId = computeEventId(event, roomVersion);
				} catch {
					continue;
				}

				// Dedupe: skip anything we already hold.
				if (await storage.getEvent(eventId)) continue;

				// Verify the event is correctly signed by its origin server.
				try {
					await verifyOriginSignature(
						event,
						server,
						storage,
						federationClient,
						roomVersion,
					);
				} catch {
					continue;
				}

				await storage.storeEvent(event, eventId);
				await indexRelation(storage, event, eventId);
				imported++;
				roundImported++;
			}

			// One server that produced events is enough for this round.
			if (roundImported > 0) break;
		}

		if (roundImported === 0) break; // No progress — stop.
	}

	return imported;
};

/**
 * Build a complete depth-ordered (ascending) view of every event currently held
 * for a room, deduplicated by event id. After backfill, historical events live
 * at the *newest* stream positions (storage appends by insertion order), so
 * `getEventsByRoom`'s stream-ordered output no longer reflects DAG order. We
 * therefore reorder by `(depth, origin_server_ts, event_id)` ourselves before
 * serving the `/messages` chunk and paginating it.
 */

/**
 * Synapse-style topological pagination token: `t<depth>-<stream>` (mirrors
 * `RoomStreamToken.to_string`, types/__init__.py). Unlike an array index it
 * encodes the event's actual DAG position, so it stays valid even as backfill
 * adds earlier events to the room — which is exactly what `/context` -> backward
 * `/messages` after a jump-to-date needs (TestJumpToDateEndpoint).
 */
const topoToken = (depth: number, stream: number): string =>
	`t${depth}-${stream}`;

const parseTopoToken = (
	s: string | null,
): { depth: number; stream: number } | undefined => {
	if (!s) return undefined;
	const m = /^t(\d+)-(\d+)$/.exec(s);
	if (!m) return undefined;
	return {
		depth: parseInt(m[1] as string, 10),
		stream: parseInt(m[2] as string, 10),
	};
};

/** Compare two (depth, stream) positions. Negative if a < b. */
const cmpTopo = (
	a: { depth: number; stream: number },
	b: { depth: number; stream: number },
): number => a.depth - b.depth || a.stream - b.stream;

const buildDepthOrdered = (
	events: { event: PDU; eventId: EventId }[],
): { event: PDU; eventId: EventId }[] => {
	const seen = new Set<EventId>();
	const out: { event: PDU; eventId: EventId }[] = [];
	for (const e of events) {
		if (seen.has(e.eventId)) continue;
		seen.add(e.eventId);
		out.push(e);
	}
	out.sort(
		(a, b) =>
			a.event.depth - b.event.depth ||
			a.event.origin_server_ts - b.event.origin_server_ts ||
			(a.eventId < b.eventId ? -1 : a.eventId > b.eventId ? 1 : 0),
	);
	return out;
};

export const getMessages =
	(
		storage: Storage,
		serverName?: string,
		_signingKey?: SigningKey,
		federationClient?: FederationClient,
	): Handler =>
	async (req) => {
		const roomId = req.params.roomId as string;
		const userId = req.userId as UserId;
		// `/messages` is a listing endpoint: a non-member who cannot otherwise
		// see the room (including the case where the room does not exist) must
		// get 403 ("You aren't a member of the room"), NOT 404. This matches
		// Synapse and TestFetchMessagesFromNonExistentRoom. We resolve access
		// locally here so the missing-room case maps to 403 rather than the
		// shared helper's 404.
		const messagesRoom = await storage.getRoom(roomId);
		// SPEC-216: a departed (left/banned) user may still page history up to their
		// leave point. `departed.leavePos` is the stream position of their last
		// membership event; events after it are not visible to them (enforced
		// below by clamping the returned chunk).
		const messagesDeparted = await resolveDepartedRead(storage, roomId, userId);
		if (
			!messagesRoom ||
			(!messagesDeparted.allowed &&
				getMembership(messagesRoom, userId) !== "join" &&
				!isWorldReadable(messagesRoom))
		) {
			throw forbidden("You aren't a member of the room");
		}
		await assertNotForgotten(storage, userId, roomId);
		const departedLeavePos = messagesDeparted.allowed
			? messagesDeparted.leavePos
			: undefined;

		const dir = (req.query.get("dir") ?? "f") as "b" | "f";
		if (dir !== "b" && dir !== "f") throw badJson("dir must be 'b' or 'f'");

		const fromStr = req.query.get("from");
		// Token kinds: `t<depth>-<stream>` is a topological token (from /context or
		// continued depth-ordered /messages) — stable across backfill. `b<index>`
		// is a legacy depth-index continuation token. A plain integer is a stream
		// position used by the storage-backed pager (e.g. a /sync prev_batch).
		const topoFrom = parseTopoToken(fromStr);
		const isBackfillToken = fromStr !== null && /^b\d+$/.test(fromStr);
		const from =
			fromStr && !isBackfillToken && !topoFrom
				? parseInt(fromStr, 10)
				: undefined;
		const limitStr = req.query.get("limit");
		const limit = parseLimit(limitStr, 10);

		const filter = parseRoomEventFilter(req.query.get("filter"));

		// MSC3874: filter the timeline by the relation type of each event
		// (`org.matrix.msc3874.rel_types` / `.not_rel_types`). These fields are
		// not part of the standard RoomEventFilter handled by
		// `matchesRoomEventFilter`, so we read them off the parsed filter object
		// and apply them locally here. An event's relation type is
		// `content["m.relates_to"]["rel_type"]` (undefined if it has no relation).
		const relFilter = filter as
			| {
					"org.matrix.msc3874.rel_types"?: string[];
					"org.matrix.msc3874.not_rel_types"?: string[];
			  }
			| undefined;
		const relTypes = Array.isArray(relFilter?.["org.matrix.msc3874.rel_types"])
			? relFilter["org.matrix.msc3874.rel_types"]
			: undefined;
		const notRelTypes = Array.isArray(
			relFilter?.["org.matrix.msc3874.not_rel_types"],
		)
			? relFilter["org.matrix.msc3874.not_rel_types"]
			: undefined;

		const relTypeOf = (e: { content: unknown }): string | undefined => {
			const relatesTo = (e.content as Record<string, unknown> | undefined)?.[
				"m.relates_to"
			];
			if (relatesTo && typeof relatesTo === "object") {
				const rt = (relatesTo as Record<string, unknown>).rel_type;
				if (typeof rt === "string") return rt;
			}
			return undefined;
		};

		// Resolve the raw page of events to serve. The normal path is the
		// storage-backed (stream-ordered) pager. For backward pagination into a
		// room whose history we only partially hold, we instead backfill the gap
		// from a remote server and serve a depth-ordered view (see
		// `backfillMissingHistory` / `buildDepthOrdered`). The depth-ordered pager
		// uses `b<index>` tokens so it can be continued across requests.
		let result: {
			events: { event: PDU; eventId: EventId }[];
			end?: number | string;
		};

		// Decide whether to serve a DAG (topological) view for backward pagination:
		// when continuing a `t<depth>-<stream>` token, or when the room holds
		// federated history that is gappy / out of stream order (so the plain
		// stream pager can't return DAG-correct order). Departed (SPEC-216) readers
		// are clamped to local history and never use this path.
		let useTopoPager = false;
		if (dir === "b" && departedLeavePos === undefined) {
			if (topoFrom !== undefined) {
				useTopoPager = true;
			} else if (serverName && federationClient) {
				const remoteServers = (
					await storage.getServersInRoom(roomId as RoomId)
				).filter((s) => s !== serverName);
				if (remoteServers.length > 0) {
					const localAll = await storage.getEventsByRoom(
						roomId as RoomId,
						1_000_000,
						undefined,
						"f",
					);
					const known = new Set<EventId>(localAll.events.map((e) => e.eventId));
					const hasGap = localAll.events.some((e) =>
						e.event.prev_events.some((p) => !known.has(p)),
					);
					// Out of stream order: a held event references a held prev stored
					// LATER (higher stream index) — ancestors backfilled after their
					// descendants (jump-to-date fetches a remote event + its chain).
					const streamIdx = new Map<EventId, number>();
					localAll.events.forEach((e, i) => {
						streamIdx.set(e.eventId, i);
					});
					const outOfOrder = localAll.events.some((e, i) =>
						e.event.prev_events.some((p) => {
							const pi = streamIdx.get(p as EventId);
							return pi !== undefined && pi > i;
						}),
					);
					useTopoPager = hasGap || outOfOrder;
				}
			}
		}

		if (useTopoPager) {
			// Pull missing history into storage on EVERY backward page (not just the
			// first) so a client paginating deep history keeps fetching older events
			// instead of stopping at the first backfilled chunk. backfillMissingHistory
			// is a no-op when there is no gap, so the cost on a fully-held room is just
			// a local read.
			if (serverName && federationClient) {
				const remoteServers = (
					await storage.getServersInRoom(roomId as RoomId)
				).filter((s) => s !== serverName);
				if (remoteServers.length > 0) {
					await backfillMissingHistory(
						storage,
						serverName,
						federationClient,
						roomId as RoomId,
						messagesRoom.room_version,
					);
				}
			}

			// Depth-ordered view annotated with stream positions for the tokens.
			const localWithPos = await storage.getEventsByRoomSince(
				roomId as RoomId,
				0,
				1_000_000,
			);
			const streamById = new Map<EventId, number>(
				localWithPos.events.map((e) => [e.eventId, e.streamPos]),
			);
			const ordered = buildDepthOrdered(
				localWithPos.events.map((e) => ({
					event: e.event,
					eventId: e.eventId,
				})),
			).map((o) => ({
				event: o.event,
				eventId: o.eventId,
				depth: o.event.depth,
				stream: streamById.get(o.eventId) ?? 0,
			}));

			// Boundary: the topological token, or — if the client supplied a plain
			// numeric (stream) token — the topological position of the event at that
			// stream position, so a /sync prev_batch still paginates correctly here.
			let boundary = topoFrom;
			if (!boundary && from !== undefined) {
				const e = ordered.find((o) => o.stream === from);
				if (e) boundary = { depth: e.depth, stream: e.stream };
			}

			// dir=b: events strictly earlier (by depth, then stream) than the
			// boundary — or all of them if there's none — keeping the latest `limit`
			// (closest to the boundary), served newest-first. The `end` token is the
			// oldest event we returned, so a follow-up page continues from there.
			const candidates = boundary
				? ordered.filter((e) => cmpTopo(e, boundary) < 0)
				: ordered;
			const pageAsc = candidates.slice(Math.max(0, candidates.length - limit));
			const page = [...pageAsc].reverse();
			const oldest = pageAsc[0];
			result = {
				events: page.map(({ event, eventId }) => ({ event, eventId })),
				end:
					oldest && candidates.length > pageAsc.length
						? topoToken(oldest.depth, oldest.stream)
						: undefined,
			};
		} else if (departedLeavePos !== undefined) {
			// SPEC-216: a departed reader sees only events up to and including their
			// leave (stream position `departedLeavePos`). Build the page directly
			// from the stream-ordered timeline, bounded by the leave position, so
			// post-leave events are never surfaced regardless of the `from` token.
			// `dir=f` from the leave token therefore yields an empty chunk; `dir=b`
			// returns the most recent visible events (including the user's own leave
			// member event) newest-first.
			const since = await storage.getEventsByRoomSince(
				roomId as RoomId,
				0,
				1_000_000,
			);
			const visible = since.events.filter(
				(e) => e.streamPos <= departedLeavePos,
			);

			let page: { event: PDU; eventId: EventId; streamPos: number }[];
			if (dir === "f") {
				// Forward from `from`: events strictly after the token but still
				// within the visible (<= leave) window. From the leave token this is
				// empty.
				const lower = from ?? 0;
				page = visible.filter((e) => e.streamPos > lower).slice(0, limit);
			} else {
				// Backward from `from`: the visible events at or before the token,
				// newest-first. The sync `from` token equals the stream position of
				// the user's own leave event (our stream counter points AT, not
				// after, the last event), so the boundary is inclusive — this is what
				// surfaces the user's `m.room.member` leave event in the first page.
				// We never exceed the leave position regardless of the token.
				const upper = Math.min(from ?? departedLeavePos, departedLeavePos);
				page = visible
					.filter((e) => e.streamPos <= upper)
					.reverse()
					.slice(0, limit);
			}

			result = {
				events: page.map((e) => ({ event: e.event, eventId: e.eventId })),
				// For backward pagination, the `end` token must point just before the
				// oldest event returned so the next page does not repeat it.
				end:
					page.length > 0
						? dir === "b"
							? (page[page.length - 1] as { streamPos: number }).streamPos - 1
							: (page[page.length - 1] as { streamPos: number }).streamPos
						: undefined,
			};
		} else {
			// Normal pagination. We page in TOPOLOGICAL (DAG) order — `(depth,
			// stream_ordering)` — rather than raw stream/arrival order, mirroring
			// Synapse's `paginate_room_events_by_topological_ordering`
			// (storage/databases/main/stream.py: `ORDER BY topological_ordering,
			// stream_ordering`). This matters when an event arrives out of DAG order:
			// a federated event injected late (high stream position) but forked at an
			// earlier point in the DAG (low depth) must scroll back into its DAG
			// position, not its arrival position. Ordering by stream alone returns
			// scrollback in the wrong order and can drop the boundary event
			// (TestNetworkPartitionOrdering).
			//
			// The pagination cursor remains a STREAM position (our tokens are plain
			// integers, and sync's `prev_batch` is a stream position): we select the
			// page by a stream-position bound but ORDER the selected events
			// topologically. Bounds are inclusive of the token on the "from" side so a
			// sync `prev_batch` of `firstKept - 1` includes the event immediately
			// older (in stream order) than the live window; the emitted `end` token is
			// `oldest_returned_stream_pos - 1` (dir=b) / `newest_returned_stream_pos +
			// 1` (dir=f), keeping successive pages contiguous and non-overlapping.
			const all = await storage.getEventsByRoomSince(
				roomId as RoomId,
				0,
				1_000_000,
			);

			// Topological (depth, then stream) ascending order over the whole room.
			const ordered = [...all.events].sort(
				(a, b) => a.event.depth - b.event.depth || a.streamPos - b.streamPos,
			);

			let page: { event: PDU; eventId: EventId; streamPos: number }[];
			let end: number | undefined;

			if (dir === "b") {
				// Backward: events at or before the cursor (by stream position), most
				// recent first in DAG order. Absent token → start from the newest.
				const upper = from ?? Number.POSITIVE_INFINITY;
				const eligible = ordered.filter((e) => e.streamPos <= upper);
				page = eligible.slice(Math.max(0, eligible.length - limit)).reverse();
				// Always emit `end` when we returned events — Synapse returns the next
				// token even at the start of the room (paginating from it just yields an
				// empty page). Clients/tests rely on `end` being present
				// (TestRoomImageRoundtrip asserts it is a string).
				if (page.length > 0) {
					const oldest = page[page.length - 1] as { streamPos: number };
					end = oldest.streamPos - 1;
				}
			} else {
				// Forward: events strictly after the cursor (by stream position),
				// oldest first in DAG order. The lower bound is EXCLUSIVE so paginating
				// forward from a sync `next_batch` token (a stream position pointing AT
				// the last-seen event) does not re-deliver that event — matching the
				// previous stream-ordered pager's `streamPos > from` semantics and
				// TestSendAndFetchMessage (forward from a pre-send token must return
				// only the newly-sent event, not the boundary state event). Absent
				// token → start from the beginning of the room.
				const lower = from ?? Number.NEGATIVE_INFINITY;
				const eligible = ordered.filter((e) => e.streamPos > lower);
				page = eligible.slice(0, limit);
				if (page.length > 0) {
					// Next forward page continues strictly after the newest returned.
					const newest = page[page.length - 1] as { streamPos: number };
					end = newest.streamPos;
				}
			}

			result = {
				events: page.map((e) => ({ event: e.event, eventId: e.eventId })),
				end,
			};
		}

		let chunk = result.events.map((e) => pduToClientEvent(e.event, e.eventId));

		if (filter) {
			chunk = chunk.filter((e) => matchesRoomEventFilter(e, filter));
		}

		if (relTypes) {
			chunk = chunk.filter((e) => {
				const rt = relTypeOf(e);
				return rt !== undefined && relTypes.includes(rt);
			});
		}
		if (notRelTypes) {
			chunk = chunk.filter((e) => {
				const rt = relTypeOf(e);
				return rt === undefined || !notRelTypes.includes(rt);
			});
		}

		const ignoredUsers = await getIgnoredUsers(storage, userId);
		if (ignoredUsers.size > 0) {
			chunk = chunk.filter(
				(e) =>
					e.state_key !== undefined || !ignoredUsers.has(e.sender as UserId),
			);
		}

		await bundleAggregations(storage, chunk, userId);

		// Lazy-loading members: when the filter sets `lazy_load_members`, include
		// in `state` the `m.room.member` event for each distinct sender of the
		// returned timeline `chunk` (rather than every member of the room). This
		// lets clients render senders without fetching the full member list.
		let state: ReturnType<typeof pduToClientEvent>[] | undefined;
		if (filter?.lazy_load_members) {
			const seen = new Set<string>();
			const memberEvents: ReturnType<typeof pduToClientEvent>[] = [];
			for (const e of chunk) {
				const sender = e.sender as string;
				if (seen.has(sender)) continue;
				seen.add(sender);
				const entry = await storage.getStateEvent(
					roomId as RoomId,
					"m.room.member",
					sender,
				);
				if (entry) {
					memberEvents.push(pduToClientEvent(entry.event, entry.eventId));
				}
			}
			state = memberEvents;
		}

		return {
			status: 200,
			body: {
				start: fromStr ?? "0",
				end: result.end !== undefined ? String(result.end) : undefined,
				chunk,
				...(state !== undefined ? { state } : {}),
			},
		};
	};

export const getMembers =
	(storage: Storage): Handler =>
	async (req) => {
		const roomId = req.params.roomId as string;

		// MSC3706: while the room is partial-state we do not hold the full member
		// list, so block until the background resync completes (synapse blocks
		// /members during a partial join). Bounded so we never hang indefinitely.
		await storage.waitForPartialStateClear(roomId as RoomId, 20000);

		// SPEC-216: a departed (left/banned) user sees the member list as of their
		// leave point — members who joined after they left (e.g. charlie) must not
		// appear. We resolve this before the join check so the leave/ban case is
		// allowed rather than rejected with 403.
		const departed = await resolveDepartedRead(storage, roomId, req.userId);
		if (!departed.allowed) {
			await requireJoinedOrWorldReadable(storage, roomId, req.userId);
		}

		const membershipFilter = req.query.get("membership");
		const notMembershipFilter = req.query.get("not_membership");
		const atToken = departed.allowed
			? String(departed.leavePos)
			: req.query.get("at");

		let entries: { event: PDU; eventId: EventId }[];

		if (atToken !== null) {
			// `?at=<token>` returns room membership as it was at the given point in
			// a sync stream. The token is a stream position (the same integer used
			// for sync `prev_batch`/`next_batch` tokens). We replay every member
			// event in the room up to and including that stream position and keep
			// the latest membership event per user (by state_key).
			const at = parseInt(atToken, 10);
			if (Number.isNaN(at)) throw invalidParam("Invalid 'at' token");

			// `getEventsByRoomSince(roomId, 0, ...)` yields every event in the room
			// in ascending stream order, each annotated with its `streamPos`.
			const all = await storage.getEventsByRoomSince(roomId, 0, 1_000_000);
			const latestByStateKey = new Map<
				string,
				{ event: PDU; eventId: EventId }
			>();
			let maxDepthAtToken = 0;
			for (const e of all.events) {
				if (e.streamPos > at) break;
				if (e.event.depth > maxDepthAtToken) maxDepthAtToken = e.event.depth;
				if (e.event.type !== "m.room.member") continue;
				if (typeof e.event.state_key !== "string") continue;
				latestByStateKey.set(e.event.state_key, {
					event: e.event,
					eventId: e.eventId,
				});
			}
			// MSC3706: members filled in by a partial-state resync were stored with
			// LATER stream positions than this `at` token (which predates the
			// resync), so the stream-ordered replay above misses them. Add current
			// member events whose DAG depth is at or below the latest depth seen at
			// the token — they belong to the room's state at that point even though
			// we only learned of them during the resync. (Not for departed/SPEC-216
			// reads, which are intentionally clamped to the leave point.)
			if (!departed.allowed) {
				for (const m of await storage.getMemberEvents(roomId)) {
					if (typeof m.event.state_key !== "string") continue;
					if (latestByStateKey.has(m.event.state_key)) continue;
					if (m.event.depth <= maxDepthAtToken)
						latestByStateKey.set(m.event.state_key, m);
				}
			}
			entries = [...latestByStateKey.values()];
		} else {
			entries = await storage.getMemberEvents(roomId);
		}

		if (membershipFilter) {
			entries = entries.filter((e) => {
				const m = (e.event.content as Record<string, unknown>).membership;
				return m === membershipFilter;
			});
		}
		if (notMembershipFilter) {
			entries = entries.filter((e) => {
				const m = (e.event.content as Record<string, unknown>).membership;
				return m !== notMembershipFilter;
			});
		}

		const chunk = entries.map((e) => pduToClientEvent(e.event, e.eventId));
		return { status: 200, body: { chunk } };
	};

export const getEvent =
	(storage: Storage): Handler =>
	async (req) => {
		const roomId = req.params.roomId as string;
		const eventId = req.params.eventId as string;

		await requireCanReadEventOr404(storage, roomId, req.userId);
		await requireHistoryVisibleOr404(storage, roomId, eventId, req.userId);

		const entry = await storage.getEvent(eventId);
		if (!entry || entry.event.room_id !== roomId || entry.rejected)
			throw notFound("Event not found");

		const clientEvent = pduToClientEvent(entry.event, entry.eventId);
		// Strip transaction_id from unsigned if requester is not the sender
		if (
			clientEvent.unsigned &&
			"transaction_id" in clientEvent.unsigned &&
			clientEvent.sender !== req.userId
		) {
			const { transaction_id: _txnId, ...rest } =
				clientEvent.unsigned as Record<string, unknown>;
			clientEvent.unsigned = rest;
		}
		await bundleAggregations(storage, [clientEvent], req.userId ?? "");
		return { status: 200, body: clientEvent };
	};

export const postRedact =
	(
		storage: Storage,
		serverName: string,
		signingKey?: SigningKey,
		federationClient?: FederationClient,
	): Handler =>
	async (req) => {
		const roomId = req.params.roomId as string;
		const targetEventId = req.params.eventId as string;
		const txnId = req.params.txnId as string;
		const userId = req.userId as string;
		const deviceId = req.deviceId as string;

		// Room-scoped txn idempotency (see putSendEvent): fold the room into the
		// opaque txn-id string so the storage (user, device, txnId) key is
		// effectively keyed by (user, device, room, txnId).
		const scopedTxnId = `${roomId}${KEY_SEP}${txnId}`;

		const existing = await storage.getTxnEventId(userId, deviceId, scopedTxnId);
		if (existing) return { status: 200, body: { event_id: existing } };

		const room = await requireJoinedRoom(storage, roomId, userId);

		// The target event may not exist locally — e.g. it was authored on a remote
		// server and never federated to us (TestFederationRedactSendsWithoutEvent).
		// In that case we still create, store and fan out the redaction event; we
		// simply skip the local "apply the redaction to the target" step below.
		// Mirrors Synapse, which builds and sends the redaction regardless of
		// whether the redacted event is held locally.
		const targetEntry = await storage.getEvent(targetEventId);
		const targetIsLocal = !!targetEntry && targetEntry.event.room_id === roomId;

		const pl = getPowerLevels(room);
		const senderPl = getUserPowerLevel(userId, room);
		const redactPl = pl.redact ?? 50;
		// We can only enforce the "you may redact your own events at any PL" carve
		// out when the target is held locally (we need its sender). When the target
		// is absent, fall back to the room's redact power level alone.
		if (
			senderPl < redactPl &&
			(!targetIsLocal || targetEntry!.event.sender !== userId)
		) {
			throw forbidden("Insufficient power level to redact");
		}

		const body = (req.body ?? {}) as { reason?: string };
		const content: JsonObject = {};
		if (body.reason) content.reason = body.reason;

		const authEvents = selectAuthEvents(
			"m.room.redaction",
			undefined,
			room,
			userId,
		);
		// Sign the redaction (when a signing key is available) so it can be fanned
		// out to remote servers, which reject unsigned PDUs. Signing is additive and
		// does not change the event ID (computed over the redacted form).
		const { event, eventId } = buildEvent({
			roomId,
			sender: userId,
			type: "m.room.redaction",
			content,
			depth: room.depth,
			prevEvents: [...room.forward_extremities],
			authEvents,
			redacts: targetEventId,
			serverName,
			signingKey,
			roomVersion: room.room_version,
		});

		checkEventAuth(event, eventId, room);
		await storage.storeEvent(event, eventId);

		room.depth++;
		room.forward_extremities = [eventId];

		// Apply the redaction to the target only when we actually hold it locally.
		// Pass the room version so version-specific redaction rules apply (e.g.
		// MSC3389 preserving m.relates_to for org.matrix.msc3389.* rooms).
		if (targetIsLocal) {
			const redacted = redactEvent(targetEntry!.event, room.room_version);
			redacted.unsigned = {
				...redacted.unsigned,
				redacted_because: pduToClientEvent(event, eventId),
			};
			// Replace the target event content entirely (Object.assign would merge, not strip)
			targetEntry!.event.content = redacted.content;
			targetEntry!.event.unsigned = redacted.unsigned;
			// Persist the redaction so it survives across reads on non-memory backends
			await storage.updateEvent(targetEventId as EventId, targetEntry!.event);
		}

		// Propagate the redaction to remote servers in the room (best-effort).
		if (signingKey && federationClient) {
			await fanoutEvent(
				storage,
				serverName,
				signingKey,
				federationClient,
				roomId as RoomId,
				event,
				eventId,
			);
		}

		await storage.setTxnEventId(userId, deviceId, scopedTxnId, eventId);
		return { status: 200, body: { event_id: eventId } };
	};

export const getContext =
	(storage: Storage): Handler =>
	async (req) => {
		const roomId = req.params.roomId as string;
		const eventId = req.params.eventId as string;
		const userId = req.userId ?? "";

		await requireCanReadEventOr404(storage, roomId, req.userId);
		await requireHistoryVisibleOr404(storage, roomId, eventId, req.userId);

		const entry = await storage.getEvent(eventId);
		if (!entry || entry.event.room_id !== roomId || entry.rejected)
			throw notFound("Event not found");

		// Honour limit=0 (the client asks for the bare target + tokens, e.g.
		// jump-to-date) — do NOT force a minimum of 1, or the neighbour we should
		// return via /messages ends up inside the /context window instead.
		const limit = Math.min(
			Math.max(parseInt(req.query.get("limit") ?? "10", 10), 0),
			100,
		);
		const halfLimit = Math.floor(limit / 2);

		// Order by the DAG (depth, then stream), not raw arrival order, so that
		// `/context` of a backfilled event (whose ancestors were stored later, with
		// higher stream positions) places those ancestors before it. Fetch with
		// stream positions so we can emit Synapse-style `t<depth>-<stream>`
		// topological tokens, which stay valid as backfill adds earlier events.
		const rawTimeline = await storage.getEventsByRoomSince(
			roomId as RoomId,
			0,
			1_000_000,
		);
		const streamById = new Map<EventId, number>(
			rawTimeline.events.map((e) => [e.eventId, e.streamPos]),
		);
		const timeline = {
			events: buildDepthOrdered(
				rawTimeline.events.map((e) => ({ event: e.event, eventId: e.eventId })),
			),
		};
		const targetIdx = timeline.events.findIndex((e) => e.eventId === eventId);

		let eventsBefore: typeof timeline.events = [];
		let eventsAfter: typeof timeline.events = [];

		if (targetIdx >= 0) {
			eventsBefore = timeline.events
				.slice(Math.max(0, targetIdx - halfLimit), targetIdx)
				.reverse();
			eventsAfter = timeline.events.slice(
				targetIdx + 1,
				targetIdx + 1 + halfLimit,
			);
		}

		const stateEntries = await storage.getAllState(roomId);
		const state = stateEntries.map((e) => pduToClientEvent(e.event, e.eventId));

		const contextEvent = pduToClientEvent(entry.event, entry.eventId);
		const beforeEvents = eventsBefore.map((e) =>
			pduToClientEvent(e.event, e.eventId),
		);
		const afterEvents = eventsAfter.map((e) =>
			pduToClientEvent(e.event, e.eventId),
		);
		await bundleAggregations(
			storage,
			[contextEvent, ...beforeEvents, ...afterEvents],
			userId,
		);

		// Topological tokens for the edges of the context window. `start` is the
		// earliest shown event (paginate /messages dir=b from it for strictly
		// earlier events); `end` the latest shown event (dir=f for later). With no
		// neighbours (limit=0) both collapse to the target itself, so dir=b from
		// `start` yields the events immediately preceding the target.
		const startEvt =
			eventsBefore.length > 0
				? (eventsBefore[eventsBefore.length - 1] as {
						event: PDU;
						eventId: EventId;
					})
				: entry;
		const endEvt =
			eventsAfter.length > 0
				? (eventsAfter[eventsAfter.length - 1] as {
						event: PDU;
						eventId: EventId;
					})
				: entry;

		return {
			status: 200,
			body: {
				event: contextEvent,
				events_before: beforeEvents,
				events_after: afterEvents,
				state,
				// `start` = the earliest shown event's position; dir=b `< start` →
				// strictly earlier events (no overlap with the window). `end` = just
				// AFTER the latest shown event (stream+1); dir=b `< end` → the window
				// itself plus earlier, which is what the test uses to see both A and B.
				start: topoToken(
					startEvt.event.depth,
					streamById.get(startEvt.eventId) ?? 0,
				),
				end: topoToken(
					endEvt.event.depth,
					(streamById.get(endEvt.eventId) ?? 0) + 1,
				),
			},
		};
	};

export const getJoinedMembers =
	(storage: Storage): Handler =>
	async (req) => {
		const roomId = req.params.roomId as string;
		// MSC3706: block until any partial-state resync completes (synapse blocks
		// /joined_members during a partial join).
		await storage.waitForPartialStateClear(roomId as RoomId, 20000);
		await requireJoinedRoom(storage, roomId, req.userId as string);

		const entries = await storage.getMemberEvents(roomId);
		const joined: Record<
			string,
			{ display_name: string | null; avatar_url: string | null }
		> = {};

		for (const entry of entries) {
			const content = entry.event.content as Record<string, unknown>;
			if (content.membership !== "join") continue;
			const userId = entry.event.state_key as string;
			const profile = await storage.getProfile(userId as UserId);
			joined[userId] = {
				display_name: profile?.displayname ?? null,
				avatar_url: profile?.avatar_url ?? null,
			};
		}

		return { status: 200, body: { joined } };
	};

/**
 * Find the closest local event to `ts` in `dir` direction, mirroring Synapse's
 * `get_event_id_for_timestamp` SQL exactly (events_worker.py):
 *
 *   ORDER BY origin_server_ts {order}, depth {order}, stream_ordering {order}
 *   WHERE origin_server_ts {<=|>=} ts   LIMIT 1
 *
 * The primary key is `origin_server_ts` (NOT depth) — sorting by depth first
 * returns the wrong neighbour when timestamps differ. We tie-break on `depth`
 * then `stream_ordering` (received order), which decides same-timestamp runs in
 * DAG order: looking backwards returns the *last* such event, forwards the
 * *first*.
 *
 * - `dir === "f"`: smallest `origin_server_ts >= ts`, then smallest depth, then
 *   smallest stream position.
 * - `dir === "b"`: largest `origin_server_ts <= ts`, then largest depth, then
 *   largest stream position.
 *
 * `events` must carry each event's `streamPos` (stream_ordering).
 */
const findClosestLocalEvent = (
	events: { event: PDU; eventId: EventId; streamPos: number }[],
	ts: number,
	dir: "f" | "b",
): { eventId: EventId; event: PDU } | undefined => {
	let best: { eventId: EventId; event: PDU; streamPos: number } | undefined;

	for (const cand of events) {
		const candTs = cand.event.origin_server_ts;
		if (dir === "f") {
			if (candTs < ts) continue;
		} else {
			if (candTs > ts) continue;
		}

		if (!best) {
			best = cand;
			continue;
		}

		// Apply the ORDER BY: origin_server_ts, then depth, then stream_ordering,
		// in ascending order for `f` and descending for `b`; keep the first row.
		const bTs = best.event.origin_server_ts;
		let better: boolean;
		if (dir === "f") {
			better =
				candTs < bTs ||
				(candTs === bTs &&
					(cand.event.depth < best.event.depth ||
						(cand.event.depth === best.event.depth &&
							cand.streamPos < best.streamPos)));
		} else {
			better =
				candTs > bTs ||
				(candTs === bTs &&
					(cand.event.depth > best.event.depth ||
						(cand.event.depth === best.event.depth &&
							cand.streamPos > best.streamPos)));
		}
		if (better) best = cand;
	}

	return best ? { eventId: best.eventId, event: best.event } : undefined;
};

/**
 * Mirror of Synapse's `is_event_next_to_backward_gap` (events_worker.py):
 * checked when looking *forwards*. The local event is next to a backward gap if
 * any of its `prev_events` is missing locally — i.e. there is unknown history
 * older than it that could hold a closer event. (Synapse keys this off
 * `event_backward_extremities`; the unheld prev_events are their analogue.)
 */
const isEventNextToBackwardGap = (event: PDU, held: Set<EventId>): boolean =>
	event.prev_events.some((p) => !held.has(p));

/**
 * Mirror of Synapse's `is_event_next_to_forward_gap` (events_worker.py):
 * checked when looking *backwards*. A forward extremity is never a gap (it is
 * the latest event in the room). Otherwise the event is next to a forward gap
 * if no held event references it in their `prev_events` — there is unknown
 * history newer than it that could hold a closer event.
 */
const isEventNextToForwardGap = (
	eventId: EventId,
	forwardExtremities: EventId[],
	referencedPrevs: Set<EventId>,
): boolean => {
	if (forwardExtremities.includes(eventId)) return false;
	return !referencedPrevs.has(eventId);
};

/**
 * Ask other resident servers for the closest event to `ts`, mirroring
 * Synapse's `get_event_for_timestamp` federation fallback. Returns the remote
 * server's answer (event id + claimed origin_server_ts) from the first server
 * that responds, or `undefined` if none do. The event itself is NOT fetched
 * here — the caller backfills it so `/context` and `/messages` can work.
 */
const remoteTimestampToEvent = async (
	storage: Storage,
	serverName: string,
	federationClient: FederationClient,
	roomId: RoomId,
	ts: number,
	dir: "f" | "b",
): Promise<{ eventId: EventId; originServerTs: number } | undefined> => {
	const servers = (await storage.getServersInRoom(roomId)).filter(
		(s) => s !== serverName,
	);
	const path = `/_matrix/federation/v1/timestamp_to_event/${encodeURIComponent(
		roomId,
	)}?ts=${ts}&dir=${dir}`;

	for (const server of servers) {
		let res: { status: number; body: unknown };
		try {
			res = await federationClient.request(server, "GET", path);
		} catch {
			continue;
		}
		if (res.status !== 200 || typeof res.body !== "object" || res.body === null)
			continue;
		const body = res.body as { event_id?: unknown; origin_server_ts?: unknown };
		if (
			typeof body.event_id !== "string" ||
			typeof body.origin_server_ts !== "number"
		)
			continue;
		return {
			eventId: body.event_id as EventId,
			originServerTs: body.origin_server_ts,
		};
	}
	return undefined;
};

/**
 * Backfill a specific remote event (and its ancestry) into local storage by
 * seeding the federation `/backfill` walk from that event id. After this
 * returns successfully the event is persisted locally with enough surrounding
 * history that `/context` and backward `/messages` pagination work. Returns
 * the stored event, or `undefined` if it could not be fetched/verified.
 */
const backfillRemoteEventById = async (
	storage: Storage,
	serverName: string,
	federationClient: FederationClient,
	roomId: RoomId,
	eventId: EventId,
	roomVersion: string | undefined,
): Promise<PDU | undefined> => {
	const existing = await storage.getEvent(eventId);
	if (existing && existing.event.room_id === roomId) return existing.event;

	const servers = (await storage.getServersInRoom(roomId)).filter(
		(s) => s !== serverName,
	);
	const path = `/_matrix/federation/v1/backfill/${encodeURIComponent(
		roomId,
	)}?v=${encodeURIComponent(eventId)}&limit=100`;

	for (const server of servers) {
		let res: { status: number; body: unknown };
		try {
			res = await federationClient.request(server, "GET", path);
		} catch {
			continue;
		}
		if (res.status !== 200 || typeof res.body !== "object" || res.body === null)
			continue;
		const pdus = (res.body as { pdus?: unknown }).pdus;
		if (!Array.isArray(pdus)) continue;

		for (const raw of pdus) {
			if (!raw || typeof raw !== "object") continue;
			const event = raw as PDU;
			if (event.room_id !== roomId) continue;

			let id: EventId;
			try {
				const expectedHash = computeContentHash(event);
				if (event.hashes?.sha256 !== expectedHash) continue;
				id = computeEventId(event, roomVersion);
			} catch {
				continue;
			}
			if (await storage.getEvent(id)) continue;
			try {
				await verifyOriginSignature(
					event,
					server,
					storage,
					federationClient,
					roomVersion,
				);
			} catch {
				continue;
			}
			// Persist + index defensively: a single malformed PDU must not abort
			// the whole backfill (or, worse, escape as a 500 from the handler).
			try {
				await storage.storeEvent(event, id);
				await indexRelation(storage, event, id);
			} catch {}
		}

		const stored = await storage.getEvent(eventId);
		if (stored && stored.event.room_id === roomId) return stored.event;
	}

	return undefined;
};

export const getTimestampToEvent =
	(
		storage: Storage,
		serverName?: string,
		_signingKey?: SigningKey,
		federationClient?: FederationClient,
	): Handler =>
	async (req) => {
		const roomId = req.params.roomId as string;
		await requireJoinedRoom(storage, roomId, req.userId as string);

		const tsStr = req.query.get("ts");
		if (!tsStr) throw missingParam("Missing 'ts'");
		const ts = parseInt(tsStr, 10);
		if (Number.isNaN(ts)) throw badJson("'ts' must be a number");

		const dir = req.query.get("dir");
		if (dir !== "f" && dir !== "b") throw badJson("'dir' must be 'f' or 'b'");

		const room = await storage.getRoom(roomId);
		const roomVersion = room?.room_version;

		// Find the closest local event in `dir`, using Synapse's exact ordering
		// (origin_server_ts, depth, stream_ordering). `getEventsByRoomSince(0)`
		// yields every held event with its `streamPos` (stream_ordering).
		const all = await storage.getEventsByRoomSince(
			roomId as RoomId,
			0,
			1_000_000,
		);
		const local = findClosestLocalEvent(all.events, ts, dir);

		// Gap detection (Synapse `get_event_for_timestamp`): a local event that
		// sits next to a gap in our history might be hiding a closer event behind
		// missing prev/forward edges, so we must consult federation even though we
		// found something locally. Looking *forwards* we check for a backward gap;
		// looking *backwards* a forward gap.
		const held = new Set<EventId>(all.events.map((e) => e.eventId));
		const referencedPrevs = new Set<EventId>();
		for (const e of all.events) {
			for (const p of e.event.prev_events) referencedPrevs.add(p);
		}
		const forwardExtremities = room?.forward_extremities ?? [];

		let nextToGap = false;
		if (local) {
			nextToGap =
				dir === "f"
					? isEventNextToBackwardGap(local.event, held)
					: isEventNextToForwardGap(
							local.eventId,
							forwardExtremities,
							referencedPrevs,
						);
		}

		// Federation fallback (mirrors Synapse's get_event_for_timestamp): when we
		// have no suitable local event, or the local event is next to a gap, ask
		// the room's other resident servers, then backfill the event they return
		// so we can serve it (and the surrounding history for /context +
		// /messages). The whole remote path is best-effort: ANY failure (network,
		// verification, persistence) falls through to the local answer (or 404),
		// never a 500.
		if ((!local || nextToGap) && serverName && federationClient) {
			try {
				const remote = await remoteTimestampToEvent(
					storage,
					serverName,
					federationClient,
					roomId as RoomId,
					ts,
					dir,
				);
				if (remote) {
					const fetched = await backfillRemoteEventById(
						storage,
						serverName,
						federationClient,
						roomId as RoomId,
						remote.eventId,
						roomVersion,
					);
					// Only return the remote event when it's actually closer to `ts`
					// than the local one (Synapse's `abs(...) < abs(...)` check), or
					// when we had no local event at all.
					if (fetched) {
						const remoteTs = fetched.origin_server_ts;
						const closer =
							!local ||
							Math.abs(remoteTs - ts) <
								Math.abs(local.event.origin_server_ts - ts);
						if (closer) {
							return {
								status: 200,
								body: {
									event_id: remote.eventId,
									origin_server_ts: remoteTs,
								},
							};
						}
					}
				}
			} catch {
				// Fall through to the local answer (or 404) below.
			}
		}

		if (!local) throw notFound("No event found for the given timestamp");

		return {
			status: 200,
			body: {
				event_id: local.eventId,
				origin_server_ts: local.event.origin_server_ts,
			},
		};
	};
