import type { PresenceState } from "../types/ephemeral.ts";
import type { PDU, StrippedStateEvent } from "../types/events.ts";
import type { RoomId, RoomState, Timestamp, UserId } from "../types/index.ts";
import type { JsonObject } from "../types/json.ts";

export const INVITE_STATE_TYPES = [
	"m.room.create",
	"m.room.join_rules",
	"m.room.canonical_alias",
	"m.room.avatar",
	"m.room.name",
	"m.room.encryption",
	"m.room.member",
] as const;

export const eventToStrippedState = (event: {
	content: JsonObject;
	sender: string;
	state_key?: string;
	type: string;
}): StrippedStateEvent => {
	// MSC4311: client-facing stripped state (invite_state / knock_state in /sync)
	// uses the minimal stripped format for EVERY event, including m.room.create —
	// no full-PDU fields such as origin_server_ts. (The federation
	// invite_room_state / knock_room_state carry FULL events instead; see
	// fullInviteState.) The room version / creators remain readable from the
	// create event's content.
	return {
		content: event.content,
		sender: event.sender,
		state_key: event.state_key ?? "",
		type: event.type,
	};
};

/**
 * MSC4311: the state events shared with an invitee/knocker over FEDERATION
 * (invite_room_state / knock_room_state) are FULL PDUs — not the minimal
 * stripped form — so the receiving server sees origin_server_ts and can verify
 * them. Selects the same state types as getStrippedState but returns the
 * unmodified events. m.room.create is always included.
 */
export const fullInviteState = (room: RoomState): PDU[] =>
	[...room.state_events.entries()]
		.filter(([key]) =>
			INVITE_STATE_TYPES.includes(
				key.split("\x1f")[0] as (typeof INVITE_STATE_TYPES)[number],
			),
		)
		.map(([, event]) => event);

export interface EphemeralStore {
	/** Monotonic stream position; every persisted change advances it. */
	streamCounter: number;
	/** Monotonic filter id counter. */
	filterCounter: number;
	/** Resolve callbacks for in-flight long-poll /sync requests. */
	readonly eventWaiters: Set<() => void>;
	/** Hot cache of room state, keyed by room id. */
	readonly roomCache: Map<RoomId, RoomState>;
	wakeWaiters(): void;
	waitForEvents(since: number, timeoutMs: number): Promise<void>;
	setTyping(
		roomId: RoomId,
		userId: UserId,
		typing: boolean,
		timeout?: number,
	): Promise<void>;
	getTypingUsers(roomId: RoomId): Promise<UserId[]>;
	getTypingChangedAt(roomId: RoomId): Promise<number>;
	setPresence(
		userId: UserId,
		presence: PresenceState,
		statusMsg?: string,
	): Promise<void>;
	getPresenceChangedAt(userId: UserId): Promise<number>;
	getPresence(userId: UserId): Promise<
		| {
				presence: PresenceState;
				status_msg?: string;
				last_active_ts?: Timestamp;
		  }
		| undefined
	>;
	/** MSC4429: record a profile-field change (value `null` means cleared). */
	recordProfileUpdate(
		userId: UserId,
		field: string,
		value: unknown,
	): Promise<void>;
	/** MSC4429: profile-field changes in the stream window (since, until]. */
	getProfileUpdatesSince(
		since: number,
		until: number,
	): Promise<
		{ userId: string; field: string; value: unknown; streamPos: number }[]
	>;
}

/**
 * In-memory ephemeral state shared by every storage backend: the monotonic
 * stream/filter counters, the long-poll waiter set, the room-state cache, and
 * transient typing/presence. Backends compose this and touch the counters,
 * roomCache and wakeWaiters directly; typing/presence live entirely behind its
 * methods. None of this is persisted — it is rebuilt on startup.
 */
export const createEphemeralStore = (): EphemeralStore => {
	let streamCounter = 0;
	let filterCounter = 0;
	const eventWaiters = new Set<() => void>();
	const roomCache = new Map<RoomId, RoomState>();
	const typingTimers = new Map<
		RoomId,
		Map<UserId, ReturnType<typeof setTimeout>>
	>();
	// Stream position at which each room's typing set last changed — lets
	// incremental /sync surface a room when typing changed (incl. to empty)
	// since the `since` token, without re-reporting unchanged rooms.
	const typingChangedAt = new Map<RoomId, number>();
	const presenceMap = new Map<
		UserId,
		{ presence: PresenceState; status_msg?: string; last_active_ts?: Timestamp }
	>();
	// Stream position at which each user's presence last changed.
	const presenceChangedAt = new Map<UserId, number>();

	// MSC4429: append-only log of profile-field changes, each tagged with a
	// stream position so incremental /sync can select changes in (since, until].
	const profileUpdates: {
		userId: string;
		field: string;
		value: unknown;
		streamPos: number;
	}[] = [];

	const wakeWaiters = (): void => {
		for (const waiter of eventWaiters) waiter();
	};

	const waitForEvents = (since: number, timeoutMs: number): Promise<void> => {
		if (streamCounter > since) return Promise.resolve();
		if (timeoutMs <= 0) return Promise.resolve();

		return new Promise<void>((resolve) => {
			const timer = setTimeout(() => {
				eventWaiters.delete(wake);
				resolve();
			}, timeoutMs);

			const wake = () => {
				clearTimeout(timer);
				eventWaiters.delete(wake);
				resolve();
			};

			eventWaiters.add(wake);
		});
	};

	const setTyping = async (
		roomId: RoomId,
		userId: UserId,
		typing: boolean,
		timeout?: number,
	): Promise<void> => {
		let roomTyping = typingTimers.get(roomId);
		if (!roomTyping) {
			roomTyping = new Map();
			typingTimers.set(roomId, roomTyping);
		}

		const wasTyping = roomTyping.has(userId);
		const existing = roomTyping.get(userId);
		if (existing) {
			clearTimeout(existing);
			roomTyping.delete(userId);
		}

		if (typing) {
			const ms = Math.min(timeout ?? 30000, 120000);
			const timer = setTimeout(() => {
				roomTyping?.delete(userId);
				typingChangedAt.set(roomId, ++streamCounter);
				wakeWaiters();
			}, ms);
			roomTyping.set(userId, timer);
		}

		// The typing set changed iff the user's typing membership flipped.
		if (wasTyping !== typing) {
			typingChangedAt.set(roomId, ++streamCounter);
		}
		wakeWaiters();
	};

	const getTypingUsers = async (roomId: RoomId): Promise<UserId[]> => {
		const roomTyping = typingTimers.get(roomId);
		return roomTyping ? [...roomTyping.keys()] : [];
	};

	const getTypingChangedAt = async (roomId: RoomId): Promise<number> =>
		typingChangedAt.get(roomId) ?? 0;

	const setPresence = async (
		userId: UserId,
		presence: PresenceState,
		statusMsg?: string,
	): Promise<void> => {
		presenceMap.set(userId, {
			presence,
			status_msg: statusMsg,
			last_active_ts: Date.now(),
		});
		// Advance the stream so long-polling /sync wakes and surfaces the change,
		// and record the position so incremental sync knows which users changed.
		presenceChangedAt.set(userId, ++streamCounter);
		wakeWaiters();
	};

	const getPresenceChangedAt = async (userId: UserId): Promise<number> =>
		presenceChangedAt.get(userId) ?? 0;

	const getPresence = async (userId: UserId) => presenceMap.get(userId);

	const recordProfileUpdate = async (
		userId: UserId,
		field: string,
		value: unknown,
	): Promise<void> => {
		profileUpdates.push({ userId, field, value, streamPos: ++streamCounter });
		wakeWaiters();
	};

	const getProfileUpdatesSince = async (since: number, until: number) =>
		profileUpdates.filter((u) => u.streamPos > since && u.streamPos <= until);

	return {
		get streamCounter() {
			return streamCounter;
		},
		set streamCounter(v: number) {
			streamCounter = v;
		},
		get filterCounter() {
			return filterCounter;
		},
		set filterCounter(v: number) {
			filterCounter = v;
		},
		eventWaiters,
		roomCache,
		wakeWaiters,
		waitForEvents,
		setTyping,
		getTypingUsers,
		getTypingChangedAt,
		setPresence,
		getPresenceChangedAt,
		getPresence,
		recordProfileUpdate,
		getProfileUpdatesSince,
	};
};
