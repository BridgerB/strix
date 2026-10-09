import type {
	CrossSigningKey,
	DeviceKeys,
	KeyBackupData,
	OneTimeKey,
} from "../types/e2ee.ts";
import type { PresenceState } from "../types/ephemeral.ts";
import type {
	EDU,
	PDU,
	StrippedStateEvent,
	ToDeviceEvent,
} from "../types/events.ts";
import type { ServerKeys } from "../types/federation.ts";
import type {
	AccessToken,
	DeviceId,
	DeviceSession,
	EventId,
	KeyId,
	RefreshToken,
	RoomAlias,
	RoomId,
	RoomState,
	ServerName,
	StoredMedia,
	Timestamp,
	UserAccount,
	UserId,
} from "../types/index.ts";
import type { JsonObject } from "../types/json.ts";
import type { Pusher } from "../types/push.ts";
import type { RoomVersion } from "../types/room-versions.ts";
import type { Device, UserProfile } from "../types/user.ts";

export interface StoredSession extends DeviceSession {
	access_token: AccessToken;
	refresh_token?: RefreshToken;
	expires_at?: Timestamp;
}

export interface Storage {
	// Users
	createUser(account: UserAccount): Promise<void>;
	getUserByLocalpart(localpart: string): Promise<UserAccount | undefined>;
	getUserById(userId: UserId): Promise<UserAccount | undefined>;

	// Sessions / Devices
	createSession(session: StoredSession): Promise<void>;
	getSessionByAccessToken(
		token: AccessToken,
	): Promise<StoredSession | undefined>;
	getSessionByRefreshToken(
		token: RefreshToken,
	): Promise<StoredSession | undefined>;
	getSessionsByUser(userId: UserId): Promise<StoredSession[]>;
	deleteSession(token: AccessToken): Promise<void>;
	deleteAllSessions(userId: UserId): Promise<void>;
	rotateToken(
		oldAccessToken: AccessToken,
		newAccessToken: AccessToken,
		newRefreshToken?: RefreshToken,
		expiresAt?: Timestamp,
	): Promise<StoredSession | undefined>;
	touchSession(
		token: AccessToken,
		ip: string,
		userAgent: string,
	): Promise<void>;

	// UIAA Sessions
	createUIAASession(sessionId: string): Promise<void>;
	getUIAASession(
		sessionId: string,
	): Promise<{ completed: string[] } | undefined>;
	addUIAACompleted(sessionId: string, stageType: string): Promise<void>;
	deleteUIAASession(sessionId: string): Promise<void>;

	// Rooms
	createRoom(state: RoomState): Promise<void>;
	getRoom(roomId: RoomId): Promise<RoomState | undefined>;
	getRoomsForUser(userId: UserId): Promise<RoomId[]>;

	// Events
	storeEvent(event: PDU, eventId: EventId): Promise<void>;
	/**
	 * Overwrite the stored JSON of an existing event in place, without changing
	 * its stream position. Used to persist redactions and other in-place edits.
	 */
	updateEvent(eventId: EventId, event: PDU): Promise<void>;
	getEvent(eventId: EventId): Promise<
		| {
				event: PDU;
				eventId: EventId;
				/** True if the event was rejected (kept for the DAG, hidden from
				 * state/sync, served as 404 by /event). */
				rejected?: boolean;
		  }
		| undefined
	>;
	getEventsByRoom(
		roomId: RoomId,
		limit: number,
		from?: number,
		direction?: "b" | "f",
	): Promise<{ events: { event: PDU; eventId: EventId }[]; end?: number }>;
	getStreamPosition(): Promise<number>;

	// State
	getStateEvent(
		roomId: RoomId,
		eventType: string,
		stateKey: string,
	): Promise<{ event: PDU; eventId: EventId } | undefined>;
	getAllState(roomId: RoomId): Promise<{ event: PDU; eventId: EventId }[]>;
	setStateEvent(roomId: RoomId, event: PDU, eventId: EventId): Promise<void>;

	// Members
	getMemberEvents(roomId: RoomId): Promise<{ event: PDU; eventId: EventId }[]>;

	// Transaction idempotency
	getTxnEventId(
		userId: UserId,
		deviceId: DeviceId,
		txnId: string,
	): Promise<EventId | undefined>;
	setTxnEventId(
		userId: UserId,
		deviceId: DeviceId,
		txnId: string,
		eventId: EventId,
	): Promise<void>;

	// Sync
	getRoomsForUserWithMembership(
		userId: UserId,
	): Promise<{ roomId: RoomId; membership: string }[]>;
	getEventsByRoomSince(
		roomId: RoomId,
		since: number,
		limit: number,
	): Promise<{
		events: { event: PDU; eventId: EventId; streamPos: number }[];
		limited: boolean;
	}>;
	getStrippedState(roomId: RoomId): Promise<StrippedStateEvent[]>;
	waitForEvents(since: number, timeoutMs: number): Promise<void>;

	// Profile
	getProfile(userId: UserId): Promise<UserProfile | undefined>;
	setDisplayName(userId: UserId, displayname: string | null): Promise<void>;
	setAvatarUrl(userId: UserId, avatarUrl: string | null): Promise<void>;

	// Devices
	getDevice(userId: UserId, deviceId: DeviceId): Promise<Device | undefined>;
	getAllDevices(userId: UserId): Promise<Device[]>;
	updateDeviceDisplayName(
		userId: UserId,
		deviceId: DeviceId,
		displayName: string,
	): Promise<void>;
	deleteDeviceSession(userId: UserId, deviceId: DeviceId): Promise<void>;

	// Account
	updatePassword(userId: UserId, newPasswordHash: string): Promise<void>;
	deactivateUser(userId: UserId): Promise<void>;

	// Aliases
	createRoomAlias(
		roomAlias: RoomAlias,
		roomId: RoomId,
		servers: ServerName[],
		creator: UserId,
	): Promise<void>;
	deleteRoomAlias(roomAlias: RoomAlias): Promise<boolean>;
	getRoomByAlias(
		roomAlias: RoomAlias,
	): Promise<{ room_id: RoomId; servers: ServerName[] } | undefined>;
	getAliasesForRoom(roomId: RoomId): Promise<RoomAlias[]>;
	getAliasCreator(roomAlias: RoomAlias): Promise<UserId | undefined>;

	// Directory
	setRoomVisibility(
		roomId: RoomId,
		visibility: "public" | "private",
	): Promise<void>;
	getRoomVisibility(roomId: RoomId): Promise<"public" | "private">;
	getPublicRoomIds(): Promise<RoomId[]>;

	// Account data
	getGlobalAccountData(
		userId: UserId,
		type: string,
	): Promise<JsonObject | undefined>;
	setGlobalAccountData(
		userId: UserId,
		type: string,
		content: JsonObject,
	): Promise<void>;
	/** Remove a global account-data entry (MSC3391). No-op if absent. */
	deleteGlobalAccountData(userId: UserId, type: string): Promise<void>;
	getAllGlobalAccountData(
		userId: UserId,
	): Promise<{ type: string; content: JsonObject }[]>;
	/**
	 * Global account-data entries changed since the given stream position
	 * (stream_pos > since), INCLUDING MSC3391 deletion tombstones (content `{}`).
	 * Used by incremental sync.
	 */
	getGlobalAccountDataSince(
		userId: UserId,
		since: number,
	): Promise<{ type: string; content: JsonObject }[]>;
	getRoomAccountData(
		userId: UserId,
		roomId: RoomId,
		type: string,
	): Promise<JsonObject | undefined>;
	setRoomAccountData(
		userId: UserId,
		roomId: RoomId,
		type: string,
		content: JsonObject,
	): Promise<void>;
	/** Remove a room account-data entry (MSC3391). No-op if absent. */
	deleteRoomAccountData(
		userId: UserId,
		roomId: RoomId,
		type: string,
	): Promise<void>;
	getAllRoomAccountData(
		userId: UserId,
		roomId: RoomId,
	): Promise<{ type: string; content: JsonObject }[]>;
	/**
	 * Room account-data entries changed since the given stream position
	 * (stream_pos > since), INCLUDING MSC3391 deletion tombstones (content `{}`).
	 * Used by incremental sync.
	 */
	getRoomAccountDataSince(
		userId: UserId,
		since: number,
	): Promise<{ roomId: RoomId; type: string; content: JsonObject }[]>;

	// Typing
	setTyping(
		roomId: RoomId,
		userId: UserId,
		typing: boolean,
		timeout?: number,
	): Promise<void>;
	getTypingUsers(roomId: RoomId): Promise<UserId[]>;
	/** Stream position at which the room's typing set last changed (0 if never). */
	getTypingChangedAt(roomId: RoomId): Promise<number>;

	// Receipts
	setReceipt(
		roomId: RoomId,
		userId: UserId,
		eventId: EventId,
		receiptType: string,
		ts: Timestamp,
		threadId?: string,
	): Promise<void>;
	getReceipts(roomId: RoomId): Promise<
		{
			eventId: EventId;
			receiptType: string;
			userId: UserId;
			ts: Timestamp;
			threadId?: string;
		}[]
	>;

	// Presence
	setPresence(
		userId: UserId,
		presence: PresenceState,
		statusMsg?: string,
	): Promise<void>;
	getPresence(userId: UserId): Promise<
		| {
				presence: PresenceState;
				status_msg?: string;
				last_active_ts?: Timestamp;
		  }
		| undefined
	>;
	/** Stream position at which `userId`'s presence last changed (0 if never). */
	getPresenceChangedAt(userId: UserId): Promise<number>;

	// Profile updates (MSC4429)
	/** Record a profile-field change for `userId` (value `null` = cleared). */
	recordProfileUpdate(
		userId: UserId,
		field: string,
		value: unknown,
	): Promise<void>;
	/** Profile-field changes in the stream window (since, until]. */
	getProfileUpdatesSince(
		since: number,
		until: number,
	): Promise<
		{ userId: string; field: string; value: unknown; streamPos: number }[]
	>;

	// Media
	storeMedia(media: StoredMedia, data: Buffer): Promise<void>;
	getMedia(
		serverName: ServerName,
		mediaId: string,
	): Promise<{ metadata: StoredMedia; data: Buffer } | undefined>;
	reserveMedia(media: StoredMedia): Promise<void>;
	updateMediaContent(
		serverName: ServerName,
		mediaId: string,
		contentType: string,
		fileName: string | undefined,
		data: Buffer,
	): Promise<boolean>;

	// Filters
	createFilter(userId: UserId, filter: JsonObject): Promise<string>;
	getFilter(userId: UserId, filterId: string): Promise<JsonObject | undefined>;

	// E2EE - Device keys
	setDeviceKeys(
		userId: UserId,
		deviceId: DeviceId,
		keys: DeviceKeys,
	): Promise<void>;
	getDeviceKeys(
		userId: UserId,
		deviceId: DeviceId,
	): Promise<DeviceKeys | undefined>;
	getAllDeviceKeys(userId: UserId): Promise<Record<DeviceId, DeviceKeys>>;
	/**
	 * Remove all cached device keys for a user. Used to evict a remote user's
	 * cached keys when we stop tracking them (they left the last room we shared)
	 * or when they re-join after a gap, so the next /keys/query re-fetches fresh.
	 */
	deleteDeviceKeys(userId: UserId): Promise<void>;

	// E2EE - Device key change stream
	recordDeviceKeyChange(userId: UserId): Promise<void>;
	getChangedDeviceUsers(since: number, until: number): Promise<UserId[]>;

	// E2EE - One-time keys
	addOneTimeKeys(
		userId: UserId,
		deviceId: DeviceId,
		keys: Record<KeyId, string | OneTimeKey>,
	): Promise<void>;
	claimOneTimeKey(
		userId: UserId,
		deviceId: DeviceId,
		algorithm: string,
	): Promise<{ keyId: KeyId; key: string | OneTimeKey } | undefined>;
	getOneTimeKeyCounts(
		userId: UserId,
		deviceId: DeviceId,
	): Promise<Record<string, number>>;

	// E2EE - Fallback keys
	setFallbackKeys(
		userId: UserId,
		deviceId: DeviceId,
		keys: Record<KeyId, string | OneTimeKey>,
	): Promise<void>;
	getFallbackKeyTypes(userId: UserId, deviceId: DeviceId): Promise<string[]>;

	// E2EE - Cross-signing keys
	setCrossSigningKeys(
		userId: UserId,
		keys: {
			master_key?: CrossSigningKey;
			self_signing_key?: CrossSigningKey;
			user_signing_key?: CrossSigningKey;
		},
	): Promise<void>;
	getCrossSigningKeys(userId: UserId): Promise<{
		master_key?: CrossSigningKey;
		self_signing_key?: CrossSigningKey;
		user_signing_key?: CrossSigningKey;
	}>;
	storeCrossSigningSignatures(
		userId: UserId,
		signatures: Record<string, Record<string, JsonObject>>,
	): Promise<
		Record<string, Record<string, { errcode: string; error: string }>>
	>;

	// E2EE - Key backup
	createKeyBackupVersion(
		userId: UserId,
		algorithm: string,
		authData: JsonObject,
	): Promise<string>;
	getKeyBackupVersion(
		userId: UserId,
		version?: string,
	): Promise<
		| {
				version: string;
				algorithm: string;
				auth_data: JsonObject;
				count: number;
				etag: string;
		  }
		| undefined
	>;
	updateKeyBackupVersion(
		userId: UserId,
		version: string,
		authData: JsonObject,
	): Promise<boolean>;
	deleteKeyBackupVersion(userId: UserId, version: string): Promise<boolean>;
	putKeyBackupKeys(
		userId: UserId,
		version: string,
		roomId: RoomId | undefined,
		sessionId: string | undefined,
		keys:
			| KeyBackupData
			| { sessions: Record<string, KeyBackupData> }
			| {
					rooms: Record<RoomId, { sessions: Record<string, KeyBackupData> }>;
			  },
	): Promise<{ count: number; etag: string } | undefined>;
	getKeyBackupKeys(
		userId: UserId,
		version: string,
		roomId?: RoomId,
		sessionId?: string,
	): Promise<
		| KeyBackupData
		| { sessions: Record<string, KeyBackupData> }
		| {
				rooms: Record<RoomId, { sessions: Record<string, KeyBackupData> }>;
		  }
		| undefined
	>;
	deleteKeyBackupKeys(
		userId: UserId,
		version: string,
		roomId?: RoomId,
		sessionId?: string,
	): Promise<{ count: number; etag: string } | undefined>;

	// To-device messages
	sendToDevice(
		userId: UserId,
		deviceId: DeviceId,
		event: ToDeviceEvent,
	): Promise<void>;
	getToDeviceMessages(
		userId: UserId,
		deviceId: DeviceId,
	): Promise<ToDeviceEvent[]>;
	clearToDeviceMessages(userId: UserId, deviceId: DeviceId): Promise<void>;

	// Pushers
	getPushers(userId: UserId): Promise<Pusher[]>;
	setPusher(userId: UserId, pusher: Pusher): Promise<void>;
	deletePusher(userId: UserId, appId: string, pushkey: string): Promise<void>;
	deletePusherByKey(appId: string, pushkey: string): Promise<void>;

	// Relations
	storeRelation(
		eventId: EventId,
		roomId: RoomId,
		relType: string,
		targetEventId: EventId,
		key?: string,
	): Promise<void>;
	getRelatedEvents(
		roomId: RoomId,
		eventId: EventId,
		relType?: string,
		eventType?: string,
		limit?: number,
		from?: string,
		direction?: "b" | "f",
	): Promise<{
		events: { event: PDU; eventId: EventId }[];
		nextBatch?: string;
	}>;
	getAnnotationCounts(
		eventId: EventId,
	): Promise<{ type: string; key: string; count: number }[]>;
	getLatestEdit(
		eventId: EventId,
		sender: UserId,
	): Promise<{ event: PDU; eventId: EventId } | undefined>;
	getThreadSummary(
		eventId: EventId,
		userId: UserId,
	): Promise<
		| {
				latestEvent: { event: PDU; eventId: EventId };
				count: number;
				currentUserParticipated: boolean;
		  }
		| undefined
	>;

	// Reports
	storeReport(
		userId: UserId,
		roomId: RoomId,
		eventId: EventId,
		score?: number,
		reason?: string,
	): Promise<void>;

	// OpenID
	storeOpenIdToken(
		token: string,
		userId: UserId,
		expiresAt: Timestamp,
	): Promise<void>;
	getOpenIdToken(
		token: string,
	): Promise<{ userId: UserId; expiresAt: Timestamp } | undefined>;

	// 3PIDs
	getThreePids(
		userId: UserId,
	): Promise<{ medium: string; address: string; added_at: Timestamp }[]>;
	addThreePid(userId: UserId, medium: string, address: string): Promise<void>;
	deleteThreePid(
		userId: UserId,
		medium: string,
		address: string,
	): Promise<void>;

	// User directory
	searchUserDirectory(
		searchTerm: string,
		limit: number,
	): Promise<{ user_id: UserId; display_name?: string; avatar_url?: string }[]>;

	// Thread roots
	getThreadRoots(
		roomId: RoomId,
		userId: UserId,
		include: "all" | "participated",
		limit: number,
		from?: string,
	): Promise<{
		events: { event: PDU; eventId: EventId }[];
		nextBatch?: string;
	}>;

	// Search
	searchRoomEvents(
		roomIds: RoomId[],
		searchTerm: string,
		keys: string[],
		limit: number,
		from?: string,
	): Promise<{
		events: { event: PDU; eventId: EventId; streamPos: number }[];
		count: number;
		nextBatch?: string;
	}>;

	// Federation - Remote server key cache
	storeServerKeys(serverName: ServerName, keys: ServerKeys): Promise<void>;
	getServerKeys(
		serverName: ServerName,
		keyId: KeyId,
	): Promise<{ key: string; validUntil: number } | undefined>;

	// Federation - Auth chain & state queries
	getAuthChain(eventIds: EventId[]): Promise<PDU[]>;
	getServersInRoom(roomId: RoomId): Promise<ServerName[]>;
	getStateAtEvent(
		roomId: RoomId,
		eventId: EventId,
	): Promise<Map<string, PDU> | undefined>;

	// Federation - Partial-state (faster) joins (MSC3706/MSC3902)
	//
	// A room joined with `omit_members=true`: we hold the create/power-levels/
	// join-rules and our own membership, but the other member events were elided
	// and are being fetched by a background resync. While a room is partial-state
	// we must (a) reject inbound make/send_join/knock, (b) hide it from eager
	// /sync, (c) block /members & /joined_members. `getRoomPartialState` returns
	// undefined once the resync has completed and the flag is cleared.

	/** Mark a room as partial-state, recording the servers to resync from and the join event. */
	markRoomPartialState(
		roomId: RoomId,
		servers: ServerName[],
		joinEventId: EventId,
	): Promise<void>;
	/** Clear the partial-state flag (resync complete); wakes any /sync or /members waiters. */
	clearRoomPartialState(roomId: RoomId): Promise<void>;
	/** The partial-state record, or undefined if the room is fully stated. */
	getRoomPartialState(
		roomId: RoomId,
	): Promise<{ servers: ServerName[]; joinEventId: EventId } | undefined>;
	/**
	 * Every room still in partial state. Used at startup to resume background
	 * resyncs that were interrupted by a restart (only the sqlite backend persists
	 * these across a restart; the in-memory backends return their live set).
	 */
	getAllPartialStateRooms(): Promise<
		{ roomId: RoomId; servers: ServerName[]; joinEventId: EventId }[]
	>;
	/** Resolve when `roomId` is no longer partial-state, or after `timeoutMs`. */
	waitForPartialStateClear(roomId: RoomId, timeoutMs: number): Promise<void>;
	/**
	 * Record an event accepted while the room was partial-state. At resync these
	 * are re-authed against the now-complete state; any that no longer pass are
	 * rejected. Mirrors synapse's `partial_state_events`.
	 */
	recordPartialStateEvent(roomId: RoomId, eventId: EventId): Promise<void>;
	/** Return and clear the events recorded by {@link recordPartialStateEvent}. */
	takePartialStateEvents(roomId: RoomId): Promise<EventId[]>;
	/**
	 * Record that a local user's device list changed while `roomId` was
	 * partial-state. At resync the change is re-sent to servers we only then
	 * learn are in the room (synapse device_lists_outbound_pokes).
	 */
	recordPartialStateDevicePoke(
		roomId: RoomId,
		userId: UserId,
		deviceId: DeviceId,
	): Promise<void>;
	/** Return and clear the pokes recorded by {@link recordPartialStateDevicePoke}. */
	takePartialStateDevicePokes(
		roomId: RoomId,
	): Promise<{ userId: UserId; deviceId: DeviceId }[]>;
	/**
	 * Permanently remove an event — used to reject an event that was accepted
	 * under partial state but fails re-auth once full state is known.
	 */
	deleteEvent(eventId: EventId): Promise<void>;
	/**
	 * Clear the `rejected` flag on an event previously rejected via deleteEvent,
	 * making it visible again (used at partial-state resync to ACCEPT an event
	 * that was rejected under incomplete state but passes once full state is
	 * known). Only meaningful on backends that keep rejected events (sqlite); a
	 * no-op where deleteEvent is destructive. The caller re-adds it to state.
	 */
	unrejectEvent(eventId: EventId): Promise<void>;
	/**
	 * The stream position at which `roomId`'s partial-state resync most recently
	 * completed (cleared), or undefined if it never did. Used by incremental
	 * /sync to surface the newly-known member state when a room un-partial-states.
	 */
	getRoomUnPartialStatedAt(roomId: RoomId): Promise<number | undefined>;
	/**
	 * Persist a state event learned during a partial-state resync as HISTORICAL
	 * state: it becomes part of current state (getAllState / getMemberEvents) but
	 * is given a negative stream position so it never appears in a forward sync
	 * timeline (it is pre-existing state we only just learned, not live activity).
	 */
	setStateEventHistorical(
		roomId: RoomId,
		event: PDU,
		eventId: EventId,
	): Promise<void>;

	// Federation - Transaction dedup
	getFederationTxn(origin: ServerName, txnId: string): Promise<boolean>;
	setFederationTxn(origin: ServerName, txnId: string): Promise<void>;

	// Federation - Durable outbound EDU retry queue
	//
	// When an EDU (to-device message, device-list update, ...) cannot be
	// delivered to a destination because it is unreachable, it is persisted
	// here keyed by destination. The outbound sender replays a destination's
	// pending EDUs the next time it successfully contacts that destination (and
	// on startup, so a sender that restarts while a peer is down still recovers).
	// Mirrors Synapse's PerDestinationQueue, which buffers pending EDUs and
	// flushes them when a transaction to the destination next succeeds.

	/**
	 * Persist an EDU for later (re)delivery to `destination`. Returns the opaque
	 * row id of the queued entry. Implementations cap the per-destination queue
	 * length; when the cap is exceeded the oldest entry is dropped and a warning
	 * is logged (callers need not handle this).
	 */
	enqueueFederationEdu(destination: ServerName, edu: EDU): Promise<number>;

	/**
	 * Return up to `limit` pending EDUs for `destination`, oldest first, each
	 * with its opaque row id (for deletion after successful delivery).
	 */
	getPendingFederationEdus(
		destination: ServerName,
		limit: number,
	): Promise<{ id: number; edu: EDU }[]>;

	/** Delete a delivered pending EDU by its row id. */
	deleteFederationEdu(id: number): Promise<void>;

	/** Distinct destinations that currently have at least one pending EDU. */
	getPendingFederationDestinations(): Promise<ServerName[]>;

	// 3PID verification
	storeVerificationToken(
		sessionId: string,
		data: {
			medium: string;
			address: string;
			clientSecret: string;
			sendAttempt: number;
			token: string;
			validated: boolean;
			userId?: string;
		},
	): Promise<void>;
	getVerificationSession(sessionId: string): Promise<
		| {
				medium: string;
				address: string;
				clientSecret: string;
				sendAttempt: number;
				token: string;
				validated: boolean;
				userId?: string;
		  }
		| undefined
	>;
	validateVerificationToken(sessionId: string, token: string): Promise<boolean>;

	// Login tokens (single-use tokens for m.login.token)
	storeLoginToken(
		token: string,
		userId: UserId,
		expiresAt: Timestamp,
	): Promise<void>;
	getLoginToken(
		token: string,
	): Promise<{ userId: UserId; expiresAt: Timestamp } | undefined>;
	deleteLoginToken(token: string): Promise<void>;

	// Federation - Room import
	importRoomState(
		roomId: RoomId,
		roomVersion: RoomVersion,
		stateEvents: PDU[],
		authChain: PDU[],
	): Promise<void>;
}

/**
 * Receipt record as returned by {@link Storage.getReceipts}.
 */
export interface ReceiptRecord {
	eventId: EventId;
	receiptType: string;
	userId: UserId;
	ts: Timestamp;
	threadId?: string;
}

/**
 * Apply the MSC4102 read-receipt preference rule.
 *
 * Receipts are persisted per (userId, receiptType, threadId) so threaded and
 * unthreaded receipts coexist in storage. When surfacing receipts to clients
 * we must collapse to a single record per (userId, receiptType, eventId):
 * if both an unthreaded receipt and a threaded receipt exist for that triple,
 * the UNTHREADED one wins (its emitted content carries no `thread_id`).
 */
/**
 * Maximum number of pending outbound EDUs retained per destination in the
 * durable retry queue. Beyond this the oldest entries are dropped (logged) so
 * an indefinitely-unreachable peer cannot grow the queue without bound. Mirrors
 * Synapse's PerDestinationQueue.MAX_PENDING_EDUS bounding.
 */
export const PENDING_FEDERATION_EDU_CAP = 1000;

export function collapseReceiptsMsc4102(
	rows: ReceiptRecord[],
): ReceiptRecord[] {
	const byKey = new Map<string, ReceiptRecord>();
	for (const row of rows) {
		const key = `${row.userId}\x1f${row.receiptType}\x1f${row.eventId}`;
		const existing = byKey.get(key);
		// Prefer the unthreaded record; otherwise keep the first seen.
		if (
			!existing ||
			(existing.threadId !== undefined && row.threadId === undefined)
		) {
			byKey.set(key, row);
		}
	}
	return [...byKey.values()];
}
