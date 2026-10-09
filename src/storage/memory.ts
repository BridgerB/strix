import { createHash } from "node:crypto";
import { computeEventId } from "../events.ts";
import {
	eventMatchesSearchTerm,
	paginateSearchMatches,
} from "../search-match.ts";
import type {
	CrossSigningKey,
	DeviceKeys,
	KeyBackupData,
	OneTimeKey,
} from "../types/e2ee.ts";
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
import {
	createEphemeralStore,
	eventToStrippedState,
	INVITE_STATE_TYPES,
} from "./ephemeral.ts";
import type { Storage, StoredSession } from "./interface.ts";
import {
	collapseReceiptsMsc4102,
	PENDING_FEDERATION_EDU_CAP,
} from "./interface.ts";

/** True for an empty JSON object `{}` (MSC3391 account-data tombstone). */
function isEmptyJsonObject(content: JsonObject): boolean {
	return Object.keys(content).length === 0;
}

export const createMemoryStorage = (): Storage => {
	const eph = createEphemeralStore();
	const users = new Map<string, UserAccount>();
	const usersByFullId = new Map<UserId, UserAccount>();
	const sessionsByToken = new Map<AccessToken, StoredSession>();
	const refreshIndex = new Map<RefreshToken, AccessToken>();
	const uiaaSessions = new Map<string, { completed: string[] }>();
	const roomsById = new Map<RoomId, RoomState>();
	const eventsById = new Map<EventId, PDU>();
	const roomTimeline = new Map<
		RoomId,
		{ eventId: EventId; streamPos: number }[]
	>();
	const txnMap = new Map<string, EventId>();
	const aliases = new Map<
		RoomAlias,
		{ room_id: RoomId; servers: ServerName[]; creator: UserId }
	>();
	const publicRooms = new Set<RoomId>();
	const globalAccountData = new Map<
		UserId,
		Map<string, { content: JsonObject; streamPos: number }>
	>();
	const roomAccountDataMap = new Map<
		string,
		Map<string, { content: JsonObject; streamPos: number }>
	>();
	const receiptsMap = new Map<
		RoomId,
		Map<string, { eventId: EventId; ts: Timestamp; threadId?: string }>
	>();
	const mediaStore = new Map<string, { metadata: StoredMedia; data: Buffer }>();
	const filters = new Map<UserId, Map<string, JsonObject>>();
	const deviceKeysMap = new Map<string, DeviceKeys>();
	const deviceListStream: { userId: UserId; streamPos: number }[] = [];
	const oneTimeKeysMap = new Map<string, Map<KeyId, string | OneTimeKey>>();
	const fallbackKeysMap = new Map<string, Map<KeyId, string | OneTimeKey>>();
	const crossSigningKeysMap = new Map<
		UserId,
		{
			master_key?: CrossSigningKey;
			self_signing_key?: CrossSigningKey;
			user_signing_key?: CrossSigningKey;
		}
	>();
	const keyBackupVersions = new Map<
		UserId,
		{
			version: string;
			algorithm: string;
			auth_data: JsonObject;
		}[]
	>();
	const keyBackupData = new Map<
		string,
		Map<RoomId, Map<string, KeyBackupData>>
	>();
	let keyBackupCounter = 0;
	const toDeviceInbox = new Map<string, ToDeviceEvent[]>();
	const pushersMap = new Map<UserId, Pusher[]>();
	const relationsMap = new Map<
		EventId,
		{
			eventId: EventId;
			relType: string;
			key?: string;
			sender: UserId;
			eventType: string;
			streamPos: number;
		}[]
	>();
	const reports: {
		userId: UserId;
		roomId: RoomId;
		eventId: EventId;
		score?: number;
		reason?: string;
		ts: number;
	}[] = [];
	const openIdTokens = new Map<string, { userId: UserId; expiresAt: number }>();
	const threePidsMap = new Map<
		UserId,
		{ medium: string; address: string; added_at: number }[]
	>();
	const serverKeysCache = new Map<
		string,
		{ key: string; validUntil: number }
	>();
	const federationTxns = new Set<string>();
	// Durable outbound EDU retry queue: destination -> ordered pending entries.
	const pendingFederationEdus = new Map<
		ServerName,
		{ id: number; edu: EDU }[]
	>();
	let pendingFederationEduCounter = 0;
	const verificationSessions = new Map<
		string,
		{
			medium: string;
			address: string;
			clientSecret: string;
			sendAttempt: number;
			token: string;
			validated: boolean;
			userId?: string;
		}
	>();
	const loginTokens = new Map<string, { userId: UserId; expiresAt: number }>();

	const createUser = async (account: UserAccount): Promise<void> => {
		users.set(account.localpart, account);
		usersByFullId.set(account.user_id, account);
	};

	const getUserByLocalpart = async (
		localpart: string,
	): Promise<UserAccount | undefined> => {
		return users.get(localpart);
	};

	const getUserById = async (
		userId: UserId,
	): Promise<UserAccount | undefined> => {
		return usersByFullId.get(userId);
	};

	const createSession = async (session: StoredSession): Promise<void> => {
		sessionsByToken.set(session.access_token, session);
		if (session.refresh_token) {
			refreshIndex.set(session.refresh_token, session.access_token);
		}
		// A new device/session was added: notify device-list subscribers.
		await recordDeviceKeyChange(session.user_id);
	};

	const getSessionByAccessToken = async (
		token: AccessToken,
	): Promise<StoredSession | undefined> => {
		return sessionsByToken.get(token);
	};

	const getSessionByRefreshToken = async (
		token: RefreshToken,
	): Promise<StoredSession | undefined> => {
		const accessToken = refreshIndex.get(token);
		if (!accessToken) return undefined;
		return sessionsByToken.get(accessToken);
	};

	const getSessionsByUser = async (
		userId: UserId,
	): Promise<StoredSession[]> => {
		return [...sessionsByToken.values()].filter((s) => s.user_id === userId);
	};

	const deleteSession = async (token: AccessToken): Promise<void> => {
		const session = sessionsByToken.get(token);
		if (session?.refresh_token) {
			refreshIndex.delete(session.refresh_token);
		}
		sessionsByToken.delete(token);
		// A device/session was removed: notify device-list subscribers.
		if (session) {
			await recordDeviceKeyChange(session.user_id);
		}
	};

	const deleteAllSessions = async (userId: UserId): Promise<void> => {
		for (const [token, session] of sessionsByToken) {
			if (session.user_id === userId) {
				if (session.refresh_token) {
					refreshIndex.delete(session.refresh_token);
				}
				sessionsByToken.delete(token);
			}
		}
		// Devices were removed: notify device-list subscribers.
		await recordDeviceKeyChange(userId);
	};

	const rotateToken = async (
		oldAccessToken: AccessToken,
		newAccessToken: AccessToken,
		newRefreshToken?: RefreshToken,
		expiresAt?: Timestamp,
	): Promise<StoredSession | undefined> => {
		const session = sessionsByToken.get(oldAccessToken);
		if (!session) return undefined;

		sessionsByToken.delete(oldAccessToken);
		if (session.refresh_token) {
			refreshIndex.delete(session.refresh_token);
		}

		const updated: StoredSession = {
			...session,
			access_token: newAccessToken,
			refresh_token: newRefreshToken,
			expires_at: expiresAt,
		};

		sessionsByToken.set(newAccessToken, updated);
		if (newRefreshToken) {
			refreshIndex.set(newRefreshToken, newAccessToken);
		}
		return updated;
	};

	const touchSession = async (
		token: AccessToken,
		ip: string,
		userAgent: string,
	): Promise<void> => {
		const session = sessionsByToken.get(token);
		if (session) {
			session.last_seen_ip = ip;
			session.last_seen_ts = Date.now();
			session.user_agent = userAgent;
		}
	};

	const createUIAASession = async (sessionId: string): Promise<void> => {
		uiaaSessions.set(sessionId, { completed: [] });
	};

	const getUIAASession = async (
		sessionId: string,
	): Promise<{ completed: string[] } | undefined> => {
		return uiaaSessions.get(sessionId);
	};

	const addUIAACompleted = async (
		sessionId: string,
		stageType: string,
	): Promise<void> => {
		uiaaSessions.get(sessionId)?.completed.push(stageType);
	};

	const deleteUIAASession = async (sessionId: string): Promise<void> => {
		uiaaSessions.delete(sessionId);
	};

	const createRoom = async (state: RoomState): Promise<void> => {
		roomsById.set(state.room_id, state);
		roomTimeline.set(state.room_id, []);
	};

	const getRoom = async (roomId: RoomId): Promise<RoomState | undefined> => {
		return roomsById.get(roomId);
	};

	const getRoomsForUser = async (userId: UserId): Promise<RoomId[]> => {
		return [...roomsById.values()]
			.filter((room) => {
				const memberEvent = room.state_events.get(`m.room.member\x1f${userId}`);
				return (
					(memberEvent?.content as Record<string, unknown>)?.membership ===
					"join"
				);
			})
			.map((room) => room.room_id);
	};

	const storeEvent = async (event: PDU, eventId: EventId): Promise<void> => {
		eventsById.set(eventId, event);
		const timeline = roomTimeline.get(event.room_id);
		if (timeline) {
			eph.streamCounter++;
			timeline.push({ eventId, streamPos: eph.streamCounter });
		}
		eph.wakeWaiters();
	};

	const updateEvent = async (eventId: EventId, event: PDU): Promise<void> => {
		eventsById.set(eventId, event);
	};

	const getEvent = async (
		eventId: EventId,
	): Promise<{ event: PDU; eventId: EventId } | undefined> => {
		const event = eventsById.get(eventId);
		if (!event) return undefined;
		return { event, eventId };
	};

	const getEventsByRoom = async (
		roomId: RoomId,
		limit: number,
		from?: number,
		direction: "b" | "f" = "f",
	): Promise<{ events: { event: PDU; eventId: EventId }[]; end?: number }> => {
		const timeline = roomTimeline.get(roomId) ?? [];
		const fromPos = from ?? (direction === "f" ? 0 : eph.streamCounter + 1);

		const filtered =
			direction === "f"
				? timeline.filter((e) => e.streamPos > fromPos)
				: timeline.filter((e) => e.streamPos < fromPos).reverse();

		const sliced = filtered.slice(0, limit);
		const events = sliced.map((e) => ({
			event: eventsById.get(e.eventId) as PDU,
			eventId: e.eventId,
		}));

		return { events, end: sliced[sliced.length - 1]?.streamPos };
	};

	const getStreamPosition = async (): Promise<number> => {
		return eph.streamCounter;
	};

	const getStateEvent = async (
		roomId: RoomId,
		eventType: string,
		stateKey: string,
	): Promise<{ event: PDU; eventId: EventId } | undefined> => {
		const room = roomsById.get(roomId);
		const event = room?.state_events.get(`${eventType}\x1f${stateKey}`);
		if (!event) return undefined;
		return { event, eventId: computeEventId(event, room?.room_version) };
	};

	const getAllState = async (
		roomId: RoomId,
	): Promise<{ event: PDU; eventId: EventId }[]> => {
		const room = roomsById.get(roomId);
		if (!room) return [];
		return [...room.state_events.values()].map((event) => ({
			event,
			eventId: computeEventId(event, room.room_version),
		}));
	};

	const setStateEvent = async (
		roomId: RoomId,
		event: PDU,
		eventId: EventId,
	): Promise<void> => {
		const room = roomsById.get(roomId);
		if (!room) return;
		const key = `${event.type}\x1f${event.state_key ?? ""}`;
		// When this state event replaces a previous one of the same
		// (type, state_key), stamp the new event's unsigned with the prior
		// state per the spec: prev_content / prev_sender / replaces_state.
		// `unsigned` is excluded from content-hash / event-ID / signature
		// computation, so mutating it here is safe and does not alter eventId.
		const previous = room.state_events.get(key);
		if (previous) {
			const previousId = computeEventId(previous, room.room_version);
			if (previousId !== eventId) {
				event.unsigned = {
					...(event.unsigned ?? {}),
					prev_content: previous.content,
					prev_sender: previous.sender,
					replaces_state: previousId,
				};
			}
		}
		room.state_events.set(key, event);
		await storeEvent(event, eventId);
	};

	const getMemberEvents = async (
		roomId: RoomId,
	): Promise<{ event: PDU; eventId: EventId }[]> => {
		const room = roomsById.get(roomId);
		if (!room) return [];
		return [...room.state_events.entries()]
			.filter(([key]) => key.startsWith("m.room.member\x1f"))
			.map(([, event]) => ({
				event,
				eventId: computeEventId(event, room.room_version),
			}));
	};

	const getTxnEventId = async (
		userId: UserId,
		deviceId: DeviceId,
		txnId: string,
	): Promise<EventId | undefined> => {
		return txnMap.get(`${userId}|${deviceId}|${txnId}`);
	};

	const setTxnEventId = async (
		userId: UserId,
		deviceId: DeviceId,
		txnId: string,
		eventId: EventId,
	): Promise<void> => {
		txnMap.set(`${userId}|${deviceId}|${txnId}`, eventId);
	};

	const getRoomsForUserWithMembership = async (
		userId: UserId,
	): Promise<{ roomId: RoomId; membership: string }[]> => {
		return [...roomsById.values()]
			.map((room) => {
				const memberEvent = room.state_events.get(`m.room.member\x1f${userId}`);
				const membership = (memberEvent?.content as Record<string, unknown>)
					?.membership as string | undefined;
				return membership ? { roomId: room.room_id, membership } : undefined;
			})
			.filter(
				(entry): entry is { roomId: RoomId; membership: string } =>
					entry !== undefined,
			);
	};

	const getEventsByRoomSince = async (
		roomId: RoomId,
		since: number,
		limit: number,
	): Promise<{
		events: { event: PDU; eventId: EventId; streamPos: number }[];
		limited: boolean;
	}> => {
		const timeline = roomTimeline.get(roomId) ?? [];
		const filtered = timeline.filter((e) => e.streamPos > since);
		const limited = filtered.length > limit;
		const sliced = limited ? filtered.slice(filtered.length - limit) : filtered;
		const events = sliced.map((e) => ({
			event: eventsById.get(e.eventId) as PDU,
			eventId: e.eventId,
			streamPos: e.streamPos,
		}));
		return { events, limited };
	};

	const getStrippedState = async (
		roomId: RoomId,
	): Promise<StrippedStateEvent[]> => {
		const room = roomsById.get(roomId);
		if (!room) return [];
		return [...room.state_events.entries()]
			.filter(([key]) =>
				INVITE_STATE_TYPES.includes(
					key.split("\x1f")[0] as (typeof INVITE_STATE_TYPES)[number],
				),
			)
			.map(([, event]) => eventToStrippedState(event));
	};

	const getProfile = async (
		userId: UserId,
	): Promise<UserProfile | undefined> => {
		const user = usersByFullId.get(userId);
		if (!user) return undefined;
		const profile: UserProfile = {};
		if (user.displayname) profile.displayname = user.displayname;
		if (user.avatar_url) profile.avatar_url = user.avatar_url;
		return profile;
	};

	const setDisplayName = async (
		userId: UserId,
		displayname: string | null,
	): Promise<void> => {
		const user = usersByFullId.get(userId);
		if (!user) return;
		if (displayname === null) {
			delete user.displayname;
		} else {
			user.displayname = displayname;
		}
	};

	const setAvatarUrl = async (
		userId: UserId,
		avatarUrl: string | null,
	): Promise<void> => {
		const user = usersByFullId.get(userId);
		if (!user) return;
		if (avatarUrl === null) {
			delete user.avatar_url;
		} else {
			user.avatar_url = avatarUrl;
		}
	};

	const getDevice = async (
		userId: UserId,
		deviceId: DeviceId,
	): Promise<Device | undefined> => {
		const session = [...sessionsByToken.values()].find(
			(s) => s.user_id === userId && s.device_id === deviceId,
		);
		if (!session) return undefined;
		return {
			device_id: session.device_id,
			display_name: session.display_name,
			last_seen_ip: session.last_seen_ip,
			last_seen_ts: session.last_seen_ts,
		};
	};

	const getAllDevices = async (userId: UserId): Promise<Device[]> => {
		return [...sessionsByToken.values()]
			.filter((s) => s.user_id === userId)
			.map((s) => ({
				device_id: s.device_id,
				display_name: s.display_name,
				last_seen_ip: s.last_seen_ip,
				last_seen_ts: s.last_seen_ts,
			}));
	};

	const updateDeviceDisplayName = async (
		userId: UserId,
		deviceId: DeviceId,
		displayName: string,
	): Promise<void> => {
		for (const session of sessionsByToken.values()) {
			if (session.user_id === userId && session.device_id === deviceId) {
				session.display_name = displayName;
				// A device's display name changed: notify device-list
				// subscribers. Mirrors Synapse's DeviceHandler, where
				// update_device (display-name change) calls notify_device_update
				// so local /sync device_lists.changed and /keys/changes, plus
				// federated m.device_list_update, pick up the change.
				await recordDeviceKeyChange(userId);
				return;
			}
		}
	};

	const deleteDeviceSession = async (
		userId: UserId,
		deviceId: DeviceId,
	): Promise<void> => {
		for (const [token, session] of sessionsByToken) {
			if (session.user_id === userId && session.device_id === deviceId) {
				if (session.refresh_token) {
					refreshIndex.delete(session.refresh_token);
				}
				sessionsByToken.delete(token);
				break;
			}
		}
		// A device was removed: notify device-list subscribers.
		await recordDeviceKeyChange(userId);
	};

	const updatePassword = async (
		userId: UserId,
		newPasswordHash: string,
	): Promise<void> => {
		const user = usersByFullId.get(userId);
		if (user) {
			user.password_hash = newPasswordHash;
		}
	};

	const deactivateUser = async (userId: UserId): Promise<void> => {
		const user = usersByFullId.get(userId);
		if (user) {
			user.is_deactivated = true;
		}
		await deleteAllSessions(userId);
	};

	const createRoomAlias = async (
		roomAlias: RoomAlias,
		roomId: RoomId,
		servers: ServerName[],
		creator: UserId,
	): Promise<void> => {
		aliases.set(roomAlias, { room_id: roomId, servers, creator });
	};

	const deleteRoomAlias = async (roomAlias: RoomAlias): Promise<boolean> => {
		return aliases.delete(roomAlias);
	};

	const getRoomByAlias = async (
		roomAlias: RoomAlias,
	): Promise<{ room_id: RoomId; servers: ServerName[] } | undefined> => {
		const entry = aliases.get(roomAlias);
		if (!entry) return undefined;
		return { room_id: entry.room_id, servers: entry.servers };
	};

	const getAliasesForRoom = async (roomId: RoomId): Promise<RoomAlias[]> => {
		return [...aliases.entries()]
			.filter(([, entry]) => entry.room_id === roomId)
			.map(([alias]) => alias);
	};

	const getAliasCreator = async (
		roomAlias: RoomAlias,
	): Promise<UserId | undefined> => {
		return aliases.get(roomAlias)?.creator;
	};

	const setRoomVisibility = async (
		roomId: RoomId,
		visibility: "public" | "private",
	): Promise<void> => {
		if (visibility === "public") {
			publicRooms.add(roomId);
		} else {
			publicRooms.delete(roomId);
		}
	};

	const getRoomVisibility = async (
		roomId: RoomId,
	): Promise<"public" | "private"> => {
		return publicRooms.has(roomId) ? "public" : "private";
	};

	const getPublicRoomIds = async (): Promise<RoomId[]> => {
		return [...publicRooms];
	};

	const getGlobalAccountData = async (
		userId: UserId,
		type: string,
	): Promise<JsonObject | undefined> => {
		return globalAccountData.get(userId)?.get(type)?.content;
	};

	const setGlobalAccountData = async (
		userId: UserId,
		type: string,
		content: JsonObject,
	): Promise<void> => {
		let userMap = globalAccountData.get(userId);
		if (!userMap) {
			userMap = new Map();
			globalAccountData.set(userId, userMap);
		}
		userMap.set(type, { content, streamPos: ++eph.streamCounter });
		eph.wakeWaiters();
	};

	const getAllGlobalAccountData = async (
		userId: UserId,
	): Promise<{ type: string; content: JsonObject }[]> => {
		const userMap = globalAccountData.get(userId);
		if (!userMap) return [];
		// Exclude MSC3391 deletion tombstones (empty content) from initial sync.
		return [...userMap.entries()]
			.filter(([, v]) => !isEmptyJsonObject(v.content))
			.map(([type, v]) => ({ type, content: v.content }));
	};

	const getGlobalAccountDataSince = async (
		userId: UserId,
		since: number,
	): Promise<{ type: string; content: JsonObject }[]> => {
		const userMap = globalAccountData.get(userId);
		if (!userMap) return [];
		// Include tombstones so incremental sync surfaces deletions.
		return [...userMap.entries()]
			.filter(([, v]) => v.streamPos > since)
			.map(([type, v]) => ({ type, content: v.content }));
	};

	const getRoomAccountData = async (
		userId: UserId,
		roomId: RoomId,
		type: string,
	): Promise<JsonObject | undefined> => {
		return roomAccountDataMap.get(`${userId}\x1f${roomId}`)?.get(type)?.content;
	};

	const setRoomAccountData = async (
		userId: UserId,
		roomId: RoomId,
		type: string,
		content: JsonObject,
	): Promise<void> => {
		const key = `${userId}\x1f${roomId}`;
		let dataMap = roomAccountDataMap.get(key);
		if (!dataMap) {
			dataMap = new Map();
			roomAccountDataMap.set(key, dataMap);
		}
		dataMap.set(type, { content, streamPos: ++eph.streamCounter });
		eph.wakeWaiters();
	};
	const deleteGlobalAccountData = async (
		userId: UserId,
		type: string,
	): Promise<void> => {
		// MSC3391: leave a tombstone (empty content) with a fresh stream position
		// rather than removing the entry, so incremental sync can surface it.
		let userMap = globalAccountData.get(userId);
		if (!userMap) {
			userMap = new Map();
			globalAccountData.set(userId, userMap);
		}
		userMap.set(type, { content: {}, streamPos: ++eph.streamCounter });
		eph.wakeWaiters();
	};
	const deleteRoomAccountData = async (
		userId: UserId,
		roomId: RoomId,
		type: string,
	): Promise<void> => {
		const key = `${userId}\x1f${roomId}`;
		let dataMap = roomAccountDataMap.get(key);
		if (!dataMap) {
			dataMap = new Map();
			roomAccountDataMap.set(key, dataMap);
		}
		dataMap.set(type, { content: {}, streamPos: ++eph.streamCounter });
		eph.wakeWaiters();
	};

	const getAllRoomAccountData = async (
		userId: UserId,
		roomId: RoomId,
	): Promise<{ type: string; content: JsonObject }[]> => {
		const dataMap = roomAccountDataMap.get(`${userId}\x1f${roomId}`);
		if (!dataMap) return [];
		// Exclude MSC3391 deletion tombstones from initial sync.
		return [...dataMap.entries()]
			.filter(([, v]) => !isEmptyJsonObject(v.content))
			.map(([type, v]) => ({ type, content: v.content }));
	};

	const getRoomAccountDataSince = async (
		userId: UserId,
		since: number,
	): Promise<{ roomId: RoomId; type: string; content: JsonObject }[]> => {
		const prefix = `${userId}\x1f`;
		const out: { roomId: RoomId; type: string; content: JsonObject }[] = [];
		for (const [key, dataMap] of roomAccountDataMap.entries()) {
			if (!key.startsWith(prefix)) continue;
			const roomId = key.slice(prefix.length) as RoomId;
			for (const [type, v] of dataMap.entries()) {
				if (v.streamPos > since) out.push({ roomId, type, content: v.content });
			}
		}
		return out;
	};

	const setReceipt = async (
		roomId: RoomId,
		userId: UserId,
		eventId: EventId,
		receiptType: string,
		ts: Timestamp,
		threadId?: string,
	): Promise<void> => {
		let roomReceipts = receiptsMap.get(roomId);
		if (!roomReceipts) {
			roomReceipts = new Map();
			receiptsMap.set(roomId, roomReceipts);
		}
		// Key by (userId, receiptType, threadId) so an unthreaded receipt and
		// receipts in distinct threads coexist as separate entries. Empty string
		// is the sentinel for "no thread".
		roomReceipts.set(`${userId}\x1f${receiptType}\x1f${threadId ?? ""}`, {
			eventId,
			ts,
			threadId,
		});
		eph.wakeWaiters();
	};

	const getReceipts = async (
		roomId: RoomId,
	): Promise<
		{
			eventId: EventId;
			receiptType: string;
			userId: UserId;
			ts: Timestamp;
			threadId?: string;
		}[]
	> => {
		const roomReceipts = receiptsMap.get(roomId);
		if (!roomReceipts) return [];
		const rows = [...roomReceipts.entries()].map(([key, value]) => {
			const [userId, receiptType] = key.split("\x1f") as [UserId, string];
			return {
				eventId: value.eventId,
				receiptType,
				userId,
				ts: value.ts,
				threadId: value.threadId,
			};
		});
		return collapseReceiptsMsc4102(rows);
	};

	const storeMedia = async (
		media: StoredMedia,
		data: Buffer,
	): Promise<void> => {
		mediaStore.set(`${media.origin}/${media.media_id}`, {
			metadata: media,
			data,
		});
	};

	const getMedia = async (
		serverName: ServerName,
		mediaId: string,
	): Promise<{ metadata: StoredMedia; data: Buffer } | undefined> => {
		return mediaStore.get(`${serverName}/${mediaId}`);
	};

	const reserveMedia = async (media: StoredMedia): Promise<void> => {
		mediaStore.set(`${media.origin}/${media.media_id}`, {
			metadata: media,
			data: Buffer.alloc(0),
		});
	};

	const updateMediaContent = async (
		serverName: ServerName,
		mediaId: string,
		contentType: string,
		fileName: string | undefined,
		data: Buffer,
	): Promise<boolean> => {
		const key = `${serverName}/${mediaId}`;
		const existing = mediaStore.get(key);
		if (!existing) return false;
		const hash = createHash("sha256").update(data).digest("base64");
		existing.metadata.content_type = contentType;
		existing.metadata.upload_name = fileName;
		existing.metadata.file_size = data.length;
		existing.metadata.content_hash = hash;
		existing.data = data;
		return true;
	};

	const createFilter = async (
		userId: UserId,
		filter: JsonObject,
	): Promise<string> => {
		let userFilters = filters.get(userId);
		if (!userFilters) {
			userFilters = new Map();
			filters.set(userId, userFilters);
		}
		const filterId = String(++eph.filterCounter);
		userFilters.set(filterId, filter);
		return filterId;
	};

	const getFilter = async (
		userId: UserId,
		filterId: string,
	): Promise<JsonObject | undefined> => {
		return filters.get(userId)?.get(filterId);
	};

	const setDeviceKeys = async (
		userId: UserId,
		deviceId: DeviceId,
		keys: DeviceKeys,
	): Promise<void> => {
		deviceKeysMap.set(`${userId}\x1f${deviceId}`, keys);
		await recordDeviceKeyChange(userId);
	};

	const recordDeviceKeyChange = async (userId: UserId): Promise<void> => {
		deviceListStream.push({ userId, streamPos: ++eph.streamCounter });
		eph.wakeWaiters();
	};

	const getChangedDeviceUsers = async (
		since: number,
		until: number,
	): Promise<UserId[]> => {
		const seen = new Set<UserId>();
		for (const entry of deviceListStream) {
			if (entry.streamPos > since && entry.streamPos <= until) {
				seen.add(entry.userId);
			}
		}
		return [...seen];
	};

	const getDeviceKeys = async (
		userId: UserId,
		deviceId: DeviceId,
	): Promise<DeviceKeys | undefined> => {
		return deviceKeysMap.get(`${userId}\x1f${deviceId}`);
	};

	const getAllDeviceKeys = async (
		userId: UserId,
	): Promise<Record<DeviceId, DeviceKeys>> => {
		const result: Record<DeviceId, DeviceKeys> = {};
		const prefix = `${userId}\x1f`;
		for (const [key, value] of deviceKeysMap) {
			if (key.startsWith(prefix)) {
				result[key.slice(prefix.length) as DeviceId] = value;
			}
		}
		return result;
	};

	const deleteDeviceKeys = async (userId: UserId): Promise<void> => {
		const prefix = `${userId}\x1f`;
		for (const key of deviceKeysMap.keys()) {
			if (key.startsWith(prefix)) deviceKeysMap.delete(key);
		}
	};

	const addOneTimeKeys = async (
		userId: UserId,
		deviceId: DeviceId,
		keys: Record<KeyId, string | OneTimeKey>,
	): Promise<void> => {
		const mapKey = `${userId}\x1f${deviceId}`;
		let otks = oneTimeKeysMap.get(mapKey);
		if (!otks) {
			otks = new Map();
			oneTimeKeysMap.set(mapKey, otks);
		}
		for (const [keyId, key] of Object.entries(keys)) {
			otks.set(keyId as KeyId, key);
		}
	};

	const claimOneTimeKey = async (
		userId: UserId,
		deviceId: DeviceId,
		algorithm: string,
	): Promise<{ keyId: KeyId; key: string | OneTimeKey } | undefined> => {
		const mapKey = `${userId}\x1f${deviceId}`;
		const otks = oneTimeKeysMap.get(mapKey);
		if (otks) {
			for (const [keyId, key] of otks) {
				if (keyId.startsWith(`${algorithm}:`)) {
					otks.delete(keyId);
					return { keyId, key };
				}
			}
		}
		const fallbacks = fallbackKeysMap.get(mapKey);
		if (fallbacks) {
			for (const [keyId, key] of fallbacks) {
				if (keyId.startsWith(`${algorithm}:`)) {
					return { keyId, key };
				}
			}
		}
		return undefined;
	};

	const getOneTimeKeyCounts = async (
		userId: UserId,
		deviceId: DeviceId,
	): Promise<Record<string, number>> => {
		const otks = oneTimeKeysMap.get(`${userId}\x1f${deviceId}`);
		if (!otks) return {};
		const counts: Record<string, number> = {};
		for (const keyId of otks.keys()) {
			const algorithm = keyId.split(":")[0] as string;
			counts[algorithm] = (counts[algorithm] ?? 0) + 1;
		}
		return counts;
	};

	const setFallbackKeys = async (
		userId: UserId,
		deviceId: DeviceId,
		keys: Record<KeyId, string | OneTimeKey>,
	): Promise<void> => {
		const fallbacks = new Map<KeyId, string | OneTimeKey>();
		for (const [keyId, key] of Object.entries(keys)) {
			fallbacks.set(keyId as KeyId, key);
		}
		fallbackKeysMap.set(`${userId}\x1f${deviceId}`, fallbacks);
	};

	const getFallbackKeyTypes = async (
		userId: UserId,
		deviceId: DeviceId,
	): Promise<string[]> => {
		const fallbacks = fallbackKeysMap.get(`${userId}\x1f${deviceId}`);
		if (!fallbacks) return [];
		return [
			...new Set(
				[...fallbacks.keys()].map((keyId) => keyId.split(":")[0] as string),
			),
		];
	};

	// Cross-signing keys
	const setCrossSigningKeys = async (
		userId: UserId,
		keys: {
			master_key?: CrossSigningKey;
			self_signing_key?: CrossSigningKey;
			user_signing_key?: CrossSigningKey;
		},
	): Promise<void> => {
		const existing = crossSigningKeysMap.get(userId) ?? {};
		if (keys.master_key) existing.master_key = keys.master_key;
		if (keys.self_signing_key)
			existing.self_signing_key = keys.self_signing_key;
		if (keys.user_signing_key)
			existing.user_signing_key = keys.user_signing_key;
		crossSigningKeysMap.set(userId, existing);
	};

	const getCrossSigningKeys = async (
		userId: UserId,
	): Promise<{
		master_key?: CrossSigningKey;
		self_signing_key?: CrossSigningKey;
		user_signing_key?: CrossSigningKey;
	}> => {
		return crossSigningKeysMap.get(userId) ?? {};
	};

	const storeCrossSigningSignatures = async (
		userId: UserId,
		signatures: Record<string, Record<string, JsonObject>>,
	): Promise<
		Record<string, Record<string, { errcode: string; error: string }>>
	> => {
		// Store signatures onto device keys or cross-signing keys
		const failures: Record<
			string,
			Record<string, { errcode: string; error: string }>
		> = {};
		for (const [targetUserId, keyMap] of Object.entries(signatures)) {
			for (const [keyId, signedObject] of Object.entries(keyMap)) {
				const signedSigs = (signedObject as Record<string, unknown>)
					.signatures as Record<string, Record<string, string>> | undefined;
				if (!signedSigs) {
					failures[targetUserId] ??= {};
					(
						failures[targetUserId] as Record<
							string,
							{ errcode: string; error: string }
						>
					)[keyId] = {
						errcode: "M_INVALID_SIGNATURE",
						error: "Missing signatures field",
					};
					continue;
				}

				// Authorization: can only sign own devices or other users' master keys
				if (targetUserId !== userId) {
					const targetCrossKeys = crossSigningKeysMap.get(
						targetUserId as UserId,
					);
					const isMasterKey =
						targetCrossKeys?.master_key &&
						Object.keys(targetCrossKeys.master_key.keys).some(
							(k) => k === keyId || k.endsWith(`:${keyId}`),
						);
					if (!isMasterKey) {
						failures[targetUserId] ??= {};
						(
							failures[targetUserId] as Record<
								string,
								{ errcode: string; error: string }
							>
						)[keyId] = {
							errcode: "M_FORBIDDEN",
							error: "Can only sign own devices or other users' master keys",
						};
						continue;
					}
				}

				// Try updating device keys
				const deviceKeys = await getDeviceKeys(
					targetUserId as UserId,
					keyId as DeviceId,
				);
				if (deviceKeys) {
					if (!deviceKeys.signatures) deviceKeys.signatures = {};
					for (const [signer, sigs] of Object.entries(signedSigs)) {
						deviceKeys.signatures[signer] ??= {};
						Object.assign(
							deviceKeys.signatures[signer] as Record<string, string>,
							sigs,
						);
					}
					continue;
				}

				// Try updating cross-signing keys
				const crossKeys = crossSigningKeysMap.get(targetUserId as UserId);
				if (crossKeys) {
					let matched = false;
					for (const key of [
						crossKeys.master_key,
						crossKeys.self_signing_key,
						crossKeys.user_signing_key,
					]) {
						if (!key) continue;
						if (
							Object.keys(key.keys).some(
								(k) => k === keyId || k.endsWith(`:${keyId}`),
							)
						) {
							if (!key.signatures) key.signatures = {};
							for (const [signer, sigs] of Object.entries(signedSigs)) {
								key.signatures[signer] ??= {};
								Object.assign(
									key.signatures[signer] as Record<string, string>,
									sigs,
								);
							}
							matched = true;
							break;
						}
					}
					if (matched) continue;
				}

				failures[targetUserId] ??= {};
				(
					failures[targetUserId] as Record<
						string,
						{ errcode: string; error: string }
					>
				)[keyId] = {
					errcode: "M_NOT_FOUND",
					error: "Key not found",
				};
			}
		}
		return failures;
	};

	// Key backup
	const createKeyBackupVersion = async (
		userId: UserId,
		algorithm: string,
		authData: JsonObject,
	): Promise<string> => {
		let versions = keyBackupVersions.get(userId);
		if (!versions) {
			versions = [];
			keyBackupVersions.set(userId, versions);
		}
		keyBackupCounter++;
		const version = String(keyBackupCounter);
		versions.push({ version, algorithm, auth_data: authData });
		return version;
	};

	const getKeyBackupVersion = async (
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
	> => {
		const versions = keyBackupVersions.get(userId);
		if (!versions || versions.length === 0) return undefined;

		const v = version
			? versions.find((b) => b.version === version)
			: versions[versions.length - 1];
		if (!v) return undefined;

		const backupKey = `${userId}\x1f${v.version}`;
		const rooms = keyBackupData.get(backupKey);
		let count = 0;
		if (rooms) {
			for (const sessions of rooms.values()) {
				count += sessions.size;
			}
		}

		return {
			version: v.version,
			algorithm: v.algorithm,
			auth_data: v.auth_data,
			count,
			etag: computeBackupEtag(backupKey),
		};
	};

	const computeBackupEtag = (backupKey: string): string => {
		const rooms = keyBackupData.get(backupKey);
		if (!rooms) return "0";
		let hash = 0;
		for (const [roomId, sessions] of rooms) {
			for (const sessionId of sessions.keys()) {
				for (const c of `${roomId}${sessionId}`) {
					hash = ((hash << 5) - hash + c.charCodeAt(0)) | 0;
				}
			}
		}
		return String(Math.abs(hash));
	};

	const updateKeyBackupVersion = async (
		userId: UserId,
		version: string,
		authData: JsonObject,
	): Promise<boolean> => {
		const versions = keyBackupVersions.get(userId);
		if (!versions) return false;
		const v = versions.find((b) => b.version === version);
		if (!v) return false;
		v.auth_data = authData;
		return true;
	};

	const deleteKeyBackupVersion = async (
		userId: UserId,
		version: string,
	): Promise<boolean> => {
		const versions = keyBackupVersions.get(userId);
		if (!versions) return false;
		const idx = versions.findIndex((b) => b.version === version);
		if (idx === -1) return false;
		versions.splice(idx, 1);
		keyBackupData.delete(`${userId}\x1f${version}`);
		return true;
	};

	const putKeyBackupKeys = async (
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
	): Promise<{ count: number; etag: string } | undefined> => {
		const versions = keyBackupVersions.get(userId);
		if (!versions || versions.length === 0) return undefined;
		const current = versions[versions.length - 1]!;
		if (current.version !== version) return undefined;

		const backupKey = `${userId}\x1f${version}`;
		let rooms = keyBackupData.get(backupKey);
		if (!rooms) {
			rooms = new Map();
			keyBackupData.set(backupKey, rooms);
		}

		if (roomId && sessionId) {
			// Single session
			const data = keys as KeyBackupData;
			mergeBackupKey(rooms, roomId, sessionId, data);
		} else if (roomId) {
			// Room sessions
			const roomKeys = keys as { sessions: Record<string, KeyBackupData> };
			for (const [sid, data] of Object.entries(roomKeys.sessions)) {
				mergeBackupKey(rooms, roomId, sid, data);
			}
		} else {
			// All rooms
			const allKeys = keys as {
				rooms: Record<RoomId, { sessions: Record<string, KeyBackupData> }>;
			};
			for (const [rid, roomData] of Object.entries(allKeys.rooms)) {
				for (const [sid, data] of Object.entries(roomData.sessions)) {
					mergeBackupKey(rooms, rid as RoomId, sid, data);
				}
			}
		}

		let count = 0;
		for (const sessions of rooms.values()) count += sessions.size;
		return { count, etag: computeBackupEtag(backupKey) };
	};

	const mergeBackupKey = (
		rooms: Map<RoomId, Map<string, KeyBackupData>>,
		roomId: RoomId,
		sessionId: string,
		newData: KeyBackupData,
	): void => {
		let sessions = rooms.get(roomId);
		if (!sessions) {
			sessions = new Map();
			rooms.set(roomId, sessions);
		}
		const existing = sessions.get(sessionId);
		if (existing) {
			// Merge: prefer verified, then lower first_message_index, then lower forwarded_count
			if (
				(newData.is_verified && !existing.is_verified) ||
				(newData.is_verified === existing.is_verified &&
					newData.first_message_index < existing.first_message_index) ||
				(newData.is_verified === existing.is_verified &&
					newData.first_message_index === existing.first_message_index &&
					newData.forwarded_count < existing.forwarded_count)
			) {
				sessions.set(sessionId, newData);
			}
		} else {
			sessions.set(sessionId, newData);
		}
	};

	const getKeyBackupKeys = async (
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
	> => {
		const backupKey = `${userId}\x1f${version}`;
		const rooms = keyBackupData.get(backupKey);

		if (roomId && sessionId) {
			const sessions = rooms?.get(roomId);
			return sessions?.get(sessionId);
		} else if (roomId) {
			const sessions = rooms?.get(roomId);
			const result: Record<string, KeyBackupData> = {};
			if (sessions) {
				for (const [sid, data] of sessions) result[sid] = data;
			}
			return { sessions: result };
		} else {
			const result: Record<
				RoomId,
				{ sessions: Record<string, KeyBackupData> }
			> = {};
			if (rooms) {
				for (const [rid, sessions] of rooms) {
					const sessionsObj: Record<string, KeyBackupData> = {};
					for (const [sid, data] of sessions) sessionsObj[sid] = data;
					result[rid] = { sessions: sessionsObj };
				}
			}
			return { rooms: result };
		}
	};

	const deleteKeyBackupKeys = async (
		userId: UserId,
		version: string,
		roomId?: RoomId,
		sessionId?: string,
	): Promise<{ count: number; etag: string } | undefined> => {
		const versions = keyBackupVersions.get(userId);
		if (!versions || !versions.some((v) => v.version === version))
			return undefined;

		const backupKey = `${userId}\x1f${version}`;
		const rooms = keyBackupData.get(backupKey);
		if (!rooms) return { count: 0, etag: "0" };

		if (roomId && sessionId) {
			const sessions = rooms.get(roomId);
			if (sessions) {
				sessions.delete(sessionId);
				if (sessions.size === 0) rooms.delete(roomId);
			}
		} else if (roomId) {
			rooms.delete(roomId);
		} else {
			rooms.clear();
		}

		let count = 0;
		for (const sessions of rooms.values()) count += sessions.size;
		return { count, etag: computeBackupEtag(backupKey) };
	};

	const sendToDevice = async (
		userId: UserId,
		deviceId: DeviceId,
		event: ToDeviceEvent,
	): Promise<void> => {
		const key = `${userId}\x1f${deviceId}`;
		let inbox = toDeviceInbox.get(key);
		if (!inbox) {
			inbox = [];
			toDeviceInbox.set(key, inbox);
		}
		inbox.push(event);
		eph.wakeWaiters();
	};

	const getToDeviceMessages = async (
		userId: UserId,
		deviceId: DeviceId,
	): Promise<ToDeviceEvent[]> => {
		return toDeviceInbox.get(`${userId}\x1f${deviceId}`) ?? [];
	};

	const clearToDeviceMessages = async (
		userId: UserId,
		deviceId: DeviceId,
	): Promise<void> => {
		toDeviceInbox.delete(`${userId}\x1f${deviceId}`);
	};

	const getPushers = async (userId: UserId): Promise<Pusher[]> => {
		return pushersMap.get(userId) ?? [];
	};

	const setPusher = async (userId: UserId, pusher: Pusher): Promise<void> => {
		let userPushers = pushersMap.get(userId);
		if (!userPushers) {
			userPushers = [];
			pushersMap.set(userId, userPushers);
		}
		const idx = userPushers.findIndex(
			(p) => p.app_id === pusher.app_id && p.pushkey === pusher.pushkey,
		);
		if (idx >= 0) {
			userPushers[idx] = pusher;
		} else {
			userPushers.push(pusher);
		}
	};

	const deletePusher = async (
		userId: UserId,
		appId: string,
		pushkey: string,
	): Promise<void> => {
		const userPushers = pushersMap.get(userId);
		if (!userPushers) return;
		const idx = userPushers.findIndex(
			(p) => p.app_id === appId && p.pushkey === pushkey,
		);
		if (idx >= 0) userPushers.splice(idx, 1);
	};

	const deletePusherByKey = async (
		appId: string,
		pushkey: string,
	): Promise<void> => {
		for (const [, userPushers] of pushersMap) {
			const idx = userPushers.findIndex(
				(p) => p.app_id === appId && p.pushkey === pushkey,
			);
			if (idx >= 0) userPushers.splice(idx, 1);
		}
	};

	const storeRelation = async (
		eventId: EventId,
		roomId: RoomId,
		relType: string,
		targetEventId: EventId,
		key?: string,
	): Promise<void> => {
		const event = eventsById.get(eventId);
		if (!event) return;

		const timeline = roomTimeline.get(roomId) ?? [];
		const streamPos =
			timeline.find((e) => e.eventId === eventId)?.streamPos ??
			eph.streamCounter;

		let relations = relationsMap.get(targetEventId);
		if (!relations) {
			relations = [];
			relationsMap.set(targetEventId, relations);
		}
		relations.push({
			eventId,
			relType,
			key,
			sender: event.sender,
			eventType: event.type,
			streamPos,
		});
	};

	const getRelatedEvents = async (
		roomId: RoomId,
		eventId: EventId,
		relType?: string,
		eventType?: string,
		limit: number = 50,
		from?: string,
		direction: "b" | "f" = "f",
	): Promise<{
		events: { event: PDU; eventId: EventId }[];
		nextBatch?: string;
	}> => {
		let relations = relationsMap.get(eventId) ?? [];

		if (relType) relations = relations.filter((r) => r.relType === relType);
		if (eventType)
			relations = relations.filter((r) => r.eventType === eventType);

		relations = [...relations].sort((a, b) =>
			direction === "f" ? a.streamPos - b.streamPos : b.streamPos - a.streamPos,
		);

		const fromPos = from ? parseInt(from, 10) : undefined;
		if (fromPos !== undefined) {
			const startIdx = relations.findIndex((r) =>
				direction === "f" ? r.streamPos > fromPos : r.streamPos < fromPos,
			);
			relations = startIdx >= 0 ? relations.slice(startIdx) : [];
		}

		const sliced = relations.slice(0, limit);
		const events = sliced
			.map((r) => {
				const event = eventsById.get(r.eventId);
				if (!event || event.room_id !== roomId) return undefined;
				return { event, eventId: r.eventId };
			})
			.filter((e): e is { event: PDU; eventId: EventId } => e !== undefined);

		const nextBatch =
			sliced.length === limit && sliced.length > 0
				? String(sliced[sliced.length - 1]?.streamPos)
				: undefined;

		return { events, nextBatch };
	};

	const getAnnotationCounts = async (
		eventId: EventId,
	): Promise<{ type: string; key: string; count: number }[]> => {
		const annotations = (relationsMap.get(eventId) ?? []).filter(
			(r) => r.relType === "m.annotation" && r.key,
		);

		const counts = new Map<
			string,
			{ type: string; key: string; count: number }
		>();
		for (const ann of annotations) {
			const mapKey = `${ann.eventType}\x1f${ann.key}`;
			const existing = counts.get(mapKey);
			if (existing) {
				existing.count++;
			} else {
				counts.set(mapKey, {
					type: ann.eventType,
					key: ann.key as string,
					count: 1,
				});
			}
		}
		return [...counts.values()];
	};

	const getLatestEdit = async (
		eventId: EventId,
		sender: UserId,
	): Promise<{ event: PDU; eventId: EventId } | undefined> => {
		const edits = (relationsMap.get(eventId) ?? [])
			.filter((r) => r.relType === "m.replace" && r.sender === sender)
			.sort((a, b) => b.streamPos - a.streamPos);

		if (edits.length === 0) return undefined;
		const latest = edits[0] as (typeof edits)[number];
		const event = eventsById.get(latest.eventId);
		if (!event) return undefined;
		return { event, eventId: latest.eventId };
	};

	const getThreadSummary = async (
		eventId: EventId,
		userId: UserId,
	): Promise<
		| {
				latestEvent: { event: PDU; eventId: EventId };
				count: number;
				currentUserParticipated: boolean;
		  }
		| undefined
	> => {
		const threadReplies = (relationsMap.get(eventId) ?? [])
			.filter((r) => r.relType === "m.thread")
			.sort((a, b) => a.streamPos - b.streamPos);

		if (threadReplies.length === 0) return undefined;

		const latest = threadReplies[
			threadReplies.length - 1
		] as (typeof threadReplies)[number];
		const latestEvent = eventsById.get(latest.eventId);
		if (!latestEvent) return undefined;

		return {
			latestEvent: { event: latestEvent, eventId: latest.eventId },
			count: threadReplies.length,
			currentUserParticipated: threadReplies.some((r) => r.sender === userId),
		};
	};

	const storeReport = async (
		userId: UserId,
		roomId: RoomId,
		eventId: EventId,
		score?: number,
		reason?: string,
	): Promise<void> => {
		reports.push({
			userId,
			roomId,
			eventId,
			score,
			reason,
			ts: Date.now(),
		});
	};

	const storeOpenIdToken = async (
		token: string,
		userId: UserId,
		expiresAt: number,
	): Promise<void> => {
		openIdTokens.set(token, { userId, expiresAt });
	};

	const getOpenIdToken = async (
		token: string,
	): Promise<{ userId: UserId; expiresAt: number } | undefined> => {
		return openIdTokens.get(token);
	};

	const getThreePids = async (
		userId: UserId,
	): Promise<{ medium: string; address: string; added_at: number }[]> => {
		return threePidsMap.get(userId) ?? [];
	};

	const addThreePid = async (
		userId: UserId,
		medium: string,
		address: string,
	): Promise<void> => {
		let pids = threePidsMap.get(userId);
		if (!pids) {
			pids = [];
			threePidsMap.set(userId, pids);
		}
		if (pids.some((p) => p.medium === medium && p.address === address)) return;
		pids.push({ medium, address, added_at: Date.now() });
	};

	const deleteThreePid = async (
		userId: UserId,
		medium: string,
		address: string,
	): Promise<void> => {
		const pids = threePidsMap.get(userId);
		if (!pids) return;
		const idx = pids.findIndex(
			(p) => p.medium === medium && p.address === address,
		);
		if (idx >= 0) pids.splice(idx, 1);
	};

	const searchUserDirectory = async (
		searchTerm: string,
		limit: number,
	): Promise<
		{ user_id: UserId; display_name?: string; avatar_url?: string }[]
	> => {
		const term = searchTerm.toLowerCase();
		const results: {
			user_id: UserId;
			display_name?: string;
			avatar_url?: string;
		}[] = [];
		for (const user of usersByFullId.values()) {
			if (user.is_deactivated) continue;
			const matchId = user.user_id.toLowerCase().includes(term);
			const matchName = user.displayname?.toLowerCase().includes(term) ?? false;
			if (matchId || matchName) {
				results.push({
					user_id: user.user_id,
					display_name: user.displayname,
					avatar_url: user.avatar_url,
				});
			}
			if (results.length >= limit) break;
		}
		return results;
	};

	const getThreadRoots = async (
		roomId: RoomId,
		userId: UserId,
		include: "all" | "participated",
		limit: number,
		from?: string,
	): Promise<{
		events: { event: PDU; eventId: EventId }[];
		nextBatch?: string;
	}> => {
		const threadRoots = new Map<EventId, number>();
		const participatedIn = new Set<EventId>();

		for (const [targetId, relations] of relationsMap) {
			const threadReplies = relations.filter((r) => r.relType === "m.thread");
			if (threadReplies.length === 0) continue;

			const targetEvent = eventsById.get(targetId);
			if (!targetEvent || targetEvent.room_id !== roomId) continue;

			threadRoots.set(
				targetId,
				Math.max(...threadReplies.map((r) => r.streamPos)),
			);

			if (threadReplies.some((r) => r.sender === userId)) {
				participatedIn.add(targetId);
			}
		}

		let rootIds = [...threadRoots.entries()];
		if (include === "participated") {
			rootIds = rootIds.filter(([id]) => participatedIn.has(id));
		}

		rootIds.sort((a, b) => b[1] - a[1]);

		if (from) {
			const fromPos = parseInt(from, 10);
			const startIdx = rootIds.findIndex(([, pos]) => pos < fromPos);
			rootIds = startIdx >= 0 ? rootIds.slice(startIdx) : [];
		}

		const sliced = rootIds.slice(0, limit);
		const events = sliced
			.map(([eventId]) => {
				const event = eventsById.get(eventId);
				if (!event) return undefined;
				return { event, eventId };
			})
			.filter((e): e is { event: PDU; eventId: EventId } => e !== undefined);

		const nextBatch =
			sliced.length === limit && sliced.length > 0
				? String(sliced[sliced.length - 1]?.[1])
				: undefined;

		return { events, nextBatch };
	};

	const searchRoomEvents = async (
		roomIds: RoomId[],
		searchTerm: string,
		keys: string[],
		limit: number,
		from?: string,
	): Promise<{
		events: { event: PDU; eventId: EventId; streamPos: number }[];
		count: number;
		nextBatch?: string;
	}> => {
		const allEntries = roomIds.flatMap(
			(roomId) => roomTimeline.get(roomId) ?? [],
		);
		allEntries.sort((a, b) => b.streamPos - a.streamPos);

		const allMatches: { event: PDU; eventId: EventId; streamPos: number }[] =
			[];
		for (const entry of allEntries) {
			const event = eventsById.get(entry.eventId);
			if (!event) continue;
			if (eventMatchesSearchTerm(event, keys, searchTerm)) {
				allMatches.push({
					event,
					eventId: entry.eventId,
					streamPos: entry.streamPos,
				});
			}
		}

		return paginateSearchMatches(allMatches, limit, from);
	};

	const storeServerKeys = async (
		serverName: ServerName,
		keys: ServerKeys,
	): Promise<void> => {
		for (const [keyId, val] of Object.entries(keys.verify_keys)) {
			serverKeysCache.set(`${serverName}\x1f${keyId}`, {
				key: val.key,
				validUntil: keys.valid_until_ts,
			});
		}
	};

	const getServerKeys = async (
		serverName: ServerName,
		keyId: KeyId,
	): Promise<{ key: string; validUntil: number } | undefined> => {
		return serverKeysCache.get(`${serverName}\x1f${keyId}`);
	};

	const getAuthChain = async (eventIds: EventId[]): Promise<PDU[]> => {
		const visited = new Set<EventId>();
		const result: PDU[] = [];
		const queue = [...eventIds];

		while (queue.length > 0) {
			const id = queue.shift() as EventId;
			if (visited.has(id)) continue;
			visited.add(id);

			const event = eventsById.get(id);
			if (!event) continue;
			result.push(event);

			for (const authId of event.auth_events) {
				if (!visited.has(authId)) {
					queue.push(authId);
				}
			}
		}

		return result;
	};

	const getServersInRoom = async (roomId: RoomId): Promise<ServerName[]> => {
		const room = roomsById.get(roomId);
		if (!room) return [];

		const servers = new Set<ServerName>();
		for (const [key, event] of room.state_events) {
			if (key.startsWith("m.room.member\x1f")) {
				const membership = (event.content as Record<string, unknown>)
					.membership;
				// Include servers of any join/invite/knock member so that
				// federation fanout reaches invited and knocking participants.
				if (
					membership === "join" ||
					membership === "invite" ||
					membership === "knock"
				) {
					servers.add(
						(event.state_key as string)
							.split(":")
							.slice(1)
							.join(":") as ServerName,
					);
				}
			}
		}

		const ps = partialStateRooms.get(roomId);
		if (ps) for (const s of ps.servers) servers.add(s);
		return [...servers];
	};

	const partialStateRooms = new Map<
		string,
		{ servers: ServerName[]; joinEventId: EventId }
	>();
	const partialStateWaiters = new Map<string, Set<() => void>>();
	const unPartialStatedAt = new Map<string, number>();

	const getRoomUnPartialStatedAt = async (
		roomId: RoomId,
	): Promise<number | undefined> => {
		return unPartialStatedAt.get(roomId);
	};

	const setStateEventHistorical = async (
		roomId: RoomId,
		event: PDU,
		eventId: EventId,
	): Promise<void> => {
		// Add to current state + the event store, but NOT the room timeline, so it
		// never appears in a forward sync/messages window.
		eventsById.set(eventId, event);
		const room = roomsById.get(roomId);
		if (room) {
			room.state_events.set(`${event.type}\x1f${event.state_key ?? ""}`, event);
		}
	};

	const markRoomPartialState = async (
		roomId: RoomId,
		servers: ServerName[],
		joinEventId: EventId,
	): Promise<void> => {
		partialStateRooms.set(roomId, { servers, joinEventId });
	};

	const clearRoomPartialState = async (roomId: RoomId): Promise<void> => {
		partialStateRooms.delete(roomId);
		eph.streamCounter++;
		unPartialStatedAt.set(roomId, eph.streamCounter);
		const waiters = partialStateWaiters.get(roomId);
		if (waiters) {
			partialStateWaiters.delete(roomId);
			for (const w of waiters) w();
		}
		eph.wakeWaiters();
	};

	const getRoomPartialState = async (
		roomId: RoomId,
	): Promise<{ servers: ServerName[]; joinEventId: EventId } | undefined> => {
		return partialStateRooms.get(roomId);
	};

	const getAllPartialStateRooms = async (): Promise<
		{ roomId: RoomId; servers: ServerName[]; joinEventId: EventId }[]
	> => {
		return [...partialStateRooms.entries()].map(([roomId, v]) => ({
			roomId: roomId as RoomId,
			servers: v.servers,
			joinEventId: v.joinEventId,
		}));
	};

	const partialStateEvents = new Map<string, Set<EventId>>();

	const recordPartialStateEvent = async (
		roomId: RoomId,
		eventId: EventId,
	): Promise<void> => {
		let set = partialStateEvents.get(roomId);
		if (!set) {
			set = new Set();
			partialStateEvents.set(roomId, set);
		}
		set.add(eventId);
	};

	const takePartialStateEvents = async (roomId: RoomId): Promise<EventId[]> => {
		const set = partialStateEvents.get(roomId);
		partialStateEvents.delete(roomId);
		return set ? [...set] : [];
	};
	const partialStateDevicePokes = new Map<string, Set<string>>();

	const recordPartialStateDevicePoke = async (
		roomId: RoomId,
		userId: UserId,
		deviceId: DeviceId,
	): Promise<void> => {
		let set = partialStateDevicePokes.get(roomId);
		if (!set) {
			set = new Set();
			partialStateDevicePokes.set(roomId, set);
		}
		set.add(`${userId}\x1f${deviceId}`);
	};

	const takePartialStateDevicePokes = async (
		roomId: RoomId,
	): Promise<{ userId: UserId; deviceId: DeviceId }[]> => {
		const set = partialStateDevicePokes.get(roomId);
		partialStateDevicePokes.delete(roomId);
		return set
			? [...set].map((s) => {
					const sep = s.indexOf("\x1f");
					return {
						userId: s.slice(0, sep) as UserId,
						deviceId: s.slice(sep + 1) as DeviceId,
					};
				})
			: [];
	};

	const deleteEvent = async (eventId: EventId): Promise<void> => {
		const ev = eventsById.get(eventId);
		eventsById.delete(eventId);
		if (!ev) return;
		const tl = roomTimeline.get(ev.room_id as RoomId);
		if (tl) {
			roomTimeline.set(
				ev.room_id as RoomId,
				tl.filter((e) => e.eventId !== eventId),
			);
		}
		if (ev.state_key !== undefined) {
			const room = roomsById.get(ev.room_id as RoomId);
			if (room) {
				const key = `${ev.type}\x1f${ev.state_key}`;
				const cur = room.state_events.get(key);
				if (cur && computeEventId(cur, room.room_version) === eventId) {
					room.state_events.delete(key);
				}
			}
		}
	};

	const unrejectEvent = async (_eventId: EventId): Promise<void> => {
		// In-memory deleteEvent is destructive (no rejected flag is kept), so a
		// rejected event cannot be restored. No-op; the partial-state resync
		// re-evaluation path that needs this only runs against sqlite.
	};

	const waitForPartialStateClear = async (
		roomId: RoomId,
		timeoutMs: number,
	): Promise<void> => {
		if (!partialStateRooms.has(roomId)) return;
		await new Promise<void>((resolve) => {
			let set = partialStateWaiters.get(roomId);
			if (!set) {
				set = new Set();
				partialStateWaiters.set(roomId, set);
			}
			const done = () => {
				set?.delete(done);
				clearTimeout(timer);
				resolve();
			};
			const timer = setTimeout(done, timeoutMs);
			set.add(done);
		});
	};

	const getStateAtEvent = async (
		_roomId: RoomId,
		_eventId: EventId,
	): Promise<Map<string, PDU> | undefined> => {
		const room = roomsById.get(_roomId);
		if (!room) return undefined;
		return new Map(room.state_events);
	};

	const getFederationTxn = async (
		origin: ServerName,
		txnId: string,
	): Promise<boolean> => {
		return federationTxns.has(`${origin}\x1f${txnId}`);
	};

	const setFederationTxn = async (
		origin: ServerName,
		txnId: string,
	): Promise<void> => {
		federationTxns.add(`${origin}\x1f${txnId}`);
	};

	const enqueueFederationEdu = async (
		destination: ServerName,
		edu: EDU,
	): Promise<number> => {
		const id = ++pendingFederationEduCounter;
		const queue = pendingFederationEdus.get(destination) ?? [];
		queue.push({ id, edu });
		// Cap the per-destination queue; drop the oldest entries on overflow.
		if (queue.length > PENDING_FEDERATION_EDU_CAP) {
			const dropped = queue.splice(
				0,
				queue.length - PENDING_FEDERATION_EDU_CAP,
			);
			console.warn(
				`pendingFederationEdus: dropped ${dropped.length} EDU(s) for ${destination} (queue cap ${PENDING_FEDERATION_EDU_CAP} exceeded)`,
			);
		}
		pendingFederationEdus.set(destination, queue);
		return id;
	};

	const getPendingFederationEdus = async (
		destination: ServerName,
		limit: number,
	): Promise<{ id: number; edu: EDU }[]> => {
		const queue = pendingFederationEdus.get(destination) ?? [];
		return queue.slice(0, limit).map((e) => ({ id: e.id, edu: e.edu }));
	};

	const deleteFederationEdu = async (id: number): Promise<void> => {
		for (const [dest, queue] of pendingFederationEdus) {
			const idx = queue.findIndex((e) => e.id === id);
			if (idx !== -1) {
				queue.splice(idx, 1);
				if (queue.length === 0) pendingFederationEdus.delete(dest);
				return;
			}
		}
	};

	const getPendingFederationDestinations = async (): Promise<ServerName[]> => {
		return [...pendingFederationEdus.keys()];
	};

	const storeVerificationToken = async (
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
	): Promise<void> => {
		verificationSessions.set(sessionId, { ...data });
	};

	const getVerificationSession = async (
		sessionId: string,
	): Promise<
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
	> => {
		return verificationSessions.get(sessionId);
	};

	const validateVerificationToken = async (
		sessionId: string,
		token: string,
	): Promise<boolean> => {
		const session = verificationSessions.get(sessionId);
		if (!session) return false;
		if (session.token !== token) return false;
		session.validated = true;
		return true;
	};

	const storeLoginToken = async (
		token: string,
		userId: UserId,
		expiresAt: number,
	): Promise<void> => {
		loginTokens.set(token, { userId, expiresAt });
	};

	const getLoginToken = async (
		token: string,
	): Promise<{ userId: UserId; expiresAt: number } | undefined> => {
		return loginTokens.get(token);
	};

	const deleteLoginToken = async (token: string): Promise<void> => {
		loginTokens.delete(token);
	};

	const importRoomState = async (
		roomId: RoomId,
		roomVersion: RoomVersion,
		stateEvents: PDU[],
		authChain: PDU[],
	): Promise<void> => {
		for (const event of authChain) {
			eventsById.set(computeEventId(event, roomVersion), event);
		}

		const stateMap = new Map<string, PDU>();
		let maxDepth = 0;
		const extremities: EventId[] = [];

		for (const event of stateEvents) {
			const eventId = computeEventId(event, roomVersion);
			eventsById.set(eventId, event);

			stateMap.set(`${event.type}\x1f${event.state_key ?? ""}`, event);

			const timeline = roomTimeline.get(roomId) ?? [];
			eph.streamCounter++;
			timeline.push({ eventId, streamPos: eph.streamCounter });
			roomTimeline.set(roomId, timeline);

			if (event.depth > maxDepth) maxDepth = event.depth;
			extremities.length = 0;
			extremities.push(eventId);
		}

		roomsById.set(roomId, {
			room_id: roomId,
			room_version: roomVersion,
			state_events: stateMap,
			depth: maxDepth + 1,
			forward_extremities: extremities,
		});

		eph.wakeWaiters();
	};

	return {
		addOneTimeKeys,
		addThreePid,
		addUIAACompleted,
		claimOneTimeKey,
		clearRoomPartialState,
		clearToDeviceMessages,
		createFilter,
		createKeyBackupVersion,
		createRoom,
		createRoomAlias,
		createSession,
		createUIAASession,
		createUser,
		deactivateUser,
		deleteAllSessions,
		deleteDeviceKeys,
		deleteDeviceSession,
		deleteEvent,
		deleteFederationEdu,
		deleteGlobalAccountData,
		deleteKeyBackupKeys,
		deleteKeyBackupVersion,
		deleteLoginToken,
		deletePusher,
		deletePusherByKey,
		deleteRoomAccountData,
		deleteRoomAlias,
		deleteSession,
		deleteThreePid,
		deleteUIAASession,
		enqueueFederationEdu,
		getAliasCreator,
		getAliasesForRoom,
		getAllDeviceKeys,
		getAllDevices,
		getAllGlobalAccountData,
		getAllPartialStateRooms,
		getAllRoomAccountData,
		getAllState,
		getAnnotationCounts,
		getAuthChain,
		getChangedDeviceUsers,
		getCrossSigningKeys,
		getDevice,
		getDeviceKeys,
		getEvent,
		getEventsByRoom,
		getEventsByRoomSince,
		getFallbackKeyTypes,
		getFederationTxn,
		getFilter,
		getGlobalAccountData,
		getGlobalAccountDataSince,
		getKeyBackupKeys,
		getKeyBackupVersion,
		getLatestEdit,
		getLoginToken,
		getMedia,
		getMemberEvents,
		getOneTimeKeyCounts,
		getOpenIdToken,
		getPendingFederationDestinations,
		getPendingFederationEdus,
		getProfile,
		getPublicRoomIds,
		getPushers,
		getReceipts,
		getRelatedEvents,
		getRoom,
		getRoomAccountData,
		getRoomAccountDataSince,
		getRoomByAlias,
		getRoomPartialState,
		getRoomsForUser,
		getRoomsForUserWithMembership,
		getRoomUnPartialStatedAt,
		getRoomVisibility,
		getServerKeys,
		getServersInRoom,
		getSessionByAccessToken,
		getSessionByRefreshToken,
		getSessionsByUser,
		getStateAtEvent,
		getStateEvent,
		getStreamPosition,
		getStrippedState,
		getThreadRoots,
		getThreadSummary,
		getThreePids,
		getToDeviceMessages,
		getTxnEventId,
		getUIAASession,
		getUserById,
		getUserByLocalpart,
		getVerificationSession,
		importRoomState,
		markRoomPartialState,
		putKeyBackupKeys,
		recordDeviceKeyChange,
		recordPartialStateDevicePoke,
		recordPartialStateEvent,
		reserveMedia,
		rotateToken,
		searchRoomEvents,
		searchUserDirectory,
		sendToDevice,
		setAvatarUrl,
		setCrossSigningKeys,
		setDeviceKeys,
		setDisplayName,
		setFallbackKeys,
		setFederationTxn,
		setGlobalAccountData,
		setPusher,
		setReceipt,
		setRoomAccountData,
		setRoomVisibility,
		setStateEvent,
		setStateEventHistorical,
		setTxnEventId,
		storeCrossSigningSignatures,
		storeEvent,
		storeLoginToken,
		storeMedia,
		storeOpenIdToken,
		storeRelation,
		storeReport,
		storeServerKeys,
		storeVerificationToken,
		takePartialStateDevicePokes,
		takePartialStateEvents,
		touchSession,
		unrejectEvent,
		updateDeviceDisplayName,
		updateEvent,
		updateKeyBackupVersion,
		updateMediaContent,
		updatePassword,
		validateVerificationToken,
		waitForPartialStateClear,
		waitForEvents: eph.waitForEvents,
		setTyping: eph.setTyping,
		getTypingUsers: eph.getTypingUsers,
		getTypingChangedAt: eph.getTypingChangedAt,
		setPresence: eph.setPresence,
		getPresenceChangedAt: eph.getPresenceChangedAt,
		recordProfileUpdate: eph.recordProfileUpdate,
		getProfileUpdatesSince: eph.getProfileUpdatesSince,
		getPresence: eph.getPresence,
	};
};
