import { mkdirSync } from "node:fs";
import { dirname } from "node:path";
import Database from "better-sqlite3";
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
import {
	decodeDevicePoke,
	encodeDevicePoke,
	flattenKeyBackupEntries,
	keyBackupEtag,
	rowsToCrossSigningKeys,
	rowToSession,
	rowToStoredMedia,
	rowToUser,
	shouldReplaceBackupKey,
} from "./sql-helpers.ts";

export const createSqliteStorage = (dbPath: string): Storage => {
	const eph = createEphemeralStore();
	let db: Database.Database;

	// Room state cache — the handler relies on setStateEvent mutating
	// the same RoomState reference that ctx.roomState holds

	let stmts!: {
		insertEvent: Database.Statement;
		getEvent: Database.Statement;
		insertTimelineEntry: Database.Statement;
		getSession: Database.Statement;
		insertSession: Database.Statement;
		insertStateEvent: Database.Statement;
		getStateEvent: Database.Statement;
		getTxn: Database.Statement;
		setTxn: Database.Statement;
	};

	const init = (): void => {
		db.exec(`
			CREATE TABLE IF NOT EXISTS users (
				user_id TEXT PRIMARY KEY,
				localpart TEXT UNIQUE NOT NULL,
				server_name TEXT NOT NULL,
				password_hash TEXT NOT NULL,
				account_type TEXT NOT NULL DEFAULT 'user',
				is_deactivated INTEGER NOT NULL DEFAULT 0,
				created_at INTEGER NOT NULL,
				displayname TEXT,
				avatar_url TEXT
			);

			CREATE TABLE IF NOT EXISTS sessions (
				access_token TEXT PRIMARY KEY,
				refresh_token TEXT,
				device_id TEXT NOT NULL,
				user_id TEXT NOT NULL,
				access_token_hash TEXT,
				expires_at INTEGER,
				display_name TEXT,
				last_seen_ip TEXT,
				last_seen_ts INTEGER,
				user_agent TEXT
			);
			CREATE INDEX IF NOT EXISTS idx_sessions_user ON sessions(user_id);
			CREATE INDEX IF NOT EXISTS idx_sessions_refresh ON sessions(refresh_token);
			CREATE INDEX IF NOT EXISTS idx_sessions_device ON sessions(user_id, device_id);

			CREATE TABLE IF NOT EXISTS uiaa_sessions (
				session_id TEXT PRIMARY KEY,
				completed TEXT NOT NULL DEFAULT '[]'
			);

			CREATE TABLE IF NOT EXISTS rooms (
				room_id TEXT PRIMARY KEY,
				room_version TEXT NOT NULL,
				depth INTEGER NOT NULL DEFAULT 0,
				forward_extremities TEXT NOT NULL DEFAULT '[]'
			);

			CREATE TABLE IF NOT EXISTS events (
				event_id TEXT PRIMARY KEY,
				room_id TEXT NOT NULL,
				stream_pos INTEGER NOT NULL,
				event_json TEXT NOT NULL,
				rejected INTEGER NOT NULL DEFAULT 0
			);
			CREATE INDEX IF NOT EXISTS idx_events_room ON events(room_id);
			CREATE INDEX IF NOT EXISTS idx_events_stream ON events(room_id, stream_pos);

			CREATE TABLE IF NOT EXISTS state_events (
				room_id TEXT NOT NULL,
				event_type TEXT NOT NULL,
				state_key TEXT NOT NULL,
				event_id TEXT NOT NULL,
				event_json TEXT NOT NULL,
				PRIMARY KEY (room_id, event_type, state_key)
			);

			CREATE TABLE IF NOT EXISTS txn_map (
				user_id TEXT NOT NULL,
				device_id TEXT NOT NULL,
				txn_id TEXT NOT NULL,
				event_id TEXT NOT NULL,
				PRIMARY KEY (user_id, device_id, txn_id)
			);

			CREATE TABLE IF NOT EXISTS room_aliases (
				room_alias TEXT PRIMARY KEY,
				room_id TEXT NOT NULL,
				servers TEXT NOT NULL DEFAULT '[]',
				creator TEXT NOT NULL
			);

			CREATE TABLE IF NOT EXISTS room_directory (
				room_id TEXT PRIMARY KEY,
				visibility TEXT NOT NULL DEFAULT 'private'
			);

			CREATE TABLE IF NOT EXISTS global_account_data (
				user_id TEXT NOT NULL,
				type TEXT NOT NULL,
				content TEXT NOT NULL,
				stream_pos INTEGER NOT NULL DEFAULT 0,
				PRIMARY KEY (user_id, type)
			);

			CREATE TABLE IF NOT EXISTS room_account_data (
				user_id TEXT NOT NULL,
				room_id TEXT NOT NULL,
				type TEXT NOT NULL,
				content TEXT NOT NULL,
				stream_pos INTEGER NOT NULL DEFAULT 0,
				PRIMARY KEY (user_id, room_id, type)
			);

			CREATE TABLE IF NOT EXISTS receipts (
				room_id TEXT NOT NULL,
				user_id TEXT NOT NULL,
				event_id TEXT NOT NULL,
				receipt_type TEXT NOT NULL,
				ts INTEGER NOT NULL,
				thread_id TEXT NOT NULL DEFAULT '',
				PRIMARY KEY (room_id, user_id, receipt_type, thread_id)
			);

			CREATE TABLE IF NOT EXISTS media (
				origin TEXT NOT NULL,
				media_id TEXT NOT NULL,
				user_id TEXT,
				content_type TEXT NOT NULL,
				upload_name TEXT,
				file_size INTEGER NOT NULL,
				content_hash TEXT NOT NULL,
				created_at INTEGER NOT NULL,
				quarantined INTEGER NOT NULL DEFAULT 0,
				data BLOB NOT NULL,
				PRIMARY KEY (origin, media_id)
			);

			CREATE TABLE IF NOT EXISTS filters (
				user_id TEXT NOT NULL,
				filter_id TEXT NOT NULL,
				filter_json TEXT NOT NULL,
				PRIMARY KEY (user_id, filter_id)
			);

			CREATE TABLE IF NOT EXISTS device_keys (
				user_id TEXT NOT NULL,
				device_id TEXT NOT NULL,
				keys_json TEXT NOT NULL,
				PRIMARY KEY (user_id, device_id)
			);

			CREATE TABLE IF NOT EXISTS device_list_stream (
				user_id TEXT NOT NULL,
				stream_pos INTEGER NOT NULL
			);
			CREATE INDEX IF NOT EXISTS idx_device_list_stream ON device_list_stream(stream_pos);

			CREATE TABLE IF NOT EXISTS one_time_keys (
				user_id TEXT NOT NULL,
				device_id TEXT NOT NULL,
				key_id TEXT NOT NULL,
				algorithm TEXT NOT NULL,
				key_json TEXT NOT NULL,
				PRIMARY KEY (user_id, device_id, key_id)
			);

			CREATE TABLE IF NOT EXISTS fallback_keys (
				user_id TEXT NOT NULL,
				device_id TEXT NOT NULL,
				key_id TEXT NOT NULL,
				key_json TEXT NOT NULL,
				PRIMARY KEY (user_id, device_id, key_id)
			);

			CREATE TABLE IF NOT EXISTS to_device (
				id INTEGER PRIMARY KEY AUTOINCREMENT,
				user_id TEXT NOT NULL,
				device_id TEXT NOT NULL,
				event_json TEXT NOT NULL
			);
			CREATE INDEX IF NOT EXISTS idx_to_device ON to_device(user_id, device_id);

			CREATE TABLE IF NOT EXISTS pushers (
				user_id TEXT NOT NULL,
				app_id TEXT NOT NULL,
				pushkey TEXT NOT NULL,
				pusher_json TEXT NOT NULL,
				PRIMARY KEY (user_id, app_id, pushkey)
			);

			CREATE TABLE IF NOT EXISTS relations (
				event_id TEXT NOT NULL,
				room_id TEXT NOT NULL,
				rel_type TEXT NOT NULL,
				target_event_id TEXT NOT NULL,
				key TEXT,
				sender TEXT NOT NULL,
				event_type TEXT NOT NULL,
				stream_pos INTEGER NOT NULL
			);
			CREATE INDEX IF NOT EXISTS idx_relations_target ON relations(target_event_id);

			CREATE TABLE IF NOT EXISTS reports (
				id INTEGER PRIMARY KEY AUTOINCREMENT,
				user_id TEXT NOT NULL,
				room_id TEXT NOT NULL,
				event_id TEXT NOT NULL,
				score INTEGER,
				reason TEXT,
				ts INTEGER NOT NULL
			);

			CREATE TABLE IF NOT EXISTS openid_tokens (
				token TEXT PRIMARY KEY,
				user_id TEXT NOT NULL,
				expires_at INTEGER NOT NULL
			);

			CREATE TABLE IF NOT EXISTS threepids (
				user_id TEXT NOT NULL,
				medium TEXT NOT NULL,
				address TEXT NOT NULL,
				added_at INTEGER NOT NULL,
				PRIMARY KEY (user_id, medium, address)
			);

			CREATE TABLE IF NOT EXISTS server_keys (
				server_name TEXT NOT NULL,
				key_id TEXT NOT NULL,
				key TEXT NOT NULL,
				valid_until INTEGER NOT NULL,
				PRIMARY KEY (server_name, key_id)
			);

			CREATE TABLE IF NOT EXISTS federation_txns (
				origin TEXT NOT NULL,
				txn_id TEXT NOT NULL,
				PRIMARY KEY (origin, txn_id)
			);

			CREATE TABLE IF NOT EXISTS pending_federation_edus (
				id INTEGER PRIMARY KEY AUTOINCREMENT,
				destination TEXT NOT NULL,
				edu_json TEXT NOT NULL
			);
			CREATE INDEX IF NOT EXISTS idx_pending_fed_edus_dest
				ON pending_federation_edus (destination, id);

			CREATE TABLE IF NOT EXISTS cross_signing_keys (
				user_id TEXT NOT NULL,
				key_type TEXT NOT NULL,
				key_json TEXT NOT NULL,
				PRIMARY KEY (user_id, key_type)
			);

			CREATE TABLE IF NOT EXISTS key_backup_versions (
				id INTEGER PRIMARY KEY AUTOINCREMENT,
				user_id TEXT NOT NULL,
				version TEXT NOT NULL,
				algorithm TEXT NOT NULL,
				auth_data TEXT NOT NULL,
				UNIQUE(user_id, version)
			);

			CREATE TABLE IF NOT EXISTS key_backup_data (
				user_id TEXT NOT NULL,
				version TEXT NOT NULL,
				room_id TEXT NOT NULL,
				session_id TEXT NOT NULL,
				key_json TEXT NOT NULL,
				PRIMARY KEY (user_id, version, room_id, session_id)
			);
			CREATE TABLE IF NOT EXISTS partial_state_rooms (
				room_id TEXT PRIMARY KEY,
				servers TEXT NOT NULL,
				join_event_id TEXT NOT NULL
			);
			CREATE TABLE IF NOT EXISTS partial_state_events (
				room_id TEXT NOT NULL,
				event_id TEXT NOT NULL,
				PRIMARY KEY (room_id, event_id)
			);
		`);

		const maxPos = db
			.prepare(
				`SELECT MAX(m) as m FROM (
					SELECT MAX(stream_pos) as m FROM events
					UNION ALL SELECT MAX(stream_pos) FROM global_account_data
					UNION ALL SELECT MAX(stream_pos) FROM room_account_data
					UNION ALL SELECT MAX(stream_pos) FROM device_list_stream
				)`,
			)
			.get() as { m: number | null } | undefined;
		eph.streamCounter = maxPos?.m ?? 0;

		const maxFilter = db
			.prepare("SELECT MAX(CAST(filter_id AS INTEGER)) as m FROM filters")
			.get() as { m: number | null } | undefined;
		eph.filterCounter = maxFilter?.m ?? 0;

		stmts = {
			insertEvent: db.prepare(
				"INSERT OR REPLACE INTO events (event_id, room_id, stream_pos, event_json) VALUES (?, ?, ?, ?)",
			),
			getEvent: db.prepare(
				"SELECT event_id, event_json, rejected FROM events WHERE event_id = ?",
			),
			insertTimelineEntry: db.prepare(
				"INSERT OR REPLACE INTO events (event_id, room_id, stream_pos, event_json) VALUES (?, ?, ?, ?)",
			),
			getSession: db.prepare("SELECT * FROM sessions WHERE access_token = ?"),
			insertSession: db.prepare(
				"INSERT OR REPLACE INTO sessions (access_token, refresh_token, device_id, user_id, access_token_hash, expires_at, display_name, last_seen_ip, last_seen_ts, user_agent) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
			),
			insertStateEvent: db.prepare(
				"INSERT OR REPLACE INTO state_events (room_id, event_type, state_key, event_id, event_json) VALUES (?, ?, ?, ?, ?)",
			),
			getStateEvent: db.prepare(
				"SELECT event_id, event_json FROM state_events WHERE room_id = ? AND event_type = ? AND state_key = ?",
			),
			getTxn: db.prepare(
				"SELECT event_id FROM txn_map WHERE user_id = ? AND device_id = ? AND txn_id = ?",
			),
			setTxn: db.prepare(
				"INSERT OR REPLACE INTO txn_map (user_id, device_id, txn_id, event_id) VALUES (?, ?, ?, ?)",
			),
		};
	};

	const createUser = async (account: UserAccount): Promise<void> => {
		db.prepare(
			"INSERT OR REPLACE INTO users (user_id, localpart, server_name, password_hash, account_type, is_deactivated, created_at, displayname, avatar_url) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
		).run(
			account.user_id,
			account.localpart,
			account.server_name,
			account.password_hash,
			account.account_type,
			account.is_deactivated ? 1 : 0,
			account.created_at,
			account.displayname ?? null,
			account.avatar_url ?? null,
		);
	};

	const getUserByLocalpart = async (
		localpart: string,
	): Promise<UserAccount | undefined> => {
		const row = db
			.prepare("SELECT * FROM users WHERE localpart = ?")
			.get(localpart) as Record<string, unknown> | undefined;
		return row ? rowToUser(row, true) : undefined;
	};

	const getUserById = async (
		userId: UserId,
	): Promise<UserAccount | undefined> => {
		const row = db
			.prepare("SELECT * FROM users WHERE user_id = ?")
			.get(userId) as Record<string, unknown> | undefined;
		return row ? rowToUser(row, true) : undefined;
	};

	const createSession = async (session: StoredSession): Promise<void> => {
		insertSessionRow(session);
		// A new device/session was added: notify device-list subscribers.
		await recordDeviceKeyChange(session.user_id);
	};

	const insertSessionRow = (session: StoredSession): void => {
		stmts.insertSession.run(
			session.access_token,
			session.refresh_token ?? null,
			session.device_id,
			session.user_id,
			session.access_token_hash,
			session.expires_at ?? null,
			session.display_name ?? null,
			session.last_seen_ip ?? null,
			session.last_seen_ts ?? null,
			session.user_agent ?? null,
		);
	};

	const getSessionByAccessToken = async (
		token: AccessToken,
	): Promise<StoredSession | undefined> => {
		const row = stmts.getSession.get(token) as
			| Record<string, unknown>
			| undefined;
		return row ? rowToSession(row) : undefined;
	};

	const getSessionByRefreshToken = async (
		token: RefreshToken,
	): Promise<StoredSession | undefined> => {
		const row = db
			.prepare("SELECT * FROM sessions WHERE refresh_token = ?")
			.get(token) as Record<string, unknown> | undefined;
		return row ? rowToSession(row) : undefined;
	};

	const getSessionsByUser = async (
		userId: UserId,
	): Promise<StoredSession[]> => {
		const rows = db
			.prepare("SELECT * FROM sessions WHERE user_id = ?")
			.all(userId) as Record<string, unknown>[];
		return rows.map((r) => rowToSession(r));
	};

	const deleteSession = async (token: AccessToken): Promise<void> => {
		const session = await getSessionByAccessToken(token);
		db.prepare("DELETE FROM sessions WHERE access_token = ?").run(token);
		// A device/session was removed: notify device-list subscribers.
		if (session) {
			await recordDeviceKeyChange(session.user_id);
		}
	};

	const deleteAllSessions = async (userId: UserId): Promise<void> => {
		db.prepare("DELETE FROM sessions WHERE user_id = ?").run(userId);
		// Devices were removed: notify device-list subscribers.
		await recordDeviceKeyChange(userId);
	};

	const rotateToken = async (
		oldAccessToken: AccessToken,
		newAccessToken: AccessToken,
		newRefreshToken?: RefreshToken,
		expiresAt?: Timestamp,
	): Promise<StoredSession | undefined> => {
		const session = await getSessionByAccessToken(oldAccessToken);
		if (!session) return undefined;

		// Token rotation keeps the same device, so it must NOT signal a
		// device-list change. Use the raw row helpers, not the instrumented
		// deleteSession/createSession.
		db.prepare("DELETE FROM sessions WHERE access_token = ?").run(
			oldAccessToken,
		);

		const updated: StoredSession = {
			...session,
			access_token: newAccessToken,
			refresh_token: newRefreshToken,
			expires_at: expiresAt,
		};

		insertSessionRow(updated);
		return updated;
	};

	const touchSession = async (
		token: AccessToken,
		ip: string,
		userAgent: string,
	): Promise<void> => {
		db.prepare(
			"UPDATE sessions SET last_seen_ip = ?, last_seen_ts = ?, user_agent = ? WHERE access_token = ?",
		).run(ip, Date.now(), userAgent, token);
	};

	const createUIAASession = async (sessionId: string): Promise<void> => {
		db.prepare(
			"INSERT OR REPLACE INTO uiaa_sessions (session_id, completed) VALUES (?, '[]')",
		).run(sessionId);
	};

	const getUIAASession = async (
		sessionId: string,
	): Promise<{ completed: string[] } | undefined> => {
		const row = db
			.prepare("SELECT completed FROM uiaa_sessions WHERE session_id = ?")
			.get(sessionId) as { completed: string } | undefined;
		if (!row) return undefined;
		return { completed: JSON.parse(row.completed) };
	};

	const addUIAACompleted = async (
		sessionId: string,
		stageType: string,
	): Promise<void> => {
		const session = await getUIAASession(sessionId);
		if (!session) return;
		session.completed.push(stageType);
		db.prepare(
			"UPDATE uiaa_sessions SET completed = ? WHERE session_id = ?",
		).run(JSON.stringify(session.completed), sessionId);
	};

	const deleteUIAASession = async (sessionId: string): Promise<void> => {
		db.prepare("DELETE FROM uiaa_sessions WHERE session_id = ?").run(sessionId);
	};

	const createRoom = async (state: RoomState): Promise<void> => {
		db.prepare(
			"INSERT OR REPLACE INTO rooms (room_id, room_version, depth, forward_extremities) VALUES (?, ?, ?, ?)",
		).run(
			state.room_id,
			state.room_version,
			state.depth,
			JSON.stringify(state.forward_extremities),
		);

		for (const [key, event] of state.state_events) {
			const [eventType, stateKey] = key.split("\x1f") as [string, string];
			const eventId = computeEventId(event, state.room_version);
			stmts.insertStateEvent.run(
				state.room_id,
				eventType,
				stateKey,
				eventId,
				JSON.stringify(event),
			);
		}

		// Cache the reference so setStateEvent can mutate it in-place
		eph.roomCache.set(state.room_id, state);
	};

	const getRoom = async (roomId: RoomId): Promise<RoomState | undefined> => {
		// Return cached reference if available (needed for in-place mutation)
		const cached = eph.roomCache.get(roomId);
		if (cached) return cached;

		const row = db
			.prepare("SELECT * FROM rooms WHERE room_id = ?")
			.get(roomId) as Record<string, unknown> | undefined;
		if (!row) return undefined;

		const stateRows = db
			.prepare("SELECT * FROM state_events WHERE room_id = ?")
			.all(roomId) as {
			event_type: string;
			state_key: string;
			event_json: string;
		}[];

		const stateMap = new Map<string, PDU>();
		for (const sr of stateRows) {
			stateMap.set(
				`${sr.event_type}\x1f${sr.state_key}`,
				JSON.parse(sr.event_json),
			);
		}

		const room: RoomState = {
			room_id: row.room_id as RoomId,
			room_version: row.room_version as RoomVersion,
			state_events: stateMap,
			depth: row.depth as number,
			forward_extremities: JSON.parse(row.forward_extremities as string),
		};

		eph.roomCache.set(roomId, room);
		return room;
	};

	const getRoomsForUser = async (userId: UserId): Promise<RoomId[]> => {
		const rows = db
			.prepare(
				"SELECT room_id FROM state_events WHERE event_type = 'm.room.member' AND state_key = ? AND json_extract(event_json, '$.content.membership') = 'join'",
			)
			.all(userId) as { room_id: string }[];
		return rows.map((r) => r.room_id as RoomId);
	};

	const storeEvent = async (event: PDU, eventId: EventId): Promise<void> => {
		eph.streamCounter++;
		stmts.insertEvent.run(
			eventId,
			event.room_id,
			eph.streamCounter,
			JSON.stringify(event),
		);
		eph.wakeWaiters();
	};

	const updateEvent = async (eventId: EventId, event: PDU): Promise<void> => {
		db.prepare("UPDATE events SET event_json = ? WHERE event_id = ?").run(
			JSON.stringify(event),
			eventId,
		);
	};

	const getEvent = async (
		eventId: EventId,
	): Promise<
		{ event: PDU; eventId: EventId; rejected?: boolean } | undefined
	> => {
		const row = stmts.getEvent.get(eventId) as
			| { event_id: string; event_json: string; rejected?: number }
			| undefined;
		if (!row) return undefined;
		return {
			event: JSON.parse(row.event_json),
			eventId: row.event_id as EventId,
			rejected: !!row.rejected,
		};
	};

	const getEventsByRoom = async (
		roomId: RoomId,
		limit: number,
		from?: number,
		direction: "b" | "f" = "f",
	): Promise<{
		events: { event: PDU; eventId: EventId }[];
		end?: number;
	}> => {
		const fromPos = from ?? (direction === "f" ? 0 : eph.streamCounter + 1);

		let rows: { event_id: string; event_json: string; stream_pos: number }[];
		if (direction === "f") {
			rows = db
				.prepare(
					"SELECT event_id, event_json, stream_pos FROM events WHERE room_id = ? AND rejected = 0 AND stream_pos > ? ORDER BY stream_pos ASC LIMIT ?",
				)
				.all(roomId, fromPos, limit) as typeof rows;
		} else {
			rows = db
				.prepare(
					"SELECT event_id, event_json, stream_pos FROM events WHERE room_id = ? AND rejected = 0 AND stream_pos < ? ORDER BY stream_pos DESC LIMIT ?",
				)
				.all(roomId, fromPos, limit) as typeof rows;
		}

		const events = rows.map((r) => ({
			event: JSON.parse(r.event_json) as PDU,
			eventId: r.event_id as EventId,
		}));

		const lastRow = rows[rows.length - 1];
		const end = lastRow ? lastRow.stream_pos : undefined;
		return { events, end };
	};

	const getStreamPosition = async (): Promise<number> => {
		return eph.streamCounter;
	};

	const getStateEvent = async (
		roomId: RoomId,
		eventType: string,
		stateKey: string,
	): Promise<{ event: PDU; eventId: EventId } | undefined> => {
		const row = stmts.getStateEvent.get(roomId, eventType, stateKey) as
			| { event_id: string; event_json: string }
			| undefined;
		if (!row) return undefined;
		return {
			event: JSON.parse(row.event_json),
			eventId: row.event_id as EventId,
		};
	};

	const getAllState = async (
		roomId: RoomId,
	): Promise<{ event: PDU; eventId: EventId }[]> => {
		const rows = db
			.prepare(
				"SELECT event_id, event_json FROM state_events WHERE room_id = ?",
			)
			.all(roomId) as { event_id: string; event_json: string }[];
		return rows.map((r) => ({
			event: JSON.parse(r.event_json),
			eventId: r.event_id as EventId,
		}));
	};

	const setStateEvent = async (
		roomId: RoomId,
		event: PDU,
		eventId: EventId,
	): Promise<void> => {
		// When this state event replaces a previous one of the same
		// (type, state_key), stamp the new event's unsigned with the prior
		// state per the spec: prev_content / prev_sender / replaces_state.
		// `unsigned` is excluded from content-hash / event-ID / signature
		// computation, so mutating it here is safe and does not alter eventId.
		// The mutated event is serialized into both the state_events row and the
		// events row (via storeEvent), so the unsigned fields are persisted.
		const previousRow = stmts.getStateEvent.get(
			roomId,
			event.type,
			event.state_key ?? "",
		) as { event_id: string; event_json: string } | undefined;
		if (previousRow && previousRow.event_id !== eventId) {
			const previous = JSON.parse(previousRow.event_json) as PDU;
			event.unsigned = {
				...(event.unsigned ?? {}),
				prev_content: previous.content,
				prev_sender: previous.sender,
				replaces_state: previousRow.event_id as EventId,
			};
		}

		stmts.insertStateEvent.run(
			roomId,
			event.type,
			event.state_key ?? "",
			eventId,
			JSON.stringify(event),
		);

		// Update cached room state in-place (handler relies on reference sharing)
		const cached = eph.roomCache.get(roomId);
		if (cached) {
			const key = `${event.type}\x1f${event.state_key ?? ""}`;
			cached.state_events.set(key, event);
		}

		await storeEvent(event, eventId);
	};

	const getMemberEvents = async (
		roomId: RoomId,
	): Promise<{ event: PDU; eventId: EventId }[]> => {
		const rows = db
			.prepare(
				"SELECT event_id, event_json FROM state_events WHERE room_id = ? AND event_type = 'm.room.member'",
			)
			.all(roomId) as { event_id: string; event_json: string }[];
		return rows.map((r) => ({
			event: JSON.parse(r.event_json),
			eventId: r.event_id as EventId,
		}));
	};

	const getTxnEventId = async (
		userId: UserId,
		deviceId: DeviceId,
		txnId: string,
	): Promise<EventId | undefined> => {
		const row = stmts.getTxn.get(userId, deviceId, txnId) as
			| { event_id: string }
			| undefined;
		return row ? (row.event_id as EventId) : undefined;
	};

	const setTxnEventId = async (
		userId: UserId,
		deviceId: DeviceId,
		txnId: string,
		eventId: EventId,
	): Promise<void> => {
		stmts.setTxn.run(userId, deviceId, txnId, eventId);
	};

	const getRoomsForUserWithMembership = async (
		userId: UserId,
	): Promise<{ roomId: RoomId; membership: string }[]> => {
		const rows = db
			.prepare(
				"SELECT room_id, json_extract(event_json, '$.content.membership') as membership FROM state_events WHERE event_type = 'm.room.member' AND state_key = ?",
			)
			.all(userId) as { room_id: string; membership: string }[];
		return rows
			.filter((r) => r.membership)
			.map((r) => ({ roomId: r.room_id as RoomId, membership: r.membership }));
	};

	const getEventsByRoomSince = async (
		roomId: RoomId,
		since: number,
		limit: number,
	): Promise<{
		events: { event: PDU; eventId: EventId; streamPos: number }[];
		limited: boolean;
	}> => {
		const countRow = db
			.prepare(
				"SELECT COUNT(*) as cnt FROM events WHERE room_id = ? AND rejected = 0 AND stream_pos > ?",
			)
			.get(roomId, since) as { cnt: number };
		const total = countRow.cnt;
		const limited = total > limit;

		// When limited, take the most recent events (tail)
		let rows: { event_id: string; event_json: string; stream_pos: number }[];
		if (limited) {
			rows = db
				.prepare(
					"SELECT event_id, event_json, stream_pos FROM events WHERE room_id = ? AND rejected = 0 AND stream_pos > ? ORDER BY stream_pos DESC LIMIT ?",
				)
				.all(roomId, since, limit) as typeof rows;
			rows.reverse();
		} else {
			rows = db
				.prepare(
					"SELECT event_id, event_json, stream_pos FROM events WHERE room_id = ? AND rejected = 0 AND stream_pos > ? ORDER BY stream_pos ASC",
				)
				.all(roomId, since) as typeof rows;
		}

		const events = rows.map((r) => ({
			event: JSON.parse(r.event_json) as PDU,
			eventId: r.event_id as EventId,
			streamPos: r.stream_pos,
		}));

		return { events, limited };
	};

	const getStrippedState = async (
		roomId: RoomId,
	): Promise<StrippedStateEvent[]> => {
		const placeholders = INVITE_STATE_TYPES.map(() => "?").join(",");
		const rows = db
			.prepare(
				`SELECT event_json FROM state_events WHERE room_id = ? AND event_type IN (${placeholders})`,
			)
			.all(roomId, ...INVITE_STATE_TYPES) as { event_json: string }[];

		return rows.map((r) => {
			const event = JSON.parse(r.event_json) as PDU;
			return eventToStrippedState(event);
		});
	};

	const getProfile = async (
		userId: UserId,
	): Promise<UserProfile | undefined> => {
		const row = db
			.prepare("SELECT displayname, avatar_url FROM users WHERE user_id = ?")
			.get(userId) as
			| { displayname: string | null; avatar_url: string | null }
			| undefined;
		if (!row) return undefined;
		const profile: UserProfile = {};
		if (row.displayname) profile.displayname = row.displayname;
		if (row.avatar_url) profile.avatar_url = row.avatar_url;
		return profile;
	};

	const setDisplayName = async (
		userId: UserId,
		displayname: string | null,
	): Promise<void> => {
		db.prepare("UPDATE users SET displayname = ? WHERE user_id = ?").run(
			displayname,
			userId,
		);
	};

	const setAvatarUrl = async (
		userId: UserId,
		avatarUrl: string | null,
	): Promise<void> => {
		db.prepare("UPDATE users SET avatar_url = ? WHERE user_id = ?").run(
			avatarUrl,
			userId,
		);
	};

	const getDevice = async (
		userId: UserId,
		deviceId: DeviceId,
	): Promise<Device | undefined> => {
		const row = db
			.prepare(
				"SELECT device_id, display_name, last_seen_ip, last_seen_ts FROM sessions WHERE user_id = ? AND device_id = ? LIMIT 1",
			)
			.get(userId, deviceId) as Record<string, unknown> | undefined;
		if (!row) return undefined;
		return {
			device_id: row.device_id as DeviceId,
			display_name: (row.display_name as string) ?? undefined,
			last_seen_ip: (row.last_seen_ip as string) ?? undefined,
			last_seen_ts: (row.last_seen_ts as number) ?? undefined,
		};
	};

	const getAllDevices = async (userId: UserId): Promise<Device[]> => {
		const rows = db
			.prepare(
				"SELECT DISTINCT device_id, display_name, last_seen_ip, last_seen_ts FROM sessions WHERE user_id = ?",
			)
			.all(userId) as Record<string, unknown>[];
		return rows.map((r) => ({
			device_id: r.device_id as DeviceId,
			display_name: (r.display_name as string) ?? undefined,
			last_seen_ip: (r.last_seen_ip as string) ?? undefined,
			last_seen_ts: (r.last_seen_ts as number) ?? undefined,
		}));
	};

	const updateDeviceDisplayName = async (
		userId: UserId,
		deviceId: DeviceId,
		displayName: string,
	): Promise<void> => {
		db.prepare(
			"UPDATE sessions SET display_name = ? WHERE user_id = ? AND device_id = ?",
		).run(displayName, userId, deviceId);
		// A device's display name changed: notify device-list subscribers.
		// Mirrors Synapse's DeviceHandler, where update_device (display-name
		// change) calls notify_device_update so local /sync device_lists.changed
		// and /keys/changes, plus federated m.device_list_update, pick up the
		// change.
		await recordDeviceKeyChange(userId);
	};

	const deleteDeviceSession = async (
		userId: UserId,
		deviceId: DeviceId,
	): Promise<void> => {
		db.prepare("DELETE FROM sessions WHERE user_id = ? AND device_id = ?").run(
			userId,
			deviceId,
		);
		// A device was removed: notify device-list subscribers.
		await recordDeviceKeyChange(userId);
	};

	const updatePassword = async (
		userId: UserId,
		newPasswordHash: string,
	): Promise<void> => {
		db.prepare("UPDATE users SET password_hash = ? WHERE user_id = ?").run(
			newPasswordHash,
			userId,
		);
	};

	const deactivateUser = async (userId: UserId): Promise<void> => {
		db.prepare("UPDATE users SET is_deactivated = 1 WHERE user_id = ?").run(
			userId,
		);
		await deleteAllSessions(userId);
	};

	const createRoomAlias = async (
		roomAlias: RoomAlias,
		roomId: RoomId,
		servers: ServerName[],
		creator: UserId,
	): Promise<void> => {
		db.prepare(
			"INSERT OR REPLACE INTO room_aliases (room_alias, room_id, servers, creator) VALUES (?, ?, ?, ?)",
		).run(roomAlias, roomId, JSON.stringify(servers), creator);
	};

	const deleteRoomAlias = async (roomAlias: RoomAlias): Promise<boolean> => {
		const result = db
			.prepare("DELETE FROM room_aliases WHERE room_alias = ?")
			.run(roomAlias);
		return result.changes > 0;
	};

	const getRoomByAlias = async (
		roomAlias: RoomAlias,
	): Promise<{ room_id: RoomId; servers: ServerName[] } | undefined> => {
		const row = db
			.prepare("SELECT room_id, servers FROM room_aliases WHERE room_alias = ?")
			.get(roomAlias) as { room_id: string; servers: string } | undefined;
		if (!row) return undefined;
		return {
			room_id: row.room_id as RoomId,
			servers: JSON.parse(row.servers),
		};
	};

	const getAliasesForRoom = async (roomId: RoomId): Promise<RoomAlias[]> => {
		const rows = db
			.prepare("SELECT room_alias FROM room_aliases WHERE room_id = ?")
			.all(roomId) as { room_alias: string }[];
		return rows.map((r) => r.room_alias as RoomAlias);
	};

	const getAliasCreator = async (
		roomAlias: RoomAlias,
	): Promise<UserId | undefined> => {
		const row = db
			.prepare("SELECT creator FROM room_aliases WHERE room_alias = ?")
			.get(roomAlias) as { creator: string } | undefined;
		return row ? (row.creator as UserId) : undefined;
	};

	const setRoomVisibility = async (
		roomId: RoomId,
		visibility: "public" | "private",
	): Promise<void> => {
		db.prepare(
			"INSERT OR REPLACE INTO room_directory (room_id, visibility) VALUES (?, ?)",
		).run(roomId, visibility);
	};

	const getRoomVisibility = async (
		roomId: RoomId,
	): Promise<"public" | "private"> => {
		const row = db
			.prepare("SELECT visibility FROM room_directory WHERE room_id = ?")
			.get(roomId) as { visibility: string } | undefined;
		return (row?.visibility as "public" | "private") ?? "private";
	};

	const getPublicRoomIds = async (): Promise<RoomId[]> => {
		const rows = db
			.prepare("SELECT room_id FROM room_directory WHERE visibility = 'public'")
			.all() as { room_id: string }[];
		return rows.map((r) => r.room_id as RoomId);
	};

	const getGlobalAccountData = async (
		userId: UserId,
		type: string,
	): Promise<JsonObject | undefined> => {
		const row = db
			.prepare(
				"SELECT content FROM global_account_data WHERE user_id = ? AND type = ?",
			)
			.get(userId, type) as { content: string } | undefined;
		return row ? JSON.parse(row.content) : undefined;
	};

	const setGlobalAccountData = async (
		userId: UserId,
		type: string,
		content: JsonObject,
	): Promise<void> => {
		db.prepare(
			"INSERT OR REPLACE INTO global_account_data (user_id, type, content, stream_pos) VALUES (?, ?, ?, ?)",
		).run(userId, type, JSON.stringify(content), ++eph.streamCounter);
		eph.wakeWaiters();
	};

	const getAllGlobalAccountData = async (
		userId: UserId,
	): Promise<{ type: string; content: JsonObject }[]> => {
		const rows = db
			.prepare(
				// Exclude MSC3391 deletion tombstones (content '{}') from initial sync.
				"SELECT type, content FROM global_account_data WHERE user_id = ? AND content != '{}'",
			)
			.all(userId) as { type: string; content: string }[];
		return rows.map((r) => ({ type: r.type, content: JSON.parse(r.content) }));
	};

	const getGlobalAccountDataSince = async (
		userId: UserId,
		since: number,
	): Promise<{ type: string; content: JsonObject }[]> => {
		const rows = db
			.prepare(
				// Include tombstones so incremental sync surfaces deletions.
				"SELECT type, content FROM global_account_data WHERE user_id = ? AND stream_pos > ?",
			)
			.all(userId, since) as { type: string; content: string }[];
		return rows.map((r) => ({ type: r.type, content: JSON.parse(r.content) }));
	};

	const getRoomAccountData = async (
		userId: UserId,
		roomId: RoomId,
		type: string,
	): Promise<JsonObject | undefined> => {
		const row = db
			.prepare(
				"SELECT content FROM room_account_data WHERE user_id = ? AND room_id = ? AND type = ?",
			)
			.get(userId, roomId, type) as { content: string } | undefined;
		return row ? JSON.parse(row.content) : undefined;
	};

	const setRoomAccountData = async (
		userId: UserId,
		roomId: RoomId,
		type: string,
		content: JsonObject,
	): Promise<void> => {
		db.prepare(
			"INSERT OR REPLACE INTO room_account_data (user_id, room_id, type, content, stream_pos) VALUES (?, ?, ?, ?, ?)",
		).run(userId, roomId, type, JSON.stringify(content), ++eph.streamCounter);
		eph.wakeWaiters();
	};
	const deleteGlobalAccountData = async (
		userId: UserId,
		type: string,
	): Promise<void> => {
		// MSC3391: leave a tombstone (content '{}') with a fresh stream position
		// rather than removing the row, so incremental sync can surface it.
		db.prepare(
			"INSERT OR REPLACE INTO global_account_data (user_id, type, content, stream_pos) VALUES (?, ?, '{}', ?)",
		).run(userId, type, ++eph.streamCounter);
		eph.wakeWaiters();
	};
	const deleteRoomAccountData = async (
		userId: UserId,
		roomId: RoomId,
		type: string,
	): Promise<void> => {
		db.prepare(
			"INSERT OR REPLACE INTO room_account_data (user_id, room_id, type, content, stream_pos) VALUES (?, ?, ?, '{}', ?)",
		).run(userId, roomId, type, ++eph.streamCounter);
		eph.wakeWaiters();
	};

	const getAllRoomAccountData = async (
		userId: UserId,
		roomId: RoomId,
	): Promise<{ type: string; content: JsonObject }[]> => {
		const rows = db
			.prepare(
				// Exclude MSC3391 deletion tombstones from initial sync.
				"SELECT type, content FROM room_account_data WHERE user_id = ? AND room_id = ? AND content != '{}'",
			)
			.all(userId, roomId) as { type: string; content: string }[];
		return rows.map((r) => ({ type: r.type, content: JSON.parse(r.content) }));
	};

	const getRoomAccountDataSince = async (
		userId: UserId,
		since: number,
	): Promise<{ roomId: RoomId; type: string; content: JsonObject }[]> => {
		const rows = db
			.prepare(
				// Include tombstones so incremental sync surfaces deletions.
				"SELECT room_id, type, content FROM room_account_data WHERE user_id = ? AND stream_pos > ?",
			)
			.all(userId, since) as {
			room_id: string;
			type: string;
			content: string;
		}[];
		return rows.map((r) => ({
			roomId: r.room_id as RoomId,
			type: r.type,
			content: JSON.parse(r.content),
		}));
	};

	const setReceipt = async (
		roomId: RoomId,
		userId: UserId,
		eventId: EventId,
		receiptType: string,
		ts: Timestamp,
		threadId?: string,
	): Promise<void> => {
		db.prepare(
			"INSERT OR REPLACE INTO receipts (room_id, user_id, event_id, receipt_type, ts, thread_id) VALUES (?, ?, ?, ?, ?, ?)",
		).run(roomId, userId, eventId, receiptType, ts, threadId ?? "");
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
		const rows = db
			.prepare("SELECT * FROM receipts WHERE room_id = ?")
			.all(roomId) as {
			event_id: string;
			receipt_type: string;
			user_id: string;
			ts: number;
			thread_id: string | null;
		}[];
		return collapseReceiptsMsc4102(
			rows.map((r) => ({
				eventId: r.event_id as EventId,
				receiptType: r.receipt_type,
				userId: r.user_id as UserId,
				ts: r.ts,
				threadId:
					r.thread_id === null || r.thread_id === "" ? undefined : r.thread_id,
			})),
		);
	};

	const storeMedia = async (
		media: StoredMedia,
		data: Buffer,
	): Promise<void> => {
		db.prepare(
			"INSERT OR REPLACE INTO media (origin, media_id, user_id, content_type, upload_name, file_size, content_hash, created_at, quarantined, data) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
		).run(
			media.origin,
			media.media_id,
			media.user_id ?? null,
			media.content_type,
			media.upload_name ?? null,
			media.file_size,
			media.content_hash,
			media.created_at,
			media.quarantined ? 1 : 0,
			data,
		);
	};

	const getMedia = async (
		serverName: ServerName,
		mediaId: string,
	): Promise<{ metadata: StoredMedia; data: Buffer } | undefined> => {
		const row = db
			.prepare("SELECT * FROM media WHERE origin = ? AND media_id = ?")
			.get(serverName, mediaId) as Record<string, unknown> | undefined;
		if (!row) return undefined;
		return {
			metadata: rowToStoredMedia(row, true),
			data: row.data as Buffer,
		};
	};

	const reserveMedia = async (media: StoredMedia): Promise<void> => {
		await storeMedia(media, Buffer.alloc(0));
	};

	const updateMediaContent = async (
		serverName: ServerName,
		mediaId: string,
		contentType: string,
		fileName: string | undefined,
		data: Buffer,
	): Promise<boolean> => {
		const existing = await getMedia(serverName, mediaId);
		if (!existing) return false;
		const { createHash } = await import("node:crypto");
		const hash = createHash("sha256").update(data).digest("base64");
		db.prepare(
			"UPDATE media SET content_type = ?, upload_name = ?, file_size = ?, content_hash = ?, data = ? WHERE origin = ? AND media_id = ?",
		).run(
			contentType,
			fileName ?? null,
			data.length,
			hash,
			data,
			serverName,
			mediaId,
		);
		return true;
	};

	const createFilter = async (
		userId: UserId,
		filter: JsonObject,
	): Promise<string> => {
		const filterId = String(++eph.filterCounter);
		db.prepare(
			"INSERT OR REPLACE INTO filters (user_id, filter_id, filter_json) VALUES (?, ?, ?)",
		).run(userId, filterId, JSON.stringify(filter));
		return filterId;
	};

	const getFilter = async (
		userId: UserId,
		filterId: string,
	): Promise<JsonObject | undefined> => {
		const row = db
			.prepare(
				"SELECT filter_json FROM filters WHERE user_id = ? AND filter_id = ?",
			)
			.get(userId, filterId) as { filter_json: string } | undefined;
		return row ? JSON.parse(row.filter_json) : undefined;
	};

	const setDeviceKeys = async (
		userId: UserId,
		deviceId: DeviceId,
		keys: DeviceKeys,
	): Promise<void> => {
		db.prepare(
			"INSERT OR REPLACE INTO device_keys (user_id, device_id, keys_json) VALUES (?, ?, ?)",
		).run(userId, deviceId, JSON.stringify(keys));
		await recordDeviceKeyChange(userId);
	};

	const recordDeviceKeyChange = async (userId: UserId): Promise<void> => {
		db.prepare(
			"INSERT INTO device_list_stream (user_id, stream_pos) VALUES (?, ?)",
		).run(userId, ++eph.streamCounter);
		eph.wakeWaiters();
	};

	const getChangedDeviceUsers = async (
		since: number,
		until: number,
	): Promise<UserId[]> => {
		const rows = db
			.prepare(
				"SELECT DISTINCT user_id FROM device_list_stream WHERE stream_pos > ? AND stream_pos <= ?",
			)
			.all(since, until) as { user_id: string }[];
		return rows.map((r) => r.user_id as UserId);
	};

	const getDeviceKeys = async (
		userId: UserId,
		deviceId: DeviceId,
	): Promise<DeviceKeys | undefined> => {
		const row = db
			.prepare(
				"SELECT keys_json FROM device_keys WHERE user_id = ? AND device_id = ?",
			)
			.get(userId, deviceId) as { keys_json: string } | undefined;
		return row ? JSON.parse(row.keys_json) : undefined;
	};

	const getAllDeviceKeys = async (
		userId: UserId,
	): Promise<Record<DeviceId, DeviceKeys>> => {
		const rows = db
			.prepare("SELECT device_id, keys_json FROM device_keys WHERE user_id = ?")
			.all(userId) as { device_id: string; keys_json: string }[];
		const result: Record<DeviceId, DeviceKeys> = {};
		for (const r of rows) {
			result[r.device_id as DeviceId] = JSON.parse(r.keys_json);
		}
		return result;
	};

	const deleteDeviceKeys = async (userId: UserId): Promise<void> => {
		db.prepare("DELETE FROM device_keys WHERE user_id = ?").run(userId);
	};

	const addOneTimeKeys = async (
		userId: UserId,
		deviceId: DeviceId,
		keys: Record<KeyId, string | OneTimeKey>,
	): Promise<void> => {
		const stmt = db.prepare(
			"INSERT OR REPLACE INTO one_time_keys (user_id, device_id, key_id, algorithm, key_json) VALUES (?, ?, ?, ?, ?)",
		);
		const insertAll = db.transaction(() => {
			for (const [keyId, key] of Object.entries(keys)) {
				const algorithm = keyId.split(":")[0] as string;
				stmt.run(userId, deviceId, keyId, algorithm, JSON.stringify(key));
			}
		});
		insertAll();
	};

	const claimOneTimeKey = async (
		userId: UserId,
		deviceId: DeviceId,
		algorithm: string,
	): Promise<{ keyId: KeyId; key: string | OneTimeKey } | undefined> => {
		const row = db
			.prepare(
				"SELECT key_id, key_json FROM one_time_keys WHERE user_id = ? AND device_id = ? AND algorithm = ? ORDER BY rowid ASC LIMIT 1",
			)
			.get(userId, deviceId, algorithm) as
			| { key_id: string; key_json: string }
			| undefined;

		if (row) {
			db.prepare(
				"DELETE FROM one_time_keys WHERE user_id = ? AND device_id = ? AND key_id = ?",
			).run(userId, deviceId, row.key_id);
			return { keyId: row.key_id as KeyId, key: JSON.parse(row.key_json) };
		}

		// Fall back to fallback keys
		const fallback = db
			.prepare(
				"SELECT key_id, key_json FROM fallback_keys WHERE user_id = ? AND device_id = ? AND key_id LIKE ? LIMIT 1",
			)
			.get(userId, deviceId, `${algorithm}:%`) as
			| { key_id: string; key_json: string }
			| undefined;

		if (fallback) {
			return {
				keyId: fallback.key_id as KeyId,
				key: JSON.parse(fallback.key_json),
			};
		}

		return undefined;
	};

	const getOneTimeKeyCounts = async (
		userId: UserId,
		deviceId: DeviceId,
	): Promise<Record<string, number>> => {
		const rows = db
			.prepare(
				"SELECT algorithm, COUNT(*) as cnt FROM one_time_keys WHERE user_id = ? AND device_id = ? GROUP BY algorithm",
			)
			.all(userId, deviceId) as { algorithm: string; cnt: number }[];
		const counts: Record<string, number> = {};
		for (const r of rows) {
			counts[r.algorithm] = r.cnt;
		}
		return counts;
	};

	const setFallbackKeys = async (
		userId: UserId,
		deviceId: DeviceId,
		keys: Record<KeyId, string | OneTimeKey>,
	): Promise<void> => {
		const del = db.prepare(
			"DELETE FROM fallback_keys WHERE user_id = ? AND device_id = ?",
		);
		const ins = db.prepare(
			"INSERT INTO fallback_keys (user_id, device_id, key_id, key_json) VALUES (?, ?, ?, ?)",
		);
		db.transaction(() => {
			del.run(userId, deviceId);
			for (const [keyId, key] of Object.entries(keys)) {
				ins.run(userId, deviceId, keyId, JSON.stringify(key));
			}
		})();
	};

	const getFallbackKeyTypes = async (
		userId: UserId,
		deviceId: DeviceId,
	): Promise<string[]> => {
		const rows = db
			.prepare(
				"SELECT DISTINCT key_id FROM fallback_keys WHERE user_id = ? AND device_id = ?",
			)
			.all(userId, deviceId) as { key_id: string }[];
		const types = new Set<string>();
		for (const r of rows) {
			types.add(r.key_id.split(":")[0] as string);
		}
		return [...types];
	};

	const setCrossSigningKeys = async (
		userId: UserId,
		keys: {
			master_key?: CrossSigningKey;
			self_signing_key?: CrossSigningKey;
			user_signing_key?: CrossSigningKey;
		},
	): Promise<void> => {
		const stmt = db.prepare(
			"INSERT OR REPLACE INTO cross_signing_keys (user_id, key_type, key_json) VALUES (?, ?, ?)",
		);
		db.transaction(() => {
			if (keys.master_key)
				stmt.run(userId, "master_key", JSON.stringify(keys.master_key));
			if (keys.self_signing_key)
				stmt.run(
					userId,
					"self_signing_key",
					JSON.stringify(keys.self_signing_key),
				);
			if (keys.user_signing_key)
				stmt.run(
					userId,
					"user_signing_key",
					JSON.stringify(keys.user_signing_key),
				);
		})();
	};

	const getCrossSigningKeys = async (
		userId: UserId,
	): Promise<{
		master_key?: CrossSigningKey;
		self_signing_key?: CrossSigningKey;
		user_signing_key?: CrossSigningKey;
	}> => {
		const rows = db
			.prepare(
				"SELECT key_type, key_json FROM cross_signing_keys WHERE user_id = ?",
			)
			.all(userId) as { key_type: string; key_json: string }[];
		return rowsToCrossSigningKeys(rows, (j) => JSON.parse(j as string));
	};

	const storeCrossSigningSignatures = async (
		_userId: UserId,
		signatures: Record<string, Record<string, JsonObject>>,
	): Promise<
		Record<string, Record<string, { errcode: string; error: string }>>
	> => {
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

				// Try updating device keys
				const dkRow = db
					.prepare(
						"SELECT keys_json FROM device_keys WHERE user_id = ? AND device_id = ?",
					)
					.get(targetUserId, keyId) as { keys_json: string } | undefined;
				if (dkRow) {
					const deviceKeys = JSON.parse(dkRow.keys_json) as DeviceKeys;
					if (!deviceKeys.signatures) deviceKeys.signatures = {};
					for (const [signer, sigs] of Object.entries(signedSigs)) {
						deviceKeys.signatures[signer] ??= {};
						Object.assign(
							deviceKeys.signatures[signer] as Record<string, string>,
							sigs,
						);
					}
					db.prepare(
						"UPDATE device_keys SET keys_json = ? WHERE user_id = ? AND device_id = ?",
					).run(JSON.stringify(deviceKeys), targetUserId, keyId);
					continue;
				}

				// Try updating cross-signing keys
				const csRows = db
					.prepare(
						"SELECT key_type, key_json FROM cross_signing_keys WHERE user_id = ?",
					)
					.all(targetUserId) as {
					key_type: string;
					key_json: string;
				}[];
				let matched = false;
				for (const csRow of csRows) {
					const key = JSON.parse(csRow.key_json) as CrossSigningKey;
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
						db.prepare(
							"UPDATE cross_signing_keys SET key_json = ? WHERE user_id = ? AND key_type = ?",
						).run(JSON.stringify(key), targetUserId, csRow.key_type);
						matched = true;
						break;
					}
				}
				if (matched) continue;

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

	const createKeyBackupVersion = async (
		userId: UserId,
		algorithm: string,
		authData: JsonObject,
	): Promise<string> => {
		const result = db
			.prepare(
				"INSERT INTO key_backup_versions (user_id, version, algorithm, auth_data) VALUES (?, (SELECT COALESCE(MAX(CAST(version AS INTEGER)), 0) + 1 FROM key_backup_versions WHERE user_id = ?), ?, ?)",
			)
			.run(userId, userId, algorithm, JSON.stringify(authData));
		// Get the version we just inserted
		const row = db
			.prepare("SELECT version FROM key_backup_versions WHERE rowid = ?")
			.get(result.lastInsertRowid) as { version: string };
		return row.version;
	};

	const keyBackupEtagFor = (userId: string, version: string): string =>
		keyBackupEtag(
			db
				.prepare(
					"SELECT room_id, session_id FROM key_backup_data WHERE user_id = ? AND version = ?",
				)
				.all(userId, version) as Record<string, unknown>[],
		);

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
		let row:
			| { version: string; algorithm: string; auth_data: string }
			| undefined;
		if (version) {
			row = db
				.prepare(
					"SELECT version, algorithm, auth_data FROM key_backup_versions WHERE user_id = ? AND version = ?",
				)
				.get(userId, version) as typeof row;
		} else {
			row = db
				.prepare(
					"SELECT version, algorithm, auth_data FROM key_backup_versions WHERE user_id = ? ORDER BY CAST(version AS INTEGER) DESC LIMIT 1",
				)
				.get(userId) as typeof row;
		}
		if (!row) return undefined;

		const countRow = db
			.prepare(
				"SELECT COUNT(*) as c FROM key_backup_data WHERE user_id = ? AND version = ?",
			)
			.get(userId, row.version) as { c: number };

		return {
			version: row.version,
			algorithm: row.algorithm,
			auth_data: JSON.parse(row.auth_data),
			count: countRow.c,
			etag: keyBackupEtagFor(userId, row.version),
		};
	};

	const updateKeyBackupVersion = async (
		userId: UserId,
		version: string,
		authData: JsonObject,
	): Promise<boolean> => {
		const result = db
			.prepare(
				"UPDATE key_backup_versions SET auth_data = ? WHERE user_id = ? AND version = ?",
			)
			.run(JSON.stringify(authData), userId, version);
		return result.changes > 0;
	};

	const deleteKeyBackupVersion = async (
		userId: UserId,
		version: string,
	): Promise<boolean> => {
		const result = db
			.prepare(
				"DELETE FROM key_backup_versions WHERE user_id = ? AND version = ?",
			)
			.run(userId, version);
		if (result.changes === 0) return false;
		db.prepare(
			"DELETE FROM key_backup_data WHERE user_id = ? AND version = ?",
		).run(userId, version);
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
		// Verify version is current
		const latest = db
			.prepare(
				"SELECT version FROM key_backup_versions WHERE user_id = ? ORDER BY CAST(version AS INTEGER) DESC LIMIT 1",
			)
			.get(userId) as { version: string } | undefined;
		if (!latest || latest.version !== version) return undefined;

		const upsert = db.prepare(
			"INSERT OR REPLACE INTO key_backup_data (user_id, version, room_id, session_id, key_json) VALUES (?, ?, ?, ?, ?)",
		);

		const entries = flattenKeyBackupEntries(roomId, sessionId, keys);

		db.transaction(() => {
			for (const [rid, sid, data] of entries) {
				// Check merge logic
				const existing = db
					.prepare(
						"SELECT key_json FROM key_backup_data WHERE user_id = ? AND version = ? AND room_id = ? AND session_id = ?",
					)
					.get(userId, version, rid, sid) as { key_json: string } | undefined;
				const old = existing
					? (JSON.parse(existing.key_json) as KeyBackupData)
					: undefined;
				if (!old || shouldReplaceBackupKey(data, old)) {
					upsert.run(userId, version, rid, sid, JSON.stringify(data));
				}
			}
		})();

		const countRow = db
			.prepare(
				"SELECT COUNT(*) as c FROM key_backup_data WHERE user_id = ? AND version = ?",
			)
			.get(userId, version) as { c: number };
		return {
			count: countRow.c,
			etag: keyBackupEtagFor(userId, version),
		};
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
		if (roomId && sessionId) {
			const row = db
				.prepare(
					"SELECT key_json FROM key_backup_data WHERE user_id = ? AND version = ? AND room_id = ? AND session_id = ?",
				)
				.get(userId, version, roomId, sessionId) as
				| { key_json: string }
				| undefined;
			return row ? JSON.parse(row.key_json) : undefined;
		} else if (roomId) {
			const rows = db
				.prepare(
					"SELECT session_id, key_json FROM key_backup_data WHERE user_id = ? AND version = ? AND room_id = ?",
				)
				.all(userId, version, roomId) as {
				session_id: string;
				key_json: string;
			}[];
			const sessions: Record<string, KeyBackupData> = {};
			for (const row of rows)
				sessions[row.session_id] = JSON.parse(row.key_json);
			return { sessions };
		} else {
			const rows = db
				.prepare(
					"SELECT room_id, session_id, key_json FROM key_backup_data WHERE user_id = ? AND version = ?",
				)
				.all(userId, version) as {
				room_id: string;
				session_id: string;
				key_json: string;
			}[];
			const rooms: Record<RoomId, { sessions: Record<string, KeyBackupData> }> =
				{};
			for (const row of rows) {
				const rid = row.room_id as RoomId;
				if (!rooms[rid]) rooms[rid] = { sessions: {} };
				(
					rooms[rid] as {
						sessions: Record<string, KeyBackupData>;
					}
				).sessions[row.session_id] = JSON.parse(row.key_json);
			}
			return { rooms };
		}
	};

	const deleteKeyBackupKeys = async (
		userId: UserId,
		version: string,
		roomId?: RoomId,
		sessionId?: string,
	): Promise<{ count: number; etag: string } | undefined> => {
		const versionExists = db
			.prepare(
				"SELECT 1 FROM key_backup_versions WHERE user_id = ? AND version = ?",
			)
			.get(userId, version);
		if (!versionExists) return undefined;

		if (roomId && sessionId) {
			db.prepare(
				"DELETE FROM key_backup_data WHERE user_id = ? AND version = ? AND room_id = ? AND session_id = ?",
			).run(userId, version, roomId, sessionId);
		} else if (roomId) {
			db.prepare(
				"DELETE FROM key_backup_data WHERE user_id = ? AND version = ? AND room_id = ?",
			).run(userId, version, roomId);
		} else {
			db.prepare(
				"DELETE FROM key_backup_data WHERE user_id = ? AND version = ?",
			).run(userId, version);
		}

		const countRow = db
			.prepare(
				"SELECT COUNT(*) as c FROM key_backup_data WHERE user_id = ? AND version = ?",
			)
			.get(userId, version) as { c: number };
		return {
			count: countRow.c,
			etag: keyBackupEtagFor(userId, version),
		};
	};

	const sendToDevice = async (
		userId: UserId,
		deviceId: DeviceId,
		event: ToDeviceEvent,
	): Promise<void> => {
		db.prepare(
			"INSERT INTO to_device (user_id, device_id, event_json) VALUES (?, ?, ?)",
		).run(userId, deviceId, JSON.stringify(event));
		eph.wakeWaiters();
	};

	const getToDeviceMessages = async (
		userId: UserId,
		deviceId: DeviceId,
	): Promise<ToDeviceEvent[]> => {
		const rows = db
			.prepare(
				"SELECT event_json FROM to_device WHERE user_id = ? AND device_id = ? ORDER BY id",
			)
			.all(userId, deviceId) as { event_json: string }[];
		return rows.map((r) => JSON.parse(r.event_json));
	};

	const clearToDeviceMessages = async (
		userId: UserId,
		deviceId: DeviceId,
	): Promise<void> => {
		db.prepare("DELETE FROM to_device WHERE user_id = ? AND device_id = ?").run(
			userId,
			deviceId,
		);
	};

	const getPushers = async (userId: UserId): Promise<Pusher[]> => {
		const rows = db
			.prepare("SELECT pusher_json FROM pushers WHERE user_id = ?")
			.all(userId) as { pusher_json: string }[];
		return rows.map((r) => JSON.parse(r.pusher_json));
	};

	const setPusher = async (userId: UserId, pusher: Pusher): Promise<void> => {
		db.prepare(
			"INSERT OR REPLACE INTO pushers (user_id, app_id, pushkey, pusher_json) VALUES (?, ?, ?, ?)",
		).run(userId, pusher.app_id, pusher.pushkey, JSON.stringify(pusher));
	};

	const deletePusher = async (
		userId: UserId,
		appId: string,
		pushkey: string,
	): Promise<void> => {
		db.prepare(
			"DELETE FROM pushers WHERE user_id = ? AND app_id = ? AND pushkey = ?",
		).run(userId, appId, pushkey);
	};

	const deletePusherByKey = async (
		appId: string,
		pushkey: string,
	): Promise<void> => {
		db.prepare("DELETE FROM pushers WHERE app_id = ? AND pushkey = ?").run(
			appId,
			pushkey,
		);
	};

	const storeRelation = async (
		eventId: EventId,
		roomId: RoomId,
		relType: string,
		targetEventId: EventId,
		key?: string,
	): Promise<void> => {
		const eventRow = stmts.getEvent.get(eventId) as
			| { event_json: string }
			| undefined;
		if (!eventRow) return;
		const event = JSON.parse(eventRow.event_json) as PDU;

		const posRow = db
			.prepare("SELECT stream_pos FROM events WHERE event_id = ?")
			.get(eventId) as { stream_pos: number } | undefined;
		const streamPos = posRow?.stream_pos ?? eph.streamCounter;

		db.prepare(
			"INSERT INTO relations (event_id, room_id, rel_type, target_event_id, key, sender, event_type, stream_pos) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
		).run(
			eventId,
			roomId,
			relType,
			targetEventId,
			key ?? null,
			event.sender,
			event.type,
			streamPos,
		);
	};

	const getRelatedEvents = async (
		roomId: RoomId,
		eventId: EventId,
		relType?: string,
		eventType?: string,
		limit = 50,
		from?: string,
		direction: "b" | "f" = "f",
	): Promise<{
		events: { event: PDU; eventId: EventId }[];
		nextBatch?: string;
	}> => {
		let sql =
			"SELECT r.event_id, r.stream_pos, e.event_json FROM relations r JOIN events e ON r.event_id = e.event_id WHERE r.target_event_id = ? AND r.room_id = ?";
		const params: unknown[] = [eventId, roomId];

		if (relType) {
			sql += " AND r.rel_type = ?";
			params.push(relType);
		}
		if (eventType) {
			sql += " AND r.event_type = ?";
			params.push(eventType);
		}

		const fromPos = from ? parseInt(from, 10) : undefined;
		if (fromPos !== undefined) {
			if (direction === "f") {
				sql += " AND r.stream_pos > ?";
			} else {
				sql += " AND r.stream_pos < ?";
			}
			params.push(fromPos);
		}

		sql +=
			direction === "f"
				? " ORDER BY r.stream_pos ASC LIMIT ?"
				: " ORDER BY r.stream_pos DESC LIMIT ?";
		params.push(limit);

		const rows = db.prepare(sql).all(...params) as {
			event_id: string;
			stream_pos: number;
			event_json: string;
		}[];

		const events = rows.map((r) => ({
			event: JSON.parse(r.event_json) as PDU,
			eventId: r.event_id as EventId,
		}));

		const nextBatch =
			rows.length === limit && rows.length > 0
				? String(rows[rows.length - 1]?.stream_pos)
				: undefined;

		return { events, nextBatch };
	};

	const getAnnotationCounts = async (
		eventId: EventId,
	): Promise<{ type: string; key: string; count: number }[]> => {
		const rows = db
			.prepare(
				"SELECT event_type, key, COUNT(*) as cnt FROM relations WHERE target_event_id = ? AND rel_type = 'm.annotation' AND key IS NOT NULL GROUP BY event_type, key",
			)
			.all(eventId) as { event_type: string; key: string; cnt: number }[];
		return rows.map((r) => ({ type: r.event_type, key: r.key, count: r.cnt }));
	};

	const getLatestEdit = async (
		eventId: EventId,
		sender: UserId,
	): Promise<{ event: PDU; eventId: EventId } | undefined> => {
		const row = db
			.prepare(
				"SELECT r.event_id, e.event_json FROM relations r JOIN events e ON r.event_id = e.event_id WHERE r.target_event_id = ? AND r.rel_type = 'm.replace' AND r.sender = ? ORDER BY r.stream_pos DESC LIMIT 1",
			)
			.get(eventId, sender) as
			| { event_id: string; event_json: string }
			| undefined;
		if (!row) return undefined;
		return {
			event: JSON.parse(row.event_json),
			eventId: row.event_id as EventId,
		};
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
		const countRow = db
			.prepare(
				"SELECT COUNT(*) as cnt FROM relations WHERE target_event_id = ? AND rel_type = 'm.thread'",
			)
			.get(eventId) as { cnt: number };
		if (countRow.cnt === 0) return undefined;

		const latestRow = db
			.prepare(
				"SELECT r.event_id, e.event_json FROM relations r JOIN events e ON r.event_id = e.event_id WHERE r.target_event_id = ? AND r.rel_type = 'm.thread' ORDER BY r.stream_pos DESC LIMIT 1",
			)
			.get(eventId) as { event_id: string; event_json: string } | undefined;
		if (!latestRow) return undefined;

		const participatedRow = db
			.prepare(
				"SELECT 1 FROM relations WHERE target_event_id = ? AND rel_type = 'm.thread' AND sender = ? LIMIT 1",
			)
			.get(eventId, userId) as unknown | undefined;

		return {
			latestEvent: {
				event: JSON.parse(latestRow.event_json),
				eventId: latestRow.event_id as EventId,
			},
			count: countRow.cnt,
			currentUserParticipated: !!participatedRow,
		};
	};

	const storeReport = async (
		userId: UserId,
		roomId: RoomId,
		eventId: EventId,
		score?: number,
		reason?: string,
	): Promise<void> => {
		db.prepare(
			"INSERT INTO reports (user_id, room_id, event_id, score, reason, ts) VALUES (?, ?, ?, ?, ?, ?)",
		).run(userId, roomId, eventId, score ?? null, reason ?? null, Date.now());
	};

	const storeOpenIdToken = async (
		token: string,
		userId: UserId,
		expiresAt: Timestamp,
	): Promise<void> => {
		db.prepare(
			"INSERT OR REPLACE INTO openid_tokens (token, user_id, expires_at) VALUES (?, ?, ?)",
		).run(token, userId, expiresAt);
	};

	const getOpenIdToken = async (
		token: string,
	): Promise<{ userId: UserId; expiresAt: Timestamp } | undefined> => {
		const row = db
			.prepare("SELECT user_id, expires_at FROM openid_tokens WHERE token = ?")
			.get(token) as { user_id: string; expires_at: number } | undefined;
		if (!row) return undefined;
		return { userId: row.user_id as UserId, expiresAt: row.expires_at };
	};

	const getThreePids = async (
		userId: UserId,
	): Promise<{ medium: string; address: string; added_at: Timestamp }[]> => {
		return db
			.prepare(
				"SELECT medium, address, added_at FROM threepids WHERE user_id = ?",
			)
			.all(userId) as { medium: string; address: string; added_at: number }[];
	};

	const addThreePid = async (
		userId: UserId,
		medium: string,
		address: string,
	): Promise<void> => {
		db.prepare(
			"INSERT OR IGNORE INTO threepids (user_id, medium, address, added_at) VALUES (?, ?, ?, ?)",
		).run(userId, medium, address, Date.now());
	};

	const deleteThreePid = async (
		userId: UserId,
		medium: string,
		address: string,
	): Promise<void> => {
		db.prepare(
			"DELETE FROM threepids WHERE user_id = ? AND medium = ? AND address = ?",
		).run(userId, medium, address);
	};

	const searchUserDirectory = async (
		searchTerm: string,
		limit: number,
	): Promise<
		{ user_id: UserId; display_name?: string; avatar_url?: string }[]
	> => {
		const term = `%${searchTerm}%`;
		const rows = db
			.prepare(
				"SELECT user_id, displayname, avatar_url FROM users WHERE is_deactivated = 0 AND (user_id LIKE ? OR displayname LIKE ?) LIMIT ?",
			)
			.all(term, term, limit) as {
			user_id: string;
			displayname: string | null;
			avatar_url: string | null;
		}[];
		return rows.map((r) => ({
			user_id: r.user_id as UserId,
			display_name: r.displayname ?? undefined,
			avatar_url: r.avatar_url ?? undefined,
		}));
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
		let sql = `
			SELECT r.target_event_id, MAX(r.stream_pos) as latest_pos, e.event_json
			FROM relations r
			JOIN events e ON r.target_event_id = e.event_id
			WHERE r.rel_type = 'm.thread' AND r.room_id = ?
		`;
		const params: unknown[] = [roomId];

		if (include === "participated") {
			sql +=
				" AND r.target_event_id IN (SELECT target_event_id FROM relations WHERE rel_type = 'm.thread' AND sender = ?)";
			params.push(userId);
		}

		if (from) {
			sql += " AND r.stream_pos < ?";
			params.push(parseInt(from, 10));
		}

		sql += " GROUP BY r.target_event_id ORDER BY latest_pos DESC LIMIT ?";
		params.push(limit);

		const rows = db.prepare(sql).all(...params) as {
			target_event_id: string;
			latest_pos: number;
			event_json: string;
		}[];

		const events = rows.map((r) => ({
			event: JSON.parse(r.event_json) as PDU,
			eventId: r.target_event_id as EventId,
		}));

		const nextBatch =
			rows.length === limit && rows.length > 0
				? String(rows[rows.length - 1]?.latest_pos)
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
		if (roomIds.length === 0) return { events: [], count: 0 };

		const placeholders = roomIds.map(() => "?").join(",");
		const sql = `SELECT event_id, event_json, stream_pos FROM events WHERE room_id IN (${placeholders}) ORDER BY stream_pos DESC`;

		const rows = db.prepare(sql).all(...roomIds) as {
			event_id: string;
			event_json: string;
			stream_pos: number;
		}[];

		const allMatches: { event: PDU; eventId: EventId; streamPos: number }[] =
			[];
		for (const row of rows) {
			const event = JSON.parse(row.event_json) as PDU;
			if (eventMatchesSearchTerm(event, keys, searchTerm)) {
				allMatches.push({
					event,
					eventId: row.event_id as EventId,
					streamPos: row.stream_pos,
				});
			}
		}

		return paginateSearchMatches(allMatches, limit, from);
	};

	const storeServerKeys = async (
		serverName: ServerName,
		keys: ServerKeys,
	): Promise<void> => {
		const stmt = db.prepare(
			"INSERT OR REPLACE INTO server_keys (server_name, key_id, key, valid_until) VALUES (?, ?, ?, ?)",
		);
		db.transaction(() => {
			for (const [keyId, val] of Object.entries(keys.verify_keys)) {
				stmt.run(serverName, keyId, val.key, keys.valid_until_ts);
			}
		})();
	};

	const getServerKeys = async (
		serverName: ServerName,
		keyId: KeyId,
	): Promise<{ key: string; validUntil: number } | undefined> => {
		const row = db
			.prepare(
				"SELECT key, valid_until FROM server_keys WHERE server_name = ? AND key_id = ?",
			)
			.get(serverName, keyId) as
			| { key: string; valid_until: number }
			| undefined;
		if (!row) return undefined;
		return { key: row.key, validUntil: row.valid_until };
	};

	const getAuthChain = async (eventIds: EventId[]): Promise<PDU[]> => {
		const visited = new Set<EventId>();
		const result: PDU[] = [];
		const queue = [...eventIds];

		while (queue.length > 0) {
			const id = queue.shift() as EventId;
			if (visited.has(id)) continue;
			visited.add(id);

			const row = stmts.getEvent.get(id) as { event_json: string } | undefined;
			if (!row) continue;
			const event = JSON.parse(row.event_json) as PDU;
			result.push(event);

			for (const authId of event.auth_events) {
				if (!visited.has(authId)) queue.push(authId);
			}
		}

		return result;
	};

	const getServersInRoom = async (roomId: RoomId): Promise<ServerName[]> => {
		// Include servers of any join/invite/knock member so that federation
		// fanout reaches invited and knocking participants.
		const rows = db
			.prepare(
				"SELECT state_key FROM state_events WHERE room_id = ? AND event_type = 'm.room.member' AND json_extract(event_json, '$.content.membership') IN ('join', 'invite', 'knock')",
			)
			.all(roomId) as { state_key: string }[];

		const servers = new Set<ServerName>();
		for (const r of rows) {
			const serverName = r.state_key
				.split(":")
				.slice(1)
				.join(":") as ServerName;
			servers.add(serverName);
		}
		// While partial-state, the omitted member events hide most of the room's
		// servers; include the servers_in_room recorded at join so federation
		// fanout still reaches them.
		const ps = db
			.prepare("SELECT servers FROM partial_state_rooms WHERE room_id = ?")
			.get(roomId) as { servers: string } | undefined;
		if (ps)
			for (const s of JSON.parse(ps.servers) as ServerName[]) servers.add(s);
		return [...servers];
	};

	const partialStateWaiters = new Map<string, Set<() => void>>();
	const unPartialStatedAt = new Map<string, number>();
	let historicalPos = -1;

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
		const pos = historicalPos--;
		stmts.insertEvent.run(
			eventId,
			event.room_id ?? roomId,
			pos,
			JSON.stringify(event),
		);
		stmts.insertStateEvent.run(
			roomId,
			event.type,
			event.state_key ?? "",
			eventId,
			JSON.stringify(event),
		);
		const cached = eph.roomCache.get(roomId);
		if (cached) {
			cached.state_events.set(
				`${event.type}\x1f${event.state_key ?? ""}`,
				event,
			);
		}
	};

	const markRoomPartialState = async (
		roomId: RoomId,
		servers: ServerName[],
		joinEventId: EventId,
	): Promise<void> => {
		db.prepare(
			"INSERT OR REPLACE INTO partial_state_rooms (room_id, servers, join_event_id) VALUES (?, ?, ?)",
		).run(roomId, JSON.stringify(servers), joinEventId);
	};

	const clearRoomPartialState = async (roomId: RoomId): Promise<void> => {
		db.prepare("DELETE FROM partial_state_rooms WHERE room_id = ?").run(roomId);
		// Un-partial-stating is a sync-relevant change: advance the stream so an
		// incremental /sync taken before the resync sees the room now (with its
		// newly-known state) and long-polls wake.
		eph.streamCounter++;
		unPartialStatedAt.set(roomId, eph.streamCounter);
		const waiters = partialStateWaiters.get(roomId);
		if (waiters) {
			partialStateWaiters.delete(roomId);
			for (const w of waiters) w();
		}
		eph.wakeWaiters(); // wake long-poll /sync so eager syncs pick the room up
	};

	const getRoomPartialState = async (
		roomId: RoomId,
	): Promise<{ servers: ServerName[]; joinEventId: EventId } | undefined> => {
		const row = db
			.prepare(
				"SELECT servers, join_event_id FROM partial_state_rooms WHERE room_id = ?",
			)
			.get(roomId) as { servers: string; join_event_id: string } | undefined;
		if (!row) return undefined;
		return {
			servers: JSON.parse(row.servers) as ServerName[],
			joinEventId: row.join_event_id as EventId,
		};
	};

	const getAllPartialStateRooms = async (): Promise<
		{ roomId: RoomId; servers: ServerName[]; joinEventId: EventId }[]
	> => {
		const rows = db
			.prepare(
				"SELECT room_id, servers, join_event_id FROM partial_state_rooms",
			)
			.all() as {
			room_id: string;
			servers: string;
			join_event_id: string;
		}[];
		return rows.map((r) => ({
			roomId: r.room_id as RoomId,
			servers: JSON.parse(r.servers) as ServerName[],
			joinEventId: r.join_event_id as EventId,
		}));
	};

	const recordPartialStateEvent = async (
		roomId: RoomId,
		eventId: EventId,
	): Promise<void> => {
		db.prepare(
			"INSERT OR IGNORE INTO partial_state_events (room_id, event_id) VALUES (?, ?)",
		).run(roomId, eventId);
	};

	const takePartialStateEvents = async (roomId: RoomId): Promise<EventId[]> => {
		const rows = db
			.prepare("SELECT event_id FROM partial_state_events WHERE room_id = ?")
			.all(roomId) as { event_id: string }[];
		db.prepare("DELETE FROM partial_state_events WHERE room_id = ?").run(
			roomId,
		);
		return rows.map((r) => r.event_id as EventId);
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
		set.add(encodeDevicePoke(userId, deviceId));
	};

	const takePartialStateDevicePokes = async (
		roomId: RoomId,
	): Promise<{ userId: UserId; deviceId: DeviceId }[]> => {
		const set = partialStateDevicePokes.get(roomId);
		partialStateDevicePokes.delete(roomId);
		return set ? [...set].map(decodeDevicePoke) : [];
	};

	const deleteEvent = async (eventId: EventId): Promise<void> => {
		const row = db
			.prepare("SELECT room_id FROM events WHERE event_id = ?")
			.get(eventId) as { room_id: string } | undefined;
		// Mark the event rejected rather than deleting it: it stays in the events
		// table so the DAG remains walkable (other events list it in prev_events),
		// but it is dropped from current state, hidden from /sync and timeline
		// reads, served as 404 by /event, and ignored when computing state at an
		// event. Mirrors synapse keeping rejected events with a rejection_reason.
		db.prepare("UPDATE events SET rejected = 1 WHERE event_id = ?").run(
			eventId,
		);
		db.prepare("DELETE FROM state_events WHERE event_id = ?").run(eventId);
		if (row) eph.roomCache.delete(row.room_id as RoomId);
	};

	const unrejectEvent = async (eventId: EventId): Promise<void> => {
		const row = db
			.prepare("SELECT room_id FROM events WHERE event_id = ?")
			.get(eventId) as { room_id: string } | undefined;
		db.prepare("UPDATE events SET rejected = 0 WHERE event_id = ?").run(
			eventId,
		);
		if (row) eph.roomCache.delete(row.room_id as RoomId);
	};

	const waitForPartialStateClear = async (
		roomId: RoomId,
		timeoutMs: number,
	): Promise<void> => {
		if (!(await getRoomPartialState(roomId))) return;
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
		// Simplified: return current room state
		const room = await getRoom(_roomId);
		if (!room) return undefined;
		return new Map(room.state_events);
	};

	const getFederationTxn = async (
		origin: ServerName,
		txnId: string,
	): Promise<boolean> => {
		const row = db
			.prepare("SELECT 1 FROM federation_txns WHERE origin = ? AND txn_id = ?")
			.get(origin, txnId);
		return !!row;
	};

	const setFederationTxn = async (
		origin: ServerName,
		txnId: string,
	): Promise<void> => {
		db.prepare(
			"INSERT OR IGNORE INTO federation_txns (origin, txn_id) VALUES (?, ?)",
		).run(origin, txnId);
	};

	const enqueueFederationEdu = async (
		destination: ServerName,
		edu: EDU,
	): Promise<number> => {
		const info = db
			.prepare(
				"INSERT INTO pending_federation_edus (destination, edu_json) VALUES (?, ?)",
			)
			.run(destination, JSON.stringify(edu));
		// Enforce the per-destination cap by deleting the oldest overflow rows.
		const count = (
			db
				.prepare(
					"SELECT COUNT(*) AS c FROM pending_federation_edus WHERE destination = ?",
				)
				.get(destination) as { c: number }
		).c;
		if (count > PENDING_FEDERATION_EDU_CAP) {
			const overflow = count - PENDING_FEDERATION_EDU_CAP;
			db.prepare(
				"DELETE FROM pending_federation_edus WHERE id IN (SELECT id FROM pending_federation_edus WHERE destination = ? ORDER BY id ASC LIMIT ?)",
			).run(destination, overflow);
			console.warn(
				`pending_federation_edus: dropped ${overflow} EDU(s) for ${destination} (queue cap ${PENDING_FEDERATION_EDU_CAP} exceeded)`,
			);
		}
		return Number(info.lastInsertRowid);
	};

	const getPendingFederationEdus = async (
		destination: ServerName,
		limit: number,
	): Promise<{ id: number; edu: EDU }[]> => {
		const rows = db
			.prepare(
				"SELECT id, edu_json FROM pending_federation_edus WHERE destination = ? ORDER BY id ASC LIMIT ?",
			)
			.all(destination, limit) as { id: number; edu_json: string }[];
		return rows.map((r) => ({ id: r.id, edu: JSON.parse(r.edu_json) as EDU }));
	};

	const deleteFederationEdu = async (id: number): Promise<void> => {
		db.prepare("DELETE FROM pending_federation_edus WHERE id = ?").run(id);
	};

	const getPendingFederationDestinations = async (): Promise<ServerName[]> => {
		const rows = db
			.prepare("SELECT DISTINCT destination FROM pending_federation_edus")
			.all() as { destination: string }[];
		return rows.map((r) => r.destination as ServerName);
	};

	// 3PID verification — in-memory for simplicity (not persisted across restarts)
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
		db.transaction(() => {
			for (const event of authChain) {
				const eventId = computeEventId(event, roomVersion);
				eph.streamCounter++;
				stmts.insertEvent.run(
					eventId,
					event.room_id,
					eph.streamCounter,
					JSON.stringify(event),
				);
			}

			let maxDepth = 0;
			const extremities: EventId[] = [];

			for (const event of stateEvents) {
				const eventId = computeEventId(event, roomVersion);
				eph.streamCounter++;
				stmts.insertEvent.run(
					eventId,
					event.room_id,
					eph.streamCounter,
					JSON.stringify(event),
				);

				stmts.insertStateEvent.run(
					roomId,
					event.type,
					event.state_key ?? "",
					eventId,
					JSON.stringify(event),
				);

				if (event.depth > maxDepth) maxDepth = event.depth;
				extremities.length = 0;
				extremities.push(eventId);
			}

			db.prepare(
				"INSERT OR REPLACE INTO rooms (room_id, room_version, depth, forward_extremities) VALUES (?, ?, ?, ?)",
			).run(roomId, roomVersion, maxDepth + 1, JSON.stringify(extremities));
		})();

		eph.wakeWaiters();
	};

	mkdirSync(dirname(dbPath), { recursive: true });
	db = new Database(dbPath);
	db.pragma("journal_mode = WAL");
	// Durability is configurable: NORMAL (default) fsyncs at WAL checkpoints
	// (~fast, can lose the last few txns on power loss); FULL fsyncs every
	// commit (fully durable). Override with SQLITE_SYNCHRONOUS=FULL.
	const sync = process.env.SQLITE_SYNCHRONOUS ?? "NORMAL";
	db.pragma(`synchronous = ${sync}`);
	db.pragma("foreign_keys = OFF");
	init();

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
