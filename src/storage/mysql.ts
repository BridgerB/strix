import * as mariadb from "mariadb";
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

export const createMysqlStorage = async (
	connectionString: string,
): Promise<Storage> => {
	const eph = createEphemeralStore();
	let pool: mariadb.Pool;

	const query = async (sql: string, params?: unknown[]): Promise<unknown[]> => {
		const rows = await pool.query(sql, params);
		return rows;
	};

	const exec = async (
		sql: string,
		params?: unknown[],
	): Promise<mariadb.UpsertResult> => {
		return await pool.query(sql, params);
	};

	const init = async (): Promise<void> => {
		const conn = await pool.getConnection();
		try {
			await conn.query(`
				CREATE TABLE IF NOT EXISTS users (
					user_id VARCHAR(255) PRIMARY KEY,
					localpart VARCHAR(255) UNIQUE NOT NULL,
					server_name VARCHAR(255) NOT NULL,
					password_hash TEXT NOT NULL,
					account_type VARCHAR(32) NOT NULL DEFAULT 'user',
					is_deactivated BOOLEAN NOT NULL DEFAULT FALSE,
					created_at BIGINT NOT NULL,
					displayname TEXT,
					avatar_url TEXT
				)
			`);

			await conn.query(`
				CREATE TABLE IF NOT EXISTS sessions (
					access_token VARCHAR(255) PRIMARY KEY,
					refresh_token VARCHAR(255),
					device_id VARCHAR(255) NOT NULL,
					user_id VARCHAR(255) NOT NULL,
					access_token_hash VARCHAR(255),
					expires_at BIGINT,
					display_name TEXT,
					last_seen_ip VARCHAR(255),
					last_seen_ts BIGINT,
					user_agent TEXT,
					INDEX idx_sessions_user (user_id),
					INDEX idx_sessions_refresh (refresh_token),
					INDEX idx_sessions_device (user_id, device_id)
				)
			`);

			await conn.query(`
				CREATE TABLE IF NOT EXISTS uiaa_sessions (
					session_id VARCHAR(255) PRIMARY KEY,
					completed JSON NOT NULL
				)
			`);

			await conn.query(`
				CREATE TABLE IF NOT EXISTS rooms (
					room_id VARCHAR(255) PRIMARY KEY,
					room_version VARCHAR(32) NOT NULL,
					depth INT NOT NULL DEFAULT 0,
					forward_extremities JSON NOT NULL
				)
			`);

			await conn.query(`
				CREATE TABLE IF NOT EXISTS events (
					event_id VARCHAR(255) PRIMARY KEY,
					room_id VARCHAR(255) NOT NULL,
					stream_pos BIGINT NOT NULL,
					event_json JSON NOT NULL,
					INDEX idx_events_room (room_id),
					INDEX idx_events_stream (room_id, stream_pos)
				)
			`);

			await conn.query(`
				CREATE TABLE IF NOT EXISTS state_events (
					room_id VARCHAR(255) NOT NULL,
					event_type VARCHAR(255) NOT NULL,
					state_key VARCHAR(255) NOT NULL,
					event_id VARCHAR(255) NOT NULL,
					event_json JSON NOT NULL,
					PRIMARY KEY (room_id, event_type, state_key)
				)
			`);

			await conn.query(`
				CREATE TABLE IF NOT EXISTS txn_map (
					user_id VARCHAR(255) NOT NULL,
					device_id VARCHAR(255) NOT NULL,
					txn_id VARCHAR(255) NOT NULL,
					event_id VARCHAR(255) NOT NULL,
					PRIMARY KEY (user_id, device_id, txn_id)
				)
			`);

			await conn.query(`
				CREATE TABLE IF NOT EXISTS room_aliases (
					room_alias VARCHAR(255) PRIMARY KEY,
					room_id VARCHAR(255) NOT NULL,
					servers JSON NOT NULL,
					creator VARCHAR(255) NOT NULL
				)
			`);

			await conn.query(`
				CREATE TABLE IF NOT EXISTS room_directory (
					room_id VARCHAR(255) PRIMARY KEY,
					visibility VARCHAR(32) NOT NULL DEFAULT 'private'
				)
			`);

			await conn.query(`
				CREATE TABLE IF NOT EXISTS global_account_data (
					user_id VARCHAR(255) NOT NULL,
					type VARCHAR(255) NOT NULL,
					content JSON NOT NULL,
					stream_pos BIGINT NOT NULL DEFAULT 0,
					PRIMARY KEY (user_id, type)
				)
			`);

			await conn.query(`
				CREATE TABLE IF NOT EXISTS room_account_data (
					user_id VARCHAR(255) NOT NULL,
					room_id VARCHAR(255) NOT NULL,
					type VARCHAR(255) NOT NULL,
					content JSON NOT NULL,
					stream_pos BIGINT NOT NULL DEFAULT 0,
					PRIMARY KEY (user_id, room_id, type)
				)
			`);

			await conn.query(`
				CREATE TABLE IF NOT EXISTS receipts (
					room_id VARCHAR(255) CHARACTER SET ascii NOT NULL,
					user_id VARCHAR(255) CHARACTER SET ascii NOT NULL,
					event_id VARCHAR(255) NOT NULL,
					receipt_type VARCHAR(255) CHARACTER SET ascii NOT NULL,
					ts BIGINT NOT NULL,
					thread_id VARCHAR(255) CHARACTER SET ascii NOT NULL DEFAULT '',
					PRIMARY KEY (room_id, user_id, receipt_type, thread_id)
				)
			`);

			await conn.query(`
				CREATE TABLE IF NOT EXISTS media (
					origin VARCHAR(255) NOT NULL,
					media_id VARCHAR(255) NOT NULL,
					user_id VARCHAR(255),
					content_type VARCHAR(255) NOT NULL,
					upload_name TEXT,
					file_size BIGINT NOT NULL,
					content_hash VARCHAR(255) NOT NULL,
					created_at BIGINT NOT NULL,
					quarantined BOOLEAN NOT NULL DEFAULT FALSE,
					data LONGBLOB NOT NULL,
					PRIMARY KEY (origin, media_id)
				)
			`);

			await conn.query(`
				CREATE TABLE IF NOT EXISTS filters (
					user_id VARCHAR(255) NOT NULL,
					filter_id BIGINT NOT NULL,
					filter_json JSON NOT NULL,
					PRIMARY KEY (user_id, filter_id)
				)
			`);

			await conn.query(`
				CREATE TABLE IF NOT EXISTS device_keys (
					user_id VARCHAR(255) NOT NULL,
					device_id VARCHAR(255) NOT NULL,
					keys_json JSON NOT NULL,
					PRIMARY KEY (user_id, device_id)
				)
			`);

			await conn.query(`
				CREATE TABLE IF NOT EXISTS one_time_keys (
					user_id VARCHAR(255) NOT NULL,
					device_id VARCHAR(255) NOT NULL,
					key_id VARCHAR(255) NOT NULL,
					algorithm VARCHAR(64) NOT NULL,
					key_json JSON NOT NULL,
					PRIMARY KEY (user_id, device_id, key_id)
				)
			`);

			await conn.query(`
				CREATE TABLE IF NOT EXISTS fallback_keys (
					user_id VARCHAR(255) NOT NULL,
					device_id VARCHAR(255) NOT NULL,
					key_id VARCHAR(255) NOT NULL,
					key_json JSON NOT NULL,
					PRIMARY KEY (user_id, device_id, key_id)
				)
			`);

			await conn.query(`
				CREATE TABLE IF NOT EXISTS to_device (
					id BIGINT AUTO_INCREMENT PRIMARY KEY,
					user_id VARCHAR(255) NOT NULL,
					device_id VARCHAR(255) NOT NULL,
					event_json JSON NOT NULL,
					INDEX idx_to_device (user_id, device_id)
				)
			`);

			await conn.query(`
				CREATE TABLE IF NOT EXISTS pushers (
					user_id VARCHAR(255) NOT NULL,
					app_id VARCHAR(255) NOT NULL,
					pushkey VARCHAR(255) NOT NULL,
					pusher_json JSON NOT NULL,
					PRIMARY KEY (user_id, app_id, pushkey)
				)
			`);

			await conn.query(`
				CREATE TABLE IF NOT EXISTS relations (
					event_id VARCHAR(255) NOT NULL,
					room_id VARCHAR(255) NOT NULL,
					rel_type VARCHAR(255) NOT NULL,
					target_event_id VARCHAR(255) NOT NULL,
					\`key\` VARCHAR(255),
					sender VARCHAR(255) NOT NULL,
					event_type VARCHAR(255) NOT NULL,
					stream_pos BIGINT NOT NULL,
					INDEX idx_relations_target (target_event_id)
				)
			`);

			await conn.query(`
				CREATE TABLE IF NOT EXISTS reports (
					id BIGINT AUTO_INCREMENT PRIMARY KEY,
					user_id VARCHAR(255) NOT NULL,
					room_id VARCHAR(255) NOT NULL,
					event_id VARCHAR(255) NOT NULL,
					score INT,
					reason TEXT,
					ts BIGINT NOT NULL
				)
			`);

			await conn.query(`
				CREATE TABLE IF NOT EXISTS openid_tokens (
					token VARCHAR(255) PRIMARY KEY,
					user_id VARCHAR(255) NOT NULL,
					expires_at BIGINT NOT NULL
				)
			`);

			await conn.query(`
				CREATE TABLE IF NOT EXISTS threepids (
					user_id VARCHAR(255) NOT NULL,
					medium VARCHAR(255) NOT NULL,
					address VARCHAR(255) NOT NULL,
					added_at BIGINT NOT NULL,
					PRIMARY KEY (user_id, medium, address)
				)
			`);

			await conn.query(`
				CREATE TABLE IF NOT EXISTS server_keys (
					server_name VARCHAR(255) NOT NULL,
					key_id VARCHAR(255) NOT NULL,
					\`key\` TEXT NOT NULL,
					valid_until BIGINT NOT NULL,
					PRIMARY KEY (server_name, key_id)
				)
			`);

			await conn.query(`
				CREATE TABLE IF NOT EXISTS federation_txns (
					origin VARCHAR(255) NOT NULL,
					txn_id VARCHAR(255) NOT NULL,
					PRIMARY KEY (origin, txn_id)
				)
			`);

			await conn.query(`
				CREATE TABLE IF NOT EXISTS pending_federation_edus (
					id BIGINT AUTO_INCREMENT PRIMARY KEY,
					destination VARCHAR(255) NOT NULL,
					edu_json LONGTEXT NOT NULL,
					INDEX idx_pending_fed_edus_dest (destination, id)
				)
			`);

			await conn.query(`
				CREATE TABLE IF NOT EXISTS cross_signing_keys (
					user_id VARCHAR(255) NOT NULL,
					key_type VARCHAR(64) NOT NULL,
					key_json TEXT NOT NULL,
					PRIMARY KEY (user_id, key_type)
				)
			`);

			await conn.query(`
				CREATE TABLE IF NOT EXISTS key_backup_versions (
					id INT AUTO_INCREMENT PRIMARY KEY,
					user_id VARCHAR(255) NOT NULL,
					version VARCHAR(64) NOT NULL,
					algorithm VARCHAR(255) NOT NULL,
					auth_data TEXT NOT NULL,
					UNIQUE KEY (user_id, version)
				)
			`);

			await conn.query(`
				CREATE TABLE IF NOT EXISTS key_backup_data (
					user_id VARCHAR(255) CHARACTER SET ascii NOT NULL,
					version VARCHAR(64) CHARACTER SET ascii NOT NULL,
					room_id VARCHAR(255) CHARACTER SET ascii NOT NULL,
					session_id VARCHAR(255) CHARACTER SET ascii NOT NULL,
					key_json TEXT NOT NULL,
					PRIMARY KEY (user_id, version, room_id, session_id)
				)
			`);

			await conn.query(`
				CREATE TABLE IF NOT EXISTS device_list_stream (
					user_id VARCHAR(255) NOT NULL,
					stream_pos BIGINT NOT NULL,
					INDEX idx_device_list_stream (stream_pos)
				)
			`);
		} finally {
			conn.release();
		}

		const [maxPos] = (await query(
			`SELECT MAX(m) AS m FROM (
				SELECT MAX(stream_pos) AS m FROM events
				UNION ALL SELECT MAX(stream_pos) FROM global_account_data
				UNION ALL SELECT MAX(stream_pos) FROM room_account_data
				UNION ALL SELECT MAX(stream_pos) FROM device_list_stream
			) sub`,
		)) as { m: number | null }[];
		eph.streamCounter = maxPos?.m ?? 0;

		const [maxFilter] = (await query(
			"SELECT MAX(filter_id) AS m FROM filters",
		)) as { m: number | null }[];
		eph.filterCounter = maxFilter?.m ?? 0;
	};

	const json = (val: unknown): string => {
		return JSON.stringify(val);
	};

	const parseJson = (val: unknown): unknown => {
		if (typeof val === "string") return JSON.parse(val);
		return val;
	};

	const createUser = async (account: UserAccount): Promise<void> => {
		await exec(
			`INSERT INTO users (user_id, localpart, server_name, password_hash, account_type, is_deactivated, created_at, displayname, avatar_url)
			 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
			 ON DUPLICATE KEY UPDATE
				localpart = VALUES(localpart), server_name = VALUES(server_name), password_hash = VALUES(password_hash),
				account_type = VALUES(account_type), is_deactivated = VALUES(is_deactivated), created_at = VALUES(created_at),
				displayname = VALUES(displayname), avatar_url = VALUES(avatar_url)`,
			[
				account.user_id,
				account.localpart,
				account.server_name,
				account.password_hash,
				account.account_type,
				account.is_deactivated ?? false,
				account.created_at,
				account.displayname ?? null,
				account.avatar_url ?? null,
			],
		);
	};

	const getUserByLocalpart = async (
		localpart: string,
	): Promise<UserAccount | undefined> => {
		const rows = (await query("SELECT * FROM users WHERE localpart = ?", [
			localpart,
		])) as Record<string, unknown>[];
		return rows[0] ? rowToUser(rows[0]) : undefined;
	};

	const getUserById = async (
		userId: UserId,
	): Promise<UserAccount | undefined> => {
		const rows = (await query("SELECT * FROM users WHERE user_id = ?", [
			userId,
		])) as Record<string, unknown>[];
		return rows[0] ? rowToUser(rows[0]) : undefined;
	};

	const createSession = async (session: StoredSession): Promise<void> => {
		await exec(
			`INSERT INTO sessions (access_token, refresh_token, device_id, user_id, access_token_hash, expires_at, display_name, last_seen_ip, last_seen_ts, user_agent)
			 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
			 ON DUPLICATE KEY UPDATE
				refresh_token = VALUES(refresh_token), device_id = VALUES(device_id), user_id = VALUES(user_id),
				access_token_hash = VALUES(access_token_hash), expires_at = VALUES(expires_at), display_name = VALUES(display_name),
				last_seen_ip = VALUES(last_seen_ip), last_seen_ts = VALUES(last_seen_ts), user_agent = VALUES(user_agent)`,
			[
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
			],
		);
	};

	const getSessionByAccessToken = async (
		token: AccessToken,
	): Promise<StoredSession | undefined> => {
		const rows = (await query("SELECT * FROM sessions WHERE access_token = ?", [
			token,
		])) as Record<string, unknown>[];
		return rows[0] ? rowToSession(rows[0]) : undefined;
	};

	const getSessionByRefreshToken = async (
		token: RefreshToken,
	): Promise<StoredSession | undefined> => {
		const rows = (await query(
			"SELECT * FROM sessions WHERE refresh_token = ?",
			[token],
		)) as Record<string, unknown>[];
		return rows[0] ? rowToSession(rows[0]) : undefined;
	};

	const getSessionsByUser = async (
		userId: UserId,
	): Promise<StoredSession[]> => {
		const rows = (await query("SELECT * FROM sessions WHERE user_id = ?", [
			userId,
		])) as Record<string, unknown>[];
		return rows.map((r) => rowToSession(r));
	};

	const deleteSession = async (token: AccessToken): Promise<void> => {
		await exec("DELETE FROM sessions WHERE access_token = ?", [token]);
	};

	const deleteAllSessions = async (userId: UserId): Promise<void> => {
		await exec("DELETE FROM sessions WHERE user_id = ?", [userId]);
	};

	const rotateToken = async (
		oldAccessToken: AccessToken,
		newAccessToken: AccessToken,
		newRefreshToken?: RefreshToken,
		expiresAt?: Timestamp,
	): Promise<StoredSession | undefined> => {
		const session = await getSessionByAccessToken(oldAccessToken);
		if (!session) return undefined;
		await deleteSession(oldAccessToken);
		const updated: StoredSession = {
			...session,
			access_token: newAccessToken,
			refresh_token: newRefreshToken,
			expires_at: expiresAt,
		};
		await createSession(updated);
		return updated;
	};

	const touchSession = async (
		token: AccessToken,
		ip: string,
		userAgent: string,
	): Promise<void> => {
		await exec(
			"UPDATE sessions SET last_seen_ip = ?, last_seen_ts = ?, user_agent = ? WHERE access_token = ?",
			[ip, Date.now(), userAgent, token],
		);
	};

	const createUIAASession = async (sessionId: string): Promise<void> => {
		await exec(
			"INSERT INTO uiaa_sessions (session_id, completed) VALUES (?, '[]') ON DUPLICATE KEY UPDATE completed = '[]'",
			[sessionId],
		);
	};

	const getUIAASession = async (
		sessionId: string,
	): Promise<{ completed: string[] } | undefined> => {
		const rows = (await query(
			"SELECT completed FROM uiaa_sessions WHERE session_id = ?",
			[sessionId],
		)) as Record<string, unknown>[];
		if (!rows[0]) return undefined;
		return { completed: parseJson(rows[0].completed) as string[] };
	};

	const addUIAACompleted = async (
		sessionId: string,
		stageType: string,
	): Promise<void> => {
		await exec(
			"UPDATE uiaa_sessions SET completed = JSON_ARRAY_APPEND(completed, '$', ?) WHERE session_id = ?",
			[stageType, sessionId],
		);
	};

	const deleteUIAASession = async (sessionId: string): Promise<void> => {
		await exec("DELETE FROM uiaa_sessions WHERE session_id = ?", [sessionId]);
	};

	const createRoom = async (state: RoomState): Promise<void> => {
		const conn = await pool.getConnection();
		try {
			await conn.beginTransaction();
			await conn.query(
				`INSERT INTO rooms (room_id, room_version, depth, forward_extremities) VALUES (?, ?, ?, ?)
				 ON DUPLICATE KEY UPDATE room_version = VALUES(room_version), depth = VALUES(depth), forward_extremities = VALUES(forward_extremities)`,
				[
					state.room_id,
					state.room_version,
					state.depth,
					json(state.forward_extremities),
				],
			);
			for (const [key, event] of state.state_events) {
				const [eventType, stateKey] = key.split("\x1f") as [string, string];
				const eventId = computeEventId(event, state.room_version);
				await conn.query(
					`INSERT INTO state_events (room_id, event_type, state_key, event_id, event_json) VALUES (?, ?, ?, ?, ?)
					 ON DUPLICATE KEY UPDATE event_id = VALUES(event_id), event_json = VALUES(event_json)`,
					[state.room_id, eventType, stateKey, eventId, json(event)],
				);
			}
			await conn.commit();
		} catch (e) {
			await conn.rollback();
			throw e;
		} finally {
			conn.release();
		}
		eph.roomCache.set(state.room_id, state);
	};

	const getRoom = async (roomId: RoomId): Promise<RoomState | undefined> => {
		const cached = eph.roomCache.get(roomId);
		if (cached) return cached;

		const rows = (await query("SELECT * FROM rooms WHERE room_id = ?", [
			roomId,
		])) as Record<string, unknown>[];
		if (!rows[0]) return undefined;
		const row = rows[0];

		const stateRows = (await query(
			"SELECT event_type, state_key, event_json FROM state_events WHERE room_id = ?",
			[roomId],
		)) as Record<string, unknown>[];
		const stateMap = new Map<string, PDU>();
		for (const sr of stateRows) {
			stateMap.set(
				`${sr.event_type}\x1f${sr.state_key}`,
				parseJson(sr.event_json) as PDU,
			);
		}

		const room: RoomState = {
			room_id: row.room_id as RoomId,
			room_version: row.room_version as RoomVersion,
			state_events: stateMap,
			depth: Number(row.depth),
			forward_extremities: parseJson(row.forward_extremities) as EventId[],
		};
		eph.roomCache.set(roomId, room);
		return room;
	};

	const getRoomsForUser = async (userId: UserId): Promise<RoomId[]> => {
		const rows = (await query(
			"SELECT room_id FROM state_events WHERE event_type = 'm.room.member' AND state_key = ? AND JSON_UNQUOTE(JSON_EXTRACT(event_json, '$.content.membership')) = 'join'",
			[userId],
		)) as Record<string, unknown>[];
		return rows.map((r) => r.room_id as RoomId);
	};

	const storeEvent = async (event: PDU, eventId: EventId): Promise<void> => {
		eph.streamCounter++;
		await exec(
			`INSERT INTO events (event_id, room_id, stream_pos, event_json) VALUES (?, ?, ?, ?)
			 ON DUPLICATE KEY UPDATE room_id = VALUES(room_id), stream_pos = VALUES(stream_pos), event_json = VALUES(event_json)`,
			[eventId, event.room_id, eph.streamCounter, json(event)],
		);
		eph.wakeWaiters();
	};

	const updateEvent = async (eventId: EventId, event: PDU): Promise<void> => {
		await exec("UPDATE events SET event_json = ? WHERE event_id = ?", [
			json(event),
			eventId,
		]);
	};

	const getEvent = async (
		eventId: EventId,
	): Promise<{ event: PDU; eventId: EventId } | undefined> => {
		const rows = (await query(
			"SELECT event_id, event_json FROM events WHERE event_id = ?",
			[eventId],
		)) as Record<string, unknown>[];
		if (!rows[0]) return undefined;
		return {
			event: parseJson(rows[0].event_json) as PDU,
			eventId: rows[0].event_id as EventId,
		};
	};

	const getEventsByRoom = async (
		roomId: RoomId,
		limit: number,
		from?: number,
		direction: "b" | "f" = "f",
	): Promise<{ events: { event: PDU; eventId: EventId }[]; end?: number }> => {
		const fromPos = from ?? (direction === "f" ? 0 : eph.streamCounter + 1);
		let rows: Record<string, unknown>[];

		if (direction === "f") {
			rows = (await query(
				"SELECT event_id, event_json, stream_pos FROM events WHERE room_id = ? AND stream_pos > ? ORDER BY stream_pos ASC LIMIT ?",
				[roomId, fromPos, limit],
			)) as Record<string, unknown>[];
		} else {
			rows = (await query(
				"SELECT event_id, event_json, stream_pos FROM events WHERE room_id = ? AND stream_pos < ? ORDER BY stream_pos DESC LIMIT ?",
				[roomId, fromPos, limit],
			)) as Record<string, unknown>[];
		}

		const events = rows.map((r) => ({
			event: parseJson(r.event_json) as PDU,
			eventId: r.event_id as EventId,
		}));
		const lastRow = rows[rows.length - 1];
		const end = lastRow ? Number(lastRow.stream_pos) : undefined;
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
		const rows = (await query(
			"SELECT event_id, event_json FROM state_events WHERE room_id = ? AND event_type = ? AND state_key = ?",
			[roomId, eventType, stateKey],
		)) as Record<string, unknown>[];
		if (!rows[0]) return undefined;
		return {
			event: parseJson(rows[0].event_json) as PDU,
			eventId: rows[0].event_id as EventId,
		};
	};

	const getAllState = async (
		roomId: RoomId,
	): Promise<{ event: PDU; eventId: EventId }[]> => {
		const rows = (await query(
			"SELECT event_id, event_json FROM state_events WHERE room_id = ?",
			[roomId],
		)) as Record<string, unknown>[];
		return rows.map((r) => ({
			event: parseJson(r.event_json) as PDU,
			eventId: r.event_id as EventId,
		}));
	};

	const setStateEvent = async (
		roomId: RoomId,
		event: PDU,
		eventId: EventId,
	): Promise<void> => {
		await exec(
			`INSERT INTO state_events (room_id, event_type, state_key, event_id, event_json) VALUES (?, ?, ?, ?, ?)
			 ON DUPLICATE KEY UPDATE event_id = VALUES(event_id), event_json = VALUES(event_json)`,
			[roomId, event.type, event.state_key ?? "", eventId, json(event)],
		);

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
		const rows = (await query(
			"SELECT event_id, event_json FROM state_events WHERE room_id = ? AND event_type = 'm.room.member'",
			[roomId],
		)) as Record<string, unknown>[];
		return rows.map((r) => ({
			event: parseJson(r.event_json) as PDU,
			eventId: r.event_id as EventId,
		}));
	};

	const getTxnEventId = async (
		userId: UserId,
		deviceId: DeviceId,
		txnId: string,
	): Promise<EventId | undefined> => {
		const rows = (await query(
			"SELECT event_id FROM txn_map WHERE user_id = ? AND device_id = ? AND txn_id = ?",
			[userId, deviceId, txnId],
		)) as Record<string, unknown>[];
		return rows[0] ? (rows[0].event_id as EventId) : undefined;
	};

	const setTxnEventId = async (
		userId: UserId,
		deviceId: DeviceId,
		txnId: string,
		eventId: EventId,
	): Promise<void> => {
		await exec(
			"INSERT INTO txn_map (user_id, device_id, txn_id, event_id) VALUES (?, ?, ?, ?) ON DUPLICATE KEY UPDATE event_id = VALUES(event_id)",
			[userId, deviceId, txnId, eventId],
		);
	};

	const getRoomsForUserWithMembership = async (
		userId: UserId,
	): Promise<{ roomId: RoomId; membership: string }[]> => {
		const rows = (await query(
			"SELECT room_id, JSON_UNQUOTE(JSON_EXTRACT(event_json, '$.content.membership')) AS membership FROM state_events WHERE event_type = 'm.room.member' AND state_key = ?",
			[userId],
		)) as Record<string, unknown>[];
		return rows
			.filter((r) => r.membership)
			.map((r) => ({
				roomId: r.room_id as RoomId,
				membership: r.membership as string,
			}));
	};

	const getEventsByRoomSince = async (
		roomId: RoomId,
		since: number,
		limit: number,
	): Promise<{
		events: { event: PDU; eventId: EventId; streamPos: number }[];
		limited: boolean;
	}> => {
		const [countRow] = (await query(
			"SELECT COUNT(*) AS cnt FROM events WHERE room_id = ? AND stream_pos > ?",
			[roomId, since],
		)) as Record<string, unknown>[];
		const total = Number(countRow?.cnt);
		const limited = total > limit;

		let rows: Record<string, unknown>[];
		if (limited) {
			rows = (await query(
				"SELECT event_id, event_json, stream_pos FROM events WHERE room_id = ? AND stream_pos > ? ORDER BY stream_pos DESC LIMIT ?",
				[roomId, since, limit],
			)) as Record<string, unknown>[];
			rows.reverse();
		} else {
			rows = (await query(
				"SELECT event_id, event_json, stream_pos FROM events WHERE room_id = ? AND stream_pos > ? ORDER BY stream_pos ASC",
				[roomId, since],
			)) as Record<string, unknown>[];
		}

		const events = rows.map((r) => ({
			event: parseJson(r.event_json) as PDU,
			eventId: r.event_id as EventId,
			streamPos: Number(r.stream_pos),
		}));
		return { events, limited };
	};

	const getStrippedState = async (
		roomId: RoomId,
	): Promise<StrippedStateEvent[]> => {
		const placeholders = INVITE_STATE_TYPES.map(() => "?").join(",");
		const rows = (await query(
			`SELECT event_json FROM state_events WHERE room_id = ? AND event_type IN (${placeholders})`,
			[roomId, ...INVITE_STATE_TYPES],
		)) as Record<string, unknown>[];
		return rows.map((r) => {
			const event = parseJson(r.event_json) as PDU;
			return eventToStrippedState(event);
		});
	};

	const getProfile = async (
		userId: UserId,
	): Promise<UserProfile | undefined> => {
		const rows = (await query(
			"SELECT displayname, avatar_url FROM users WHERE user_id = ?",
			[userId],
		)) as Record<string, unknown>[];
		if (!rows[0]) return undefined;
		const profile: UserProfile = {};
		if (rows[0].displayname)
			profile.displayname = rows[0].displayname as string;
		if (rows[0].avatar_url) profile.avatar_url = rows[0].avatar_url as string;
		return profile;
	};

	const setDisplayName = async (
		userId: UserId,
		displayname: string | null,
	): Promise<void> => {
		await exec("UPDATE users SET displayname = ? WHERE user_id = ?", [
			displayname,
			userId,
		]);
	};

	const setAvatarUrl = async (
		userId: UserId,
		avatarUrl: string | null,
	): Promise<void> => {
		await exec("UPDATE users SET avatar_url = ? WHERE user_id = ?", [
			avatarUrl,
			userId,
		]);
	};

	const getDevice = async (
		userId: UserId,
		deviceId: DeviceId,
	): Promise<Device | undefined> => {
		const rows = (await query(
			"SELECT device_id, display_name, last_seen_ip, last_seen_ts FROM sessions WHERE user_id = ? AND device_id = ? LIMIT 1",
			[userId, deviceId],
		)) as Record<string, unknown>[];
		if (!rows[0]) return undefined;
		return {
			device_id: rows[0].device_id as DeviceId,
			display_name: (rows[0].display_name as string) ?? undefined,
			last_seen_ip: (rows[0].last_seen_ip as string) ?? undefined,
			last_seen_ts: rows[0].last_seen_ts
				? Number(rows[0].last_seen_ts)
				: undefined,
		};
	};

	const getAllDevices = async (userId: UserId): Promise<Device[]> => {
		const rows = (await query(
			"SELECT device_id, display_name, last_seen_ip, last_seen_ts FROM sessions WHERE user_id = ? GROUP BY device_id, display_name, last_seen_ip, last_seen_ts",
			[userId],
		)) as Record<string, unknown>[];
		return rows.map((r) => ({
			device_id: r.device_id as DeviceId,
			display_name: (r.display_name as string) ?? undefined,
			last_seen_ip: (r.last_seen_ip as string) ?? undefined,
			last_seen_ts: r.last_seen_ts ? Number(r.last_seen_ts) : undefined,
		}));
	};

	const updateDeviceDisplayName = async (
		userId: UserId,
		deviceId: DeviceId,
		displayName: string,
	): Promise<void> => {
		await exec(
			"UPDATE sessions SET display_name = ? WHERE user_id = ? AND device_id = ?",
			[displayName, userId, deviceId],
		);
	};

	const deleteDeviceSession = async (
		userId: UserId,
		deviceId: DeviceId,
	): Promise<void> => {
		await exec("DELETE FROM sessions WHERE user_id = ? AND device_id = ?", [
			userId,
			deviceId,
		]);
	};

	const updatePassword = async (
		userId: UserId,
		newPasswordHash: string,
	): Promise<void> => {
		await exec("UPDATE users SET password_hash = ? WHERE user_id = ?", [
			newPasswordHash,
			userId,
		]);
	};

	const deactivateUser = async (userId: UserId): Promise<void> => {
		await exec("UPDATE users SET is_deactivated = TRUE WHERE user_id = ?", [
			userId,
		]);
		await deleteAllSessions(userId);
	};

	const createRoomAlias = async (
		roomAlias: RoomAlias,
		roomId: RoomId,
		servers: ServerName[],
		creator: UserId,
	): Promise<void> => {
		await exec(
			"INSERT INTO room_aliases (room_alias, room_id, servers, creator) VALUES (?, ?, ?, ?) ON DUPLICATE KEY UPDATE room_id = VALUES(room_id), servers = VALUES(servers), creator = VALUES(creator)",
			[roomAlias, roomId, json(servers), creator],
		);
	};

	const deleteRoomAlias = async (roomAlias: RoomAlias): Promise<boolean> => {
		const result = await exec("DELETE FROM room_aliases WHERE room_alias = ?", [
			roomAlias,
		]);
		return (result.affectedRows ?? 0) > 0;
	};

	const getRoomByAlias = async (
		roomAlias: RoomAlias,
	): Promise<{ room_id: RoomId; servers: ServerName[] } | undefined> => {
		const rows = (await query(
			"SELECT room_id, servers FROM room_aliases WHERE room_alias = ?",
			[roomAlias],
		)) as Record<string, unknown>[];
		if (!rows[0]) return undefined;
		return {
			room_id: rows[0].room_id as RoomId,
			servers: parseJson(rows[0].servers) as ServerName[],
		};
	};

	const getAliasesForRoom = async (roomId: RoomId): Promise<RoomAlias[]> => {
		const rows = (await query(
			"SELECT room_alias FROM room_aliases WHERE room_id = ?",
			[roomId],
		)) as Record<string, unknown>[];
		return rows.map((r) => r.room_alias as RoomAlias);
	};

	const getAliasCreator = async (
		roomAlias: RoomAlias,
	): Promise<UserId | undefined> => {
		const rows = (await query(
			"SELECT creator FROM room_aliases WHERE room_alias = ?",
			[roomAlias],
		)) as Record<string, unknown>[];
		return rows[0] ? (rows[0].creator as UserId) : undefined;
	};

	const setRoomVisibility = async (
		roomId: RoomId,
		visibility: "public" | "private",
	): Promise<void> => {
		await exec(
			"INSERT INTO room_directory (room_id, visibility) VALUES (?, ?) ON DUPLICATE KEY UPDATE visibility = VALUES(visibility)",
			[roomId, visibility],
		);
	};

	const getRoomVisibility = async (
		roomId: RoomId,
	): Promise<"public" | "private"> => {
		const rows = (await query(
			"SELECT visibility FROM room_directory WHERE room_id = ?",
			[roomId],
		)) as Record<string, unknown>[];
		return (rows[0]?.visibility as "public" | "private") ?? "private";
	};

	const getPublicRoomIds = async (): Promise<RoomId[]> => {
		const rows = (await query(
			"SELECT room_id FROM room_directory WHERE visibility = 'public'",
		)) as Record<string, unknown>[];
		return rows.map((r) => r.room_id as RoomId);
	};

	const getGlobalAccountData = async (
		userId: UserId,
		type: string,
	): Promise<JsonObject | undefined> => {
		const rows = (await query(
			"SELECT content FROM global_account_data WHERE user_id = ? AND type = ?",
			[userId, type],
		)) as Record<string, unknown>[];
		return rows[0] ? (parseJson(rows[0].content) as JsonObject) : undefined;
	};

	const setGlobalAccountData = async (
		userId: UserId,
		type: string,
		content: JsonObject,
	): Promise<void> => {
		await exec(
			"INSERT INTO global_account_data (user_id, type, content, stream_pos) VALUES (?, ?, ?, ?) ON DUPLICATE KEY UPDATE content = VALUES(content), stream_pos = VALUES(stream_pos)",
			[userId, type, json(content), ++eph.streamCounter],
		);
		eph.wakeWaiters();
	};

	const getAllGlobalAccountData = async (
		userId: UserId,
	): Promise<{ type: string; content: JsonObject }[]> => {
		const rows = (await query(
			// Exclude MSC3391 deletion tombstones (empty object) from initial sync.
			"SELECT type, content FROM global_account_data WHERE user_id = ? AND JSON_LENGTH(content) > 0",
			[userId],
		)) as Record<string, unknown>[];
		return rows.map((r) => ({
			type: r.type as string,
			content: parseJson(r.content) as JsonObject,
		}));
	};

	const getGlobalAccountDataSince = async (
		userId: UserId,
		since: number,
	): Promise<{ type: string; content: JsonObject }[]> => {
		const rows = (await query(
			// Include tombstones so incremental sync surfaces deletions.
			"SELECT type, content FROM global_account_data WHERE user_id = ? AND stream_pos > ?",
			[userId, since],
		)) as Record<string, unknown>[];
		return rows.map((r) => ({
			type: r.type as string,
			content: parseJson(r.content) as JsonObject,
		}));
	};

	const getRoomAccountData = async (
		userId: UserId,
		roomId: RoomId,
		type: string,
	): Promise<JsonObject | undefined> => {
		const rows = (await query(
			"SELECT content FROM room_account_data WHERE user_id = ? AND room_id = ? AND type = ?",
			[userId, roomId, type],
		)) as Record<string, unknown>[];
		return rows[0] ? (parseJson(rows[0].content) as JsonObject) : undefined;
	};

	const setRoomAccountData = async (
		userId: UserId,
		roomId: RoomId,
		type: string,
		content: JsonObject,
	): Promise<void> => {
		await exec(
			"INSERT INTO room_account_data (user_id, room_id, type, content, stream_pos) VALUES (?, ?, ?, ?, ?) ON DUPLICATE KEY UPDATE content = VALUES(content), stream_pos = VALUES(stream_pos)",
			[userId, roomId, type, json(content), ++eph.streamCounter],
		);
		eph.wakeWaiters();
	};
	const deleteGlobalAccountData = async (
		userId: UserId,
		type: string,
	): Promise<void> => {
		// MSC3391: leave a tombstone (empty object) with a fresh stream position
		// rather than removing the row, so incremental sync can surface it.
		await exec(
			"INSERT INTO global_account_data (user_id, type, content, stream_pos) VALUES (?, ?, ?, ?) ON DUPLICATE KEY UPDATE content = VALUES(content), stream_pos = VALUES(stream_pos)",
			[userId, type, json({}), ++eph.streamCounter],
		);
		eph.wakeWaiters();
	};
	const deleteRoomAccountData = async (
		userId: UserId,
		roomId: RoomId,
		type: string,
	): Promise<void> => {
		await exec(
			"INSERT INTO room_account_data (user_id, room_id, type, content, stream_pos) VALUES (?, ?, ?, ?, ?) ON DUPLICATE KEY UPDATE content = VALUES(content), stream_pos = VALUES(stream_pos)",
			[userId, roomId, type, json({}), ++eph.streamCounter],
		);
		eph.wakeWaiters();
	};

	const getAllRoomAccountData = async (
		userId: UserId,
		roomId: RoomId,
	): Promise<{ type: string; content: JsonObject }[]> => {
		const rows = (await query(
			// Exclude MSC3391 deletion tombstones from initial sync.
			"SELECT type, content FROM room_account_data WHERE user_id = ? AND room_id = ? AND JSON_LENGTH(content) > 0",
			[userId, roomId],
		)) as Record<string, unknown>[];
		return rows.map((r) => ({
			type: r.type as string,
			content: parseJson(r.content) as JsonObject,
		}));
	};

	const getRoomAccountDataSince = async (
		userId: UserId,
		since: number,
	): Promise<{ roomId: RoomId; type: string; content: JsonObject }[]> => {
		const rows = (await query(
			// Include tombstones so incremental sync surfaces deletions.
			"SELECT room_id, type, content FROM room_account_data WHERE user_id = ? AND stream_pos > ?",
			[userId, since],
		)) as Record<string, unknown>[];
		return rows.map((r) => ({
			roomId: r.room_id as RoomId,
			type: r.type as string,
			content: parseJson(r.content) as JsonObject,
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
		await exec(
			"INSERT INTO receipts (room_id, user_id, event_id, receipt_type, ts, thread_id) VALUES (?, ?, ?, ?, ?, ?) ON DUPLICATE KEY UPDATE event_id = VALUES(event_id), ts = VALUES(ts)",
			[roomId, userId, eventId, receiptType, ts, threadId ?? ""],
		);
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
		const rows = (await query(
			"SELECT event_id, receipt_type, user_id, ts, thread_id FROM receipts WHERE room_id = ?",
			[roomId],
		)) as Record<string, unknown>[];
		return collapseReceiptsMsc4102(
			rows.map((r) => ({
				eventId: r.event_id as EventId,
				receiptType: r.receipt_type as string,
				userId: r.user_id as UserId,
				ts: Number(r.ts),
				threadId:
					r.thread_id === null || r.thread_id === ""
						? undefined
						: (r.thread_id as string),
			})),
		);
	};

	const storeMedia = async (
		media: StoredMedia,
		data: Buffer,
	): Promise<void> => {
		await exec(
			`INSERT INTO media (origin, media_id, user_id, content_type, upload_name, file_size, content_hash, created_at, quarantined, data)
			 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
			 ON DUPLICATE KEY UPDATE user_id = VALUES(user_id), content_type = VALUES(content_type), upload_name = VALUES(upload_name),
				file_size = VALUES(file_size), content_hash = VALUES(content_hash), created_at = VALUES(created_at), quarantined = VALUES(quarantined), data = VALUES(data)`,
			[
				media.origin,
				media.media_id,
				media.user_id ?? null,
				media.content_type,
				media.upload_name ?? null,
				media.file_size,
				media.content_hash,
				media.created_at,
				media.quarantined ?? false,
				data,
			],
		);
	};

	const getMedia = async (
		serverName: ServerName,
		mediaId: string,
	): Promise<{ metadata: StoredMedia; data: Buffer } | undefined> => {
		const rows = (await query(
			"SELECT * FROM media WHERE origin = ? AND media_id = ?",
			[serverName, mediaId],
		)) as Record<string, unknown>[];
		if (!rows[0]) return undefined;
		const row = rows[0];
		return {
			metadata: rowToStoredMedia(row),
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
		await exec(
			"UPDATE media SET content_type = ?, upload_name = ?, file_size = ?, content_hash = ?, data = ? WHERE origin = ? AND media_id = ?",
			[
				contentType,
				fileName ?? null,
				data.length,
				hash,
				data,
				serverName,
				mediaId,
			],
		);
		return true;
	};

	const createFilter = async (
		userId: UserId,
		filter: JsonObject,
	): Promise<string> => {
		const filterId = String(++eph.filterCounter);
		await exec(
			"INSERT INTO filters (user_id, filter_id, filter_json) VALUES (?, ?, ?) ON DUPLICATE KEY UPDATE filter_json = VALUES(filter_json)",
			[userId, filterId, json(filter)],
		);
		return filterId;
	};

	const getFilter = async (
		userId: UserId,
		filterId: string,
	): Promise<JsonObject | undefined> => {
		const rows = (await query(
			"SELECT filter_json FROM filters WHERE user_id = ? AND filter_id = ?",
			[userId, filterId],
		)) as Record<string, unknown>[];
		return rows[0] ? (parseJson(rows[0].filter_json) as JsonObject) : undefined;
	};

	const setDeviceKeys = async (
		userId: UserId,
		deviceId: DeviceId,
		keys: DeviceKeys,
	): Promise<void> => {
		await exec(
			"INSERT INTO device_keys (user_id, device_id, keys_json) VALUES (?, ?, ?) ON DUPLICATE KEY UPDATE keys_json = VALUES(keys_json)",
			[userId, deviceId, json(keys)],
		);
		await recordDeviceKeyChange(userId);
	};

	const recordDeviceKeyChange = async (userId: UserId): Promise<void> => {
		await exec(
			"INSERT INTO device_list_stream (user_id, stream_pos) VALUES (?, ?)",
			[userId, ++eph.streamCounter],
		);
		eph.wakeWaiters();
	};

	const getChangedDeviceUsers = async (
		since: number,
		until: number,
	): Promise<UserId[]> => {
		const rows = (await query(
			"SELECT DISTINCT user_id FROM device_list_stream WHERE stream_pos > ? AND stream_pos <= ?",
			[since, until],
		)) as Record<string, unknown>[];
		return rows.map((r) => r.user_id as UserId);
	};

	const getDeviceKeys = async (
		userId: UserId,
		deviceId: DeviceId,
	): Promise<DeviceKeys | undefined> => {
		const rows = (await query(
			"SELECT keys_json FROM device_keys WHERE user_id = ? AND device_id = ?",
			[userId, deviceId],
		)) as Record<string, unknown>[];
		return rows[0] ? (parseJson(rows[0].keys_json) as DeviceKeys) : undefined;
	};

	const getAllDeviceKeys = async (
		userId: UserId,
	): Promise<Record<DeviceId, DeviceKeys>> => {
		const rows = (await query(
			"SELECT device_id, keys_json FROM device_keys WHERE user_id = ?",
			[userId],
		)) as Record<string, unknown>[];
		const result: Record<DeviceId, DeviceKeys> = {};
		for (const r of rows)
			result[r.device_id as DeviceId] = parseJson(r.keys_json) as DeviceKeys;
		return result;
	};

	const deleteDeviceKeys = async (userId: UserId): Promise<void> => {
		await query("DELETE FROM device_keys WHERE user_id = ?", [userId]);
	};

	const addOneTimeKeys = async (
		userId: UserId,
		deviceId: DeviceId,
		keys: Record<KeyId, string | OneTimeKey>,
	): Promise<void> => {
		const conn = await pool.getConnection();
		try {
			await conn.beginTransaction();
			for (const [keyId, key] of Object.entries(keys)) {
				const algorithm = keyId.split(":")[0] as string;
				await conn.query(
					"INSERT INTO one_time_keys (user_id, device_id, key_id, algorithm, key_json) VALUES (?, ?, ?, ?, ?) ON DUPLICATE KEY UPDATE key_json = VALUES(key_json)",
					[userId, deviceId, keyId, algorithm, json(key)],
				);
			}
			await conn.commit();
		} catch (e) {
			await conn.rollback();
			throw e;
		} finally {
			conn.release();
		}
	};

	const claimOneTimeKey = async (
		userId: UserId,
		deviceId: DeviceId,
		algorithm: string,
	): Promise<{ keyId: KeyId; key: string | OneTimeKey } | undefined> => {
		const conn = await pool.getConnection();
		try {
			await conn.beginTransaction();
			const rows = (await conn.query(
				"SELECT key_id, key_json FROM one_time_keys WHERE user_id = ? AND device_id = ? AND algorithm = ? LIMIT 1",
				[userId, deviceId, algorithm],
			)) as Record<string, unknown>[];
			if (rows[0]) {
				await conn.query(
					"DELETE FROM one_time_keys WHERE user_id = ? AND device_id = ? AND key_id = ?",
					[userId, deviceId, rows[0].key_id],
				);
				await conn.commit();
				return {
					keyId: rows[0].key_id as KeyId,
					key: parseJson(rows[0].key_json) as string | OneTimeKey,
				};
			}
			await conn.commit();
		} catch (e) {
			await conn.rollback();
			throw e;
		} finally {
			conn.release();
		}

		const fallbackRows = (await query(
			"SELECT key_id, key_json FROM fallback_keys WHERE user_id = ? AND device_id = ? AND key_id LIKE ? LIMIT 1",
			[userId, deviceId, `${algorithm}:%`],
		)) as Record<string, unknown>[];
		if (fallbackRows[0])
			return {
				keyId: fallbackRows[0].key_id as KeyId,
				key: parseJson(fallbackRows[0].key_json) as string | OneTimeKey,
			};
		return undefined;
	};

	const getOneTimeKeyCounts = async (
		userId: UserId,
		deviceId: DeviceId,
	): Promise<Record<string, number>> => {
		const rows = (await query(
			"SELECT algorithm, COUNT(*) AS cnt FROM one_time_keys WHERE user_id = ? AND device_id = ? GROUP BY algorithm",
			[userId, deviceId],
		)) as Record<string, unknown>[];
		const counts: Record<string, number> = {};
		for (const r of rows) counts[r.algorithm as string] = Number(r.cnt);
		return counts;
	};

	const setFallbackKeys = async (
		userId: UserId,
		deviceId: DeviceId,
		keys: Record<KeyId, string | OneTimeKey>,
	): Promise<void> => {
		const conn = await pool.getConnection();
		try {
			await conn.beginTransaction();
			await conn.query(
				"DELETE FROM fallback_keys WHERE user_id = ? AND device_id = ?",
				[userId, deviceId],
			);
			for (const [keyId, key] of Object.entries(keys)) {
				await conn.query(
					"INSERT INTO fallback_keys (user_id, device_id, key_id, key_json) VALUES (?, ?, ?, ?)",
					[userId, deviceId, keyId, json(key)],
				);
			}
			await conn.commit();
		} catch (e) {
			await conn.rollback();
			throw e;
		} finally {
			conn.release();
		}
	};

	const getFallbackKeyTypes = async (
		userId: UserId,
		deviceId: DeviceId,
	): Promise<string[]> => {
		const rows = (await query(
			"SELECT DISTINCT key_id FROM fallback_keys WHERE user_id = ? AND device_id = ?",
			[userId, deviceId],
		)) as Record<string, unknown>[];
		const types = new Set<string>();
		for (const r of rows)
			types.add((r.key_id as string).split(":")[0] as string);
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
		const entries: [string, CrossSigningKey][] = [];
		if (keys.master_key) entries.push(["master_key", keys.master_key]);
		if (keys.self_signing_key)
			entries.push(["self_signing_key", keys.self_signing_key]);
		if (keys.user_signing_key)
			entries.push(["user_signing_key", keys.user_signing_key]);
		for (const [keyType, key] of entries) {
			await exec(
				"INSERT INTO cross_signing_keys (user_id, key_type, key_json) VALUES (?, ?, ?) ON DUPLICATE KEY UPDATE key_json = VALUES(key_json)",
				[userId, keyType, json(key)],
			);
		}
	};

	const getCrossSigningKeys = async (
		userId: UserId,
	): Promise<{
		master_key?: CrossSigningKey;
		self_signing_key?: CrossSigningKey;
		user_signing_key?: CrossSigningKey;
	}> => {
		const rows = (await query(
			"SELECT key_type, key_json FROM cross_signing_keys WHERE user_id = ?",
			[userId],
		)) as Record<string, unknown>[];
		return rowsToCrossSigningKeys(rows, (j) => parseJson(j) as CrossSigningKey);
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
					await setDeviceKeys(
						targetUserId as UserId,
						keyId as DeviceId,
						deviceKeys,
					);
					continue;
				}

				// Try updating cross-signing keys
				const crossKeys = await getCrossSigningKeys(targetUserId as UserId);
				let matched = false;
				for (const [crossKeyType, key] of [
					["master_key", crossKeys.master_key],
					["self_signing_key", crossKeys.self_signing_key],
					["user_signing_key", crossKeys.user_signing_key],
				] as const) {
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
						await exec(
							"UPDATE cross_signing_keys SET key_json = ? WHERE user_id = ? AND key_type = ?",
							[json(key), targetUserId, crossKeyType],
						);
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
		const [maxRow] = (await query(
			"SELECT MAX(CAST(version AS UNSIGNED)) AS m FROM key_backup_versions WHERE user_id = ?",
			[userId],
		)) as Record<string, unknown>[];
		const version = String((Number(maxRow?.m) || 0) + 1);
		await exec(
			"INSERT INTO key_backup_versions (user_id, version, algorithm, auth_data) VALUES (?, ?, ?, ?)",
			[userId, version, algorithm, json(authData)],
		);
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
		let rows: Record<string, unknown>[];
		if (version) {
			rows = (await query(
				"SELECT version, algorithm, auth_data FROM key_backup_versions WHERE user_id = ? AND version = ?",
				[userId, version],
			)) as Record<string, unknown>[];
		} else {
			rows = (await query(
				"SELECT version, algorithm, auth_data FROM key_backup_versions WHERE user_id = ? ORDER BY CAST(version AS UNSIGNED) DESC LIMIT 1",
				[userId],
			)) as Record<string, unknown>[];
		}
		if (!rows[0]) return undefined;
		const v = rows[0];
		const ver = v.version as string;

		const [countRow] = (await query(
			"SELECT COUNT(*) AS cnt FROM key_backup_data WHERE user_id = ? AND version = ?",
			[userId, ver],
		)) as Record<string, unknown>[];
		const count = Number(countRow?.cnt ?? 0);

		return {
			version: ver,
			algorithm: v.algorithm as string,
			auth_data: parseJson(v.auth_data) as JsonObject,
			count,
			etag: await computeMysqlBackupEtag(userId, ver),
		};
	};

	const computeMysqlBackupEtag = async (
		userId: UserId,
		version: string,
	): Promise<string> => {
		const rows = (await query(
			"SELECT room_id, session_id FROM key_backup_data WHERE user_id = ? AND version = ?",
			[userId, version],
		)) as Record<string, unknown>[];
		return keyBackupEtag(rows);
	};

	const updateKeyBackupVersion = async (
		userId: UserId,
		version: string,
		authData: JsonObject,
	): Promise<boolean> => {
		const result = await exec(
			"UPDATE key_backup_versions SET auth_data = ? WHERE user_id = ? AND version = ?",
			[json(authData), userId, version],
		);
		return (result as unknown as { affectedRows: number }).affectedRows > 0;
	};

	const deleteKeyBackupVersion = async (
		userId: UserId,
		version: string,
	): Promise<boolean> => {
		await exec(
			"DELETE FROM key_backup_data WHERE user_id = ? AND version = ?",
			[userId, version],
		);
		const result = await exec(
			"DELETE FROM key_backup_versions WHERE user_id = ? AND version = ?",
			[userId, version],
		);
		return (result as unknown as { affectedRows: number }).affectedRows > 0;
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
		// Verify version exists and is the latest
		const [latestRow] = (await query(
			"SELECT version FROM key_backup_versions WHERE user_id = ? ORDER BY CAST(version AS UNSIGNED) DESC LIMIT 1",
			[userId],
		)) as Record<string, unknown>[];
		if (!latestRow || (latestRow.version as string) !== version)
			return undefined;

		const entries = flattenKeyBackupEntries(roomId, sessionId, keys);

		for (const [rid, sid, data] of entries) {
			// Check existing for merge priority
			const existingRows = (await query(
				"SELECT key_json FROM key_backup_data WHERE user_id = ? AND version = ? AND room_id = ? AND session_id = ?",
				[userId, version, rid, sid],
			)) as Record<string, unknown>[];
			if (existingRows[0]) {
				const existing = parseJson(existingRows[0].key_json) as KeyBackupData;
				if (!shouldReplaceBackupKey(data, existing)) {
					continue;
				}
			}
			await exec(
				"INSERT INTO key_backup_data (user_id, version, room_id, session_id, key_json) VALUES (?, ?, ?, ?, ?) ON DUPLICATE KEY UPDATE key_json = VALUES(key_json)",
				[userId, version, rid, sid, json(data)],
			);
		}

		const [countRow] = (await query(
			"SELECT COUNT(*) AS cnt FROM key_backup_data WHERE user_id = ? AND version = ?",
			[userId, version],
		)) as Record<string, unknown>[];
		const count = Number(countRow?.cnt ?? 0);
		return { count, etag: await computeMysqlBackupEtag(userId, version) };
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
			const rows = (await query(
				"SELECT key_json FROM key_backup_data WHERE user_id = ? AND version = ? AND room_id = ? AND session_id = ?",
				[userId, version, roomId, sessionId],
			)) as Record<string, unknown>[];
			return rows[0]
				? (parseJson(rows[0].key_json) as KeyBackupData)
				: undefined;
		} else if (roomId) {
			const rows = (await query(
				"SELECT session_id, key_json FROM key_backup_data WHERE user_id = ? AND version = ? AND room_id = ?",
				[userId, version, roomId],
			)) as Record<string, unknown>[];
			const sessions: Record<string, KeyBackupData> = {};
			for (const r of rows) {
				sessions[r.session_id as string] = parseJson(
					r.key_json,
				) as KeyBackupData;
			}
			return { sessions };
		} else {
			const rows = (await query(
				"SELECT room_id, session_id, key_json FROM key_backup_data WHERE user_id = ? AND version = ?",
				[userId, version],
			)) as Record<string, unknown>[];
			const rooms: Record<RoomId, { sessions: Record<string, KeyBackupData> }> =
				{};
			for (const r of rows) {
				const rid = r.room_id as RoomId;
				if (!rooms[rid]) rooms[rid] = { sessions: {} };
				(rooms[rid] as { sessions: Record<string, KeyBackupData> }).sessions[
					r.session_id as string
				] = parseJson(r.key_json) as KeyBackupData;
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
		// Verify version exists
		const [versionRow] = (await query(
			"SELECT version FROM key_backup_versions WHERE user_id = ? AND version = ?",
			[userId, version],
		)) as Record<string, unknown>[];
		if (!versionRow) return undefined;

		if (roomId && sessionId) {
			await exec(
				"DELETE FROM key_backup_data WHERE user_id = ? AND version = ? AND room_id = ? AND session_id = ?",
				[userId, version, roomId, sessionId],
			);
		} else if (roomId) {
			await exec(
				"DELETE FROM key_backup_data WHERE user_id = ? AND version = ? AND room_id = ?",
				[userId, version, roomId],
			);
		} else {
			await exec(
				"DELETE FROM key_backup_data WHERE user_id = ? AND version = ?",
				[userId, version],
			);
		}

		const [countRow] = (await query(
			"SELECT COUNT(*) AS cnt FROM key_backup_data WHERE user_id = ? AND version = ?",
			[userId, version],
		)) as Record<string, unknown>[];
		const count = Number(countRow?.cnt ?? 0);
		return { count, etag: await computeMysqlBackupEtag(userId, version) };
	};

	const sendToDevice = async (
		userId: UserId,
		deviceId: DeviceId,
		event: ToDeviceEvent,
	): Promise<void> => {
		await exec(
			"INSERT INTO to_device (user_id, device_id, event_json) VALUES (?, ?, ?)",
			[userId, deviceId, json(event)],
		);
		eph.wakeWaiters();
	};

	const getToDeviceMessages = async (
		userId: UserId,
		deviceId: DeviceId,
	): Promise<ToDeviceEvent[]> => {
		const rows = (await query(
			"SELECT event_json FROM to_device WHERE user_id = ? AND device_id = ? ORDER BY id",
			[userId, deviceId],
		)) as Record<string, unknown>[];
		return rows.map((r) => parseJson(r.event_json) as ToDeviceEvent);
	};

	const clearToDeviceMessages = async (
		userId: UserId,
		deviceId: DeviceId,
	): Promise<void> => {
		await exec("DELETE FROM to_device WHERE user_id = ? AND device_id = ?", [
			userId,
			deviceId,
		]);
	};

	const getPushers = async (userId: UserId): Promise<Pusher[]> => {
		const rows = (await query(
			"SELECT pusher_json FROM pushers WHERE user_id = ?",
			[userId],
		)) as Record<string, unknown>[];
		return rows.map((r) => parseJson(r.pusher_json) as Pusher);
	};

	const setPusher = async (userId: UserId, pusher: Pusher): Promise<void> => {
		await exec(
			"INSERT INTO pushers (user_id, app_id, pushkey, pusher_json) VALUES (?, ?, ?, ?) ON DUPLICATE KEY UPDATE pusher_json = VALUES(pusher_json)",
			[userId, pusher.app_id, pusher.pushkey, json(pusher)],
		);
	};

	const deletePusher = async (
		userId: UserId,
		appId: string,
		pushkey: string,
	): Promise<void> => {
		await exec(
			"DELETE FROM pushers WHERE user_id = ? AND app_id = ? AND pushkey = ?",
			[userId, appId, pushkey],
		);
	};

	const deletePusherByKey = async (
		appId: string,
		pushkey: string,
	): Promise<void> => {
		await exec("DELETE FROM pushers WHERE app_id = ? AND pushkey = ?", [
			appId,
			pushkey,
		]);
	};

	const storeRelation = async (
		eventId: EventId,
		roomId: RoomId,
		relType: string,
		targetEventId: EventId,
		key?: string,
	): Promise<void> => {
		const rows = (await query(
			"SELECT event_json, stream_pos FROM events WHERE event_id = ?",
			[eventId],
		)) as Record<string, unknown>[];
		if (!rows[0]) return;
		const event = parseJson(rows[0].event_json) as PDU;
		const streamPos = Number(rows[0].stream_pos);
		await exec(
			"INSERT INTO relations (event_id, room_id, rel_type, target_event_id, `key`, sender, event_type, stream_pos) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
			[
				eventId,
				roomId,
				relType,
				targetEventId,
				key ?? null,
				event.sender,
				event.type,
				streamPos,
			],
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
			sql +=
				direction === "f" ? " AND r.stream_pos > ?" : " AND r.stream_pos < ?";
			params.push(fromPos);
		}

		sql +=
			direction === "f"
				? " ORDER BY r.stream_pos ASC LIMIT ?"
				: " ORDER BY r.stream_pos DESC LIMIT ?";
		params.push(limit);

		const rows = (await query(sql, params)) as Record<string, unknown>[];
		const events = rows.map((r) => ({
			event: parseJson(r.event_json) as PDU,
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
		const rows = (await query(
			"SELECT event_type, `key`, COUNT(*) AS cnt FROM relations WHERE target_event_id = ? AND rel_type = 'm.annotation' AND `key` IS NOT NULL GROUP BY event_type, `key`",
			[eventId],
		)) as Record<string, unknown>[];
		return rows.map((r) => ({
			type: r.event_type as string,
			key: r.key as string,
			count: Number(r.cnt),
		}));
	};

	const getLatestEdit = async (
		eventId: EventId,
		sender: UserId,
	): Promise<{ event: PDU; eventId: EventId } | undefined> => {
		const rows = (await query(
			"SELECT r.event_id, e.event_json FROM relations r JOIN events e ON r.event_id = e.event_id WHERE r.target_event_id = ? AND r.rel_type = 'm.replace' AND r.sender = ? ORDER BY r.stream_pos DESC LIMIT 1",
			[eventId, sender],
		)) as Record<string, unknown>[];
		if (!rows[0]) return undefined;
		return {
			event: parseJson(rows[0].event_json) as PDU,
			eventId: rows[0].event_id as EventId,
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
		const [countRow] = (await query(
			"SELECT COUNT(*) AS cnt FROM relations WHERE target_event_id = ? AND rel_type = 'm.thread'",
			[eventId],
		)) as Record<string, unknown>[];
		if (Number(countRow?.cnt) === 0) return undefined;

		const [latestRow] = (await query(
			"SELECT r.event_id, e.event_json FROM relations r JOIN events e ON r.event_id = e.event_id WHERE r.target_event_id = ? AND r.rel_type = 'm.thread' ORDER BY r.stream_pos DESC LIMIT 1",
			[eventId],
		)) as Record<string, unknown>[];
		if (!latestRow) return undefined;

		const participated = (await query(
			"SELECT 1 FROM relations WHERE target_event_id = ? AND rel_type = 'm.thread' AND sender = ? LIMIT 1",
			[eventId, userId],
		)) as Record<string, unknown>[];

		return {
			latestEvent: {
				event: parseJson(latestRow.event_json) as PDU,
				eventId: latestRow.event_id as EventId,
			},
			count: Number(countRow?.cnt),
			currentUserParticipated: participated.length > 0,
		};
	};

	const storeReport = async (
		userId: UserId,
		roomId: RoomId,
		eventId: EventId,
		score?: number,
		reason?: string,
	): Promise<void> => {
		await exec(
			"INSERT INTO reports (user_id, room_id, event_id, score, reason, ts) VALUES (?, ?, ?, ?, ?, ?)",
			[userId, roomId, eventId, score ?? null, reason ?? null, Date.now()],
		);
	};

	const storeOpenIdToken = async (
		token: string,
		userId: UserId,
		expiresAt: Timestamp,
	): Promise<void> => {
		await exec(
			"INSERT INTO openid_tokens (token, user_id, expires_at) VALUES (?, ?, ?) ON DUPLICATE KEY UPDATE user_id = VALUES(user_id), expires_at = VALUES(expires_at)",
			[token, userId, expiresAt],
		);
	};

	const getOpenIdToken = async (
		token: string,
	): Promise<{ userId: UserId; expiresAt: Timestamp } | undefined> => {
		const rows = (await query(
			"SELECT user_id, expires_at FROM openid_tokens WHERE token = ?",
			[token],
		)) as Record<string, unknown>[];
		if (!rows[0]) return undefined;
		return {
			userId: rows[0].user_id as UserId,
			expiresAt: Number(rows[0].expires_at),
		};
	};

	const getThreePids = async (
		userId: UserId,
	): Promise<{ medium: string; address: string; added_at: Timestamp }[]> => {
		const rows = (await query(
			"SELECT medium, address, added_at FROM threepids WHERE user_id = ?",
			[userId],
		)) as Record<string, unknown>[];
		return rows.map((r) => ({
			medium: r.medium as string,
			address: r.address as string,
			added_at: Number(r.added_at),
		}));
	};

	const addThreePid = async (
		userId: UserId,
		medium: string,
		address: string,
	): Promise<void> => {
		await exec(
			"INSERT IGNORE INTO threepids (user_id, medium, address, added_at) VALUES (?, ?, ?, ?)",
			[userId, medium, address, Date.now()],
		);
	};

	const deleteThreePid = async (
		userId: UserId,
		medium: string,
		address: string,
	): Promise<void> => {
		await exec(
			"DELETE FROM threepids WHERE user_id = ? AND medium = ? AND address = ?",
			[userId, medium, address],
		);
	};

	const searchUserDirectory = async (
		searchTerm: string,
		limit: number,
	): Promise<
		{ user_id: UserId; display_name?: string; avatar_url?: string }[]
	> => {
		const term = `%${searchTerm}%`;
		const rows = (await query(
			"SELECT user_id, displayname, avatar_url FROM users WHERE is_deactivated = FALSE AND (user_id LIKE ? OR displayname LIKE ?) LIMIT ?",
			[term, term, limit],
		)) as Record<string, unknown>[];
		return rows.map((r) => ({
			user_id: r.user_id as UserId,
			display_name: (r.displayname as string) ?? undefined,
			avatar_url: (r.avatar_url as string) ?? undefined,
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
			SELECT r.target_event_id, MAX(r.stream_pos) AS latest_pos, e.event_json
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
		sql +=
			" GROUP BY r.target_event_id, e.event_json ORDER BY latest_pos DESC LIMIT ?";
		params.push(limit);

		const rows = (await query(sql, params)) as Record<string, unknown>[];
		const events = rows.map((r) => ({
			event: parseJson(r.event_json) as PDU,
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

		const rows = (await query(sql, [...roomIds])) as Record<string, unknown>[];

		const allMatches: { event: PDU; eventId: EventId; streamPos: number }[] =
			[];
		for (const row of rows) {
			const event = parseJson(row.event_json) as PDU;
			if (eventMatchesSearchTerm(event, keys, searchTerm)) {
				allMatches.push({
					event,
					eventId: row.event_id as EventId,
					streamPos: Number(row.stream_pos),
				});
			}
		}

		return paginateSearchMatches(allMatches, limit, from);
	};

	const storeServerKeys = async (
		serverName: ServerName,
		keys: ServerKeys,
	): Promise<void> => {
		const conn = await pool.getConnection();
		try {
			await conn.beginTransaction();
			for (const [keyId, val] of Object.entries(keys.verify_keys)) {
				await conn.query(
					"INSERT INTO server_keys (server_name, key_id, `key`, valid_until) VALUES (?, ?, ?, ?) ON DUPLICATE KEY UPDATE `key` = VALUES(`key`), valid_until = VALUES(valid_until)",
					[serverName, keyId, val.key, keys.valid_until_ts],
				);
			}
			await conn.commit();
		} catch (e) {
			await conn.rollback();
			throw e;
		} finally {
			conn.release();
		}
	};

	const getServerKeys = async (
		serverName: ServerName,
		keyId: KeyId,
	): Promise<{ key: string; validUntil: number } | undefined> => {
		const rows = (await query(
			"SELECT `key`, valid_until FROM server_keys WHERE server_name = ? AND key_id = ?",
			[serverName, keyId],
		)) as Record<string, unknown>[];
		if (!rows[0]) return undefined;
		return {
			key: rows[0].key as string,
			validUntil: Number(rows[0].valid_until),
		};
	};

	const getAuthChain = async (eventIds: EventId[]): Promise<PDU[]> => {
		const visited = new Set<EventId>();
		const result: PDU[] = [];
		const queue = [...eventIds];

		while (queue.length > 0) {
			const id = queue.shift() as EventId;
			if (visited.has(id)) continue;
			visited.add(id);
			const rows = (await query(
				"SELECT event_json FROM events WHERE event_id = ?",
				[id],
			)) as Record<string, unknown>[];
			if (!rows[0]) continue;
			const event = parseJson(rows[0].event_json) as PDU;
			result.push(event);
			for (const authId of event.auth_events) {
				if (!visited.has(authId)) queue.push(authId);
			}
		}
		return result;
	};

	const getServersInRoom = async (roomId: RoomId): Promise<ServerName[]> => {
		const rows = (await query(
			"SELECT state_key FROM state_events WHERE room_id = ? AND event_type = 'm.room.member' AND JSON_UNQUOTE(JSON_EXTRACT(event_json, '$.content.membership')) = 'join'",
			[roomId],
		)) as Record<string, unknown>[];
		const servers = new Set<ServerName>();
		for (const r of rows) {
			const serverName = (r.state_key as string)
				.split(":")
				.slice(1)
				.join(":") as ServerName;
			servers.add(serverName);
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
		await setStateEvent(roomId, event, eventId);
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
		await pool.query("DELETE FROM events WHERE event_id = ?", [eventId]);
		await pool.query("DELETE FROM state_events WHERE event_id = ?", [eventId]);
	};

	const unrejectEvent = async (_eventId: EventId): Promise<void> => {
		// deleteEvent is destructive here (no rejected flag), so there is nothing
		// to restore. No-op; partial-state resync re-evaluation targets sqlite.
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
		const room = await getRoom(_roomId);
		if (!room) return undefined;
		return new Map(room.state_events);
	};

	const getFederationTxn = async (
		origin: ServerName,
		txnId: string,
	): Promise<boolean> => {
		const rows = (await query(
			"SELECT 1 FROM federation_txns WHERE origin = ? AND txn_id = ?",
			[origin, txnId],
		)) as unknown[];
		return rows.length > 0;
	};

	const setFederationTxn = async (
		origin: ServerName,
		txnId: string,
	): Promise<void> => {
		await exec(
			"INSERT IGNORE INTO federation_txns (origin, txn_id) VALUES (?, ?)",
			[origin, txnId],
		);
	};

	const enqueueFederationEdu = async (
		destination: ServerName,
		edu: EDU,
	): Promise<number> => {
		const result = await exec(
			"INSERT INTO pending_federation_edus (destination, edu_json) VALUES (?, ?)",
			[destination, JSON.stringify(edu)],
		);
		const id = Number(result.insertId);
		// Enforce the per-destination cap by deleting the oldest overflow rows.
		const countRows = (await query(
			"SELECT COUNT(*) AS c FROM pending_federation_edus WHERE destination = ?",
			[destination],
		)) as { c: number | bigint }[];
		const count = Number(countRows[0]?.c ?? 0);
		if (count > PENDING_FEDERATION_EDU_CAP) {
			const overflow = count - PENDING_FEDERATION_EDU_CAP;
			await exec(
				"DELETE FROM pending_federation_edus WHERE destination = ? ORDER BY id ASC LIMIT ?",
				[destination, overflow],
			);
			console.warn(
				`pending_federation_edus: dropped ${overflow} EDU(s) for ${destination} (queue cap ${PENDING_FEDERATION_EDU_CAP} exceeded)`,
			);
		}
		return id;
	};

	const getPendingFederationEdus = async (
		destination: ServerName,
		limit: number,
	): Promise<{ id: number; edu: EDU }[]> => {
		const rows = (await query(
			"SELECT id, edu_json FROM pending_federation_edus WHERE destination = ? ORDER BY id ASC LIMIT ?",
			[destination, limit],
		)) as { id: number | bigint; edu_json: string }[];
		return rows.map((r) => ({
			id: Number(r.id),
			edu: JSON.parse(r.edu_json) as EDU,
		}));
	};

	const deleteFederationEdu = async (id: number): Promise<void> => {
		await exec("DELETE FROM pending_federation_edus WHERE id = ?", [id]);
	};

	const getPendingFederationDestinations = async (): Promise<ServerName[]> => {
		const rows = (await query(
			"SELECT DISTINCT destination FROM pending_federation_edus",
		)) as { destination: string }[];
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
		const conn = await pool.getConnection();
		try {
			await conn.beginTransaction();
			for (const event of authChain) {
				const eventId = computeEventId(event, roomVersion);
				eph.streamCounter++;
				await conn.query(
					"INSERT IGNORE INTO events (event_id, room_id, stream_pos, event_json) VALUES (?, ?, ?, ?)",
					[eventId, event.room_id, eph.streamCounter, json(event)],
				);
			}

			let maxDepth = 0;
			const extremities: EventId[] = [];
			for (const event of stateEvents) {
				const eventId = computeEventId(event, roomVersion);
				eph.streamCounter++;
				await conn.query(
					"INSERT IGNORE INTO events (event_id, room_id, stream_pos, event_json) VALUES (?, ?, ?, ?)",
					[eventId, event.room_id, eph.streamCounter, json(event)],
				);
				await conn.query(
					`INSERT INTO state_events (room_id, event_type, state_key, event_id, event_json) VALUES (?, ?, ?, ?, ?)
					 ON DUPLICATE KEY UPDATE event_id = VALUES(event_id), event_json = VALUES(event_json)`,
					[roomId, event.type, event.state_key ?? "", eventId, json(event)],
				);
				if (event.depth > maxDepth) maxDepth = event.depth;
				extremities.length = 0;
				extremities.push(eventId);
			}

			await conn.query(
				`INSERT INTO rooms (room_id, room_version, depth, forward_extremities) VALUES (?, ?, ?, ?)
				 ON DUPLICATE KEY UPDATE room_version = VALUES(room_version), depth = VALUES(depth), forward_extremities = VALUES(forward_extremities)`,
				[roomId, roomVersion, maxDepth + 1, json(extremities)],
			);
			await conn.commit();
		} catch (e) {
			await conn.rollback();
			throw e;
		} finally {
			conn.release();
		}
		eph.wakeWaiters();
	};

	const uri = connectionString.replace(/^mysql:\/\//, "mariadb://");
	pool = mariadb.createPool(`${uri}?connectionLimit=20`);
	await init();

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
