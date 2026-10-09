import pg from "pg";
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

export const createPostgresStorage = async (
	connectionString: string,
): Promise<Storage> => {
	const eph = createEphemeralStore();
	let pool: pg.Pool;

	const init = async (): Promise<void> => {
		await pool.query(`
			CREATE TABLE IF NOT EXISTS users (
				user_id TEXT PRIMARY KEY,
				localpart TEXT UNIQUE NOT NULL,
				server_name TEXT NOT NULL,
				password_hash TEXT NOT NULL,
				account_type TEXT NOT NULL DEFAULT 'user',
				is_deactivated BOOLEAN NOT NULL DEFAULT FALSE,
				created_at BIGINT NOT NULL,
				displayname TEXT,
				avatar_url TEXT
			);

			CREATE TABLE IF NOT EXISTS sessions (
				access_token TEXT PRIMARY KEY,
				refresh_token TEXT,
				device_id TEXT NOT NULL,
				user_id TEXT NOT NULL,
				access_token_hash TEXT,
				expires_at BIGINT,
				display_name TEXT,
				last_seen_ip TEXT,
				last_seen_ts BIGINT,
				user_agent TEXT
			);
			CREATE INDEX IF NOT EXISTS idx_sessions_user ON sessions(user_id);
			CREATE INDEX IF NOT EXISTS idx_sessions_refresh ON sessions(refresh_token) WHERE refresh_token IS NOT NULL;
			CREATE INDEX IF NOT EXISTS idx_sessions_device ON sessions(user_id, device_id);

			CREATE TABLE IF NOT EXISTS uiaa_sessions (
				session_id TEXT PRIMARY KEY,
				completed JSONB NOT NULL DEFAULT '[]'
			);

			CREATE TABLE IF NOT EXISTS rooms (
				room_id TEXT PRIMARY KEY,
				room_version TEXT NOT NULL,
				depth INT NOT NULL DEFAULT 0,
				forward_extremities JSONB NOT NULL DEFAULT '[]'
			);

			CREATE TABLE IF NOT EXISTS events (
				event_id TEXT PRIMARY KEY,
				room_id TEXT NOT NULL,
				stream_pos BIGINT NOT NULL,
				event_json JSONB NOT NULL
			);
			CREATE INDEX IF NOT EXISTS idx_events_room ON events(room_id);
			CREATE INDEX IF NOT EXISTS idx_events_stream ON events(room_id, stream_pos);

			CREATE TABLE IF NOT EXISTS state_events (
				room_id TEXT NOT NULL,
				event_type TEXT NOT NULL,
				state_key TEXT NOT NULL,
				event_id TEXT NOT NULL,
				event_json JSONB NOT NULL,
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
				servers JSONB NOT NULL DEFAULT '[]',
				creator TEXT NOT NULL
			);

			CREATE TABLE IF NOT EXISTS room_directory (
				room_id TEXT PRIMARY KEY,
				visibility TEXT NOT NULL DEFAULT 'private'
			);

			CREATE TABLE IF NOT EXISTS global_account_data (
				user_id TEXT NOT NULL,
				type TEXT NOT NULL,
				content JSONB NOT NULL,
				stream_pos BIGINT NOT NULL DEFAULT 0,
				PRIMARY KEY (user_id, type)
			);

			CREATE TABLE IF NOT EXISTS room_account_data (
				user_id TEXT NOT NULL,
				room_id TEXT NOT NULL,
				type TEXT NOT NULL,
				content JSONB NOT NULL,
				stream_pos BIGINT NOT NULL DEFAULT 0,
				PRIMARY KEY (user_id, room_id, type)
			);

			CREATE TABLE IF NOT EXISTS receipts (
				room_id TEXT NOT NULL,
				user_id TEXT NOT NULL,
				event_id TEXT NOT NULL,
				receipt_type TEXT NOT NULL,
				ts BIGINT NOT NULL,
				thread_id TEXT NOT NULL DEFAULT '',
				PRIMARY KEY (room_id, user_id, receipt_type, thread_id)
			);

			CREATE TABLE IF NOT EXISTS media (
				origin TEXT NOT NULL,
				media_id TEXT NOT NULL,
				user_id TEXT,
				content_type TEXT NOT NULL,
				upload_name TEXT,
				file_size BIGINT NOT NULL,
				content_hash TEXT NOT NULL,
				created_at BIGINT NOT NULL,
				quarantined BOOLEAN NOT NULL DEFAULT FALSE,
				data BYTEA NOT NULL,
				PRIMARY KEY (origin, media_id)
			);

			CREATE TABLE IF NOT EXISTS filters (
				user_id TEXT NOT NULL,
				filter_id BIGINT NOT NULL,
				filter_json JSONB NOT NULL,
				PRIMARY KEY (user_id, filter_id)
			);

			CREATE TABLE IF NOT EXISTS device_keys (
				user_id TEXT NOT NULL,
				device_id TEXT NOT NULL,
				keys_json JSONB NOT NULL,
				PRIMARY KEY (user_id, device_id)
			);

			CREATE TABLE IF NOT EXISTS one_time_keys (
				user_id TEXT NOT NULL,
				device_id TEXT NOT NULL,
				key_id TEXT NOT NULL,
				algorithm TEXT NOT NULL,
				key_json JSONB NOT NULL,
				PRIMARY KEY (user_id, device_id, key_id)
			);

			CREATE TABLE IF NOT EXISTS fallback_keys (
				user_id TEXT NOT NULL,
				device_id TEXT NOT NULL,
				key_id TEXT NOT NULL,
				key_json JSONB NOT NULL,
				PRIMARY KEY (user_id, device_id, key_id)
			);

			CREATE TABLE IF NOT EXISTS to_device (
				id BIGSERIAL PRIMARY KEY,
				user_id TEXT NOT NULL,
				device_id TEXT NOT NULL,
				event_json JSONB NOT NULL
			);
			CREATE INDEX IF NOT EXISTS idx_to_device ON to_device(user_id, device_id);

			CREATE TABLE IF NOT EXISTS pushers (
				user_id TEXT NOT NULL,
				app_id TEXT NOT NULL,
				pushkey TEXT NOT NULL,
				pusher_json JSONB NOT NULL,
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
				stream_pos BIGINT NOT NULL
			);
			CREATE INDEX IF NOT EXISTS idx_relations_target ON relations(target_event_id);

			CREATE TABLE IF NOT EXISTS reports (
				id BIGSERIAL PRIMARY KEY,
				user_id TEXT NOT NULL,
				room_id TEXT NOT NULL,
				event_id TEXT NOT NULL,
				score INT,
				reason TEXT,
				ts BIGINT NOT NULL
			);

			CREATE TABLE IF NOT EXISTS openid_tokens (
				token TEXT PRIMARY KEY,
				user_id TEXT NOT NULL,
				expires_at BIGINT NOT NULL
			);

			CREATE TABLE IF NOT EXISTS threepids (
				user_id TEXT NOT NULL,
				medium TEXT NOT NULL,
				address TEXT NOT NULL,
				added_at BIGINT NOT NULL,
				PRIMARY KEY (user_id, medium, address)
			);

			CREATE TABLE IF NOT EXISTS server_keys (
				server_name TEXT NOT NULL,
				key_id TEXT NOT NULL,
				key TEXT NOT NULL,
				valid_until BIGINT NOT NULL,
				PRIMARY KEY (server_name, key_id)
			);

			CREATE TABLE IF NOT EXISTS federation_txns (
				origin TEXT NOT NULL,
				txn_id TEXT NOT NULL,
				PRIMARY KEY (origin, txn_id)
			);

			CREATE TABLE IF NOT EXISTS pending_federation_edus (
				id BIGSERIAL PRIMARY KEY,
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
				id SERIAL PRIMARY KEY,
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

			CREATE TABLE IF NOT EXISTS device_list_stream (
				user_id TEXT NOT NULL,
				stream_pos BIGINT NOT NULL
			);
			CREATE INDEX IF NOT EXISTS idx_device_list_stream ON device_list_stream(stream_pos);
		`);

		const {
			rows: [maxPos],
		} = await pool.query<{ m: string | null }>(
			`SELECT MAX(m) AS m FROM (
				SELECT MAX(stream_pos) AS m FROM events
				UNION ALL SELECT MAX(stream_pos) FROM global_account_data
				UNION ALL SELECT MAX(stream_pos) FROM room_account_data
				UNION ALL SELECT MAX(stream_pos) FROM device_list_stream
			) sub`,
		);
		eph.streamCounter = maxPos?.m ? parseInt(maxPos.m, 10) : 0;

		const {
			rows: [maxFilter],
		} = await pool.query<{ m: string | null }>(
			"SELECT MAX(filter_id) AS m FROM filters",
		);
		eph.filterCounter = maxFilter?.m ? parseInt(maxFilter.m, 10) : 0;
	};

	const createUser = async (account: UserAccount): Promise<void> => {
		await pool.query(
			`INSERT INTO users (user_id, localpart, server_name, password_hash, account_type, is_deactivated, created_at, displayname, avatar_url)
			 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
			 ON CONFLICT (user_id) DO UPDATE SET
				localpart = EXCLUDED.localpart, server_name = EXCLUDED.server_name, password_hash = EXCLUDED.password_hash,
				account_type = EXCLUDED.account_type, is_deactivated = EXCLUDED.is_deactivated, created_at = EXCLUDED.created_at,
				displayname = EXCLUDED.displayname, avatar_url = EXCLUDED.avatar_url`,
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
		const { rows } = await pool.query(
			"SELECT * FROM users WHERE localpart = $1",
			[localpart],
		);
		return rows[0] ? rowToUser(rows[0]) : undefined;
	};

	const getUserById = async (
		userId: UserId,
	): Promise<UserAccount | undefined> => {
		const { rows } = await pool.query(
			"SELECT * FROM users WHERE user_id = $1",
			[userId],
		);
		return rows[0] ? rowToUser(rows[0]) : undefined;
	};

	const createSession = async (session: StoredSession): Promise<void> => {
		await pool.query(
			`INSERT INTO sessions (access_token, refresh_token, device_id, user_id, access_token_hash, expires_at, display_name, last_seen_ip, last_seen_ts, user_agent)
			 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
			 ON CONFLICT (access_token) DO UPDATE SET
				refresh_token = EXCLUDED.refresh_token, device_id = EXCLUDED.device_id, user_id = EXCLUDED.user_id,
				access_token_hash = EXCLUDED.access_token_hash, expires_at = EXCLUDED.expires_at, display_name = EXCLUDED.display_name,
				last_seen_ip = EXCLUDED.last_seen_ip, last_seen_ts = EXCLUDED.last_seen_ts, user_agent = EXCLUDED.user_agent`,
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
		const { rows } = await pool.query(
			"SELECT * FROM sessions WHERE access_token = $1",
			[token],
		);
		return rows[0] ? rowToSession(rows[0]) : undefined;
	};

	const getSessionByRefreshToken = async (
		token: RefreshToken,
	): Promise<StoredSession | undefined> => {
		const { rows } = await pool.query(
			"SELECT * FROM sessions WHERE refresh_token = $1",
			[token],
		);
		return rows[0] ? rowToSession(rows[0]) : undefined;
	};

	const getSessionsByUser = async (
		userId: UserId,
	): Promise<StoredSession[]> => {
		const { rows } = await pool.query(
			"SELECT * FROM sessions WHERE user_id = $1",
			[userId],
		);
		return rows.map((r) => rowToSession(r));
	};

	const deleteSession = async (token: AccessToken): Promise<void> => {
		await pool.query("DELETE FROM sessions WHERE access_token = $1", [token]);
	};

	const deleteAllSessions = async (userId: UserId): Promise<void> => {
		await pool.query("DELETE FROM sessions WHERE user_id = $1", [userId]);
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
		await pool.query(
			"UPDATE sessions SET last_seen_ip = $1, last_seen_ts = $2, user_agent = $3 WHERE access_token = $4",
			[ip, Date.now(), userAgent, token],
		);
	};

	const createUIAASession = async (sessionId: string): Promise<void> => {
		await pool.query(
			"INSERT INTO uiaa_sessions (session_id, completed) VALUES ($1, '[]'::jsonb) ON CONFLICT (session_id) DO UPDATE SET completed = '[]'::jsonb",
			[sessionId],
		);
	};

	const getUIAASession = async (
		sessionId: string,
	): Promise<{ completed: string[] } | undefined> => {
		const { rows } = await pool.query(
			"SELECT completed FROM uiaa_sessions WHERE session_id = $1",
			[sessionId],
		);
		if (!rows[0]) return undefined;
		return { completed: rows[0].completed };
	};

	const addUIAACompleted = async (
		sessionId: string,
		stageType: string,
	): Promise<void> => {
		await pool.query(
			"UPDATE uiaa_sessions SET completed = completed || $1::jsonb WHERE session_id = $2",
			[JSON.stringify([stageType]), sessionId],
		);
	};

	const deleteUIAASession = async (sessionId: string): Promise<void> => {
		await pool.query("DELETE FROM uiaa_sessions WHERE session_id = $1", [
			sessionId,
		]);
	};

	const createRoom = async (state: RoomState): Promise<void> => {
		const client = await pool.connect();
		try {
			await client.query("BEGIN");
			await client.query(
				`INSERT INTO rooms (room_id, room_version, depth, forward_extremities) VALUES ($1, $2, $3, $4)
				 ON CONFLICT (room_id) DO UPDATE SET room_version = EXCLUDED.room_version, depth = EXCLUDED.depth, forward_extremities = EXCLUDED.forward_extremities`,
				[
					state.room_id,
					state.room_version,
					state.depth,
					JSON.stringify(state.forward_extremities),
				],
			);
			for (const [key, event] of state.state_events) {
				const [eventType, stateKey] = key.split("\x1f") as [string, string];
				const eventId = computeEventId(event, state.room_version);
				await client.query(
					`INSERT INTO state_events (room_id, event_type, state_key, event_id, event_json) VALUES ($1, $2, $3, $4, $5)
					 ON CONFLICT (room_id, event_type, state_key) DO UPDATE SET event_id = EXCLUDED.event_id, event_json = EXCLUDED.event_json`,
					[state.room_id, eventType, stateKey, eventId, JSON.stringify(event)],
				);
			}
			await client.query("COMMIT");
		} catch (e) {
			await client.query("ROLLBACK");
			throw e;
		} finally {
			client.release();
		}
		eph.roomCache.set(state.room_id, state);
	};

	const getRoom = async (roomId: RoomId): Promise<RoomState | undefined> => {
		const cached = eph.roomCache.get(roomId);
		if (cached) return cached;

		const { rows } = await pool.query(
			"SELECT * FROM rooms WHERE room_id = $1",
			[roomId],
		);
		if (!rows[0]) return undefined;
		const row = rows[0];

		const { rows: stateRows } = await pool.query(
			"SELECT event_type, state_key, event_json FROM state_events WHERE room_id = $1",
			[roomId],
		);
		const stateMap = new Map<string, PDU>();
		for (const sr of stateRows) {
			stateMap.set(`${sr.event_type}\x1f${sr.state_key}`, sr.event_json);
		}

		const room: RoomState = {
			room_id: row.room_id as RoomId,
			room_version: row.room_version as RoomVersion,
			state_events: stateMap,
			depth: row.depth,
			forward_extremities: row.forward_extremities,
		};
		eph.roomCache.set(roomId, room);
		return room;
	};

	const getRoomsForUser = async (userId: UserId): Promise<RoomId[]> => {
		const { rows } = await pool.query(
			"SELECT room_id FROM state_events WHERE event_type = 'm.room.member' AND state_key = $1 AND event_json->'content'->>'membership' = 'join'",
			[userId],
		);
		return rows.map((r) => r.room_id as RoomId);
	};

	const storeEvent = async (event: PDU, eventId: EventId): Promise<void> => {
		eph.streamCounter++;
		await pool.query(
			`INSERT INTO events (event_id, room_id, stream_pos, event_json) VALUES ($1, $2, $3, $4)
			 ON CONFLICT (event_id) DO UPDATE SET room_id = EXCLUDED.room_id, stream_pos = EXCLUDED.stream_pos, event_json = EXCLUDED.event_json`,
			[eventId, event.room_id, eph.streamCounter, JSON.stringify(event)],
		);
		eph.wakeWaiters();
	};

	const updateEvent = async (eventId: EventId, event: PDU): Promise<void> => {
		await pool.query("UPDATE events SET event_json = $1 WHERE event_id = $2", [
			JSON.stringify(event),
			eventId,
		]);
	};

	const getEvent = async (
		eventId: EventId,
	): Promise<{ event: PDU; eventId: EventId } | undefined> => {
		const { rows } = await pool.query(
			"SELECT event_id, event_json FROM events WHERE event_id = $1",
			[eventId],
		);
		if (!rows[0]) return undefined;
		return { event: rows[0].event_json, eventId: rows[0].event_id as EventId };
	};

	const getEventsByRoom = async (
		roomId: RoomId,
		limit: number,
		from?: number,
		direction: "b" | "f" = "f",
	): Promise<{ events: { event: PDU; eventId: EventId }[]; end?: number }> => {
		const fromPos = from ?? (direction === "f" ? 0 : eph.streamCounter + 1);
		let rows: { event_id: string; event_json: PDU; stream_pos: string }[];

		if (direction === "f") {
			({ rows } = await pool.query(
				"SELECT event_id, event_json, stream_pos FROM events WHERE room_id = $1 AND stream_pos > $2 ORDER BY stream_pos ASC LIMIT $3",
				[roomId, fromPos, limit],
			));
		} else {
			({ rows } = await pool.query(
				"SELECT event_id, event_json, stream_pos FROM events WHERE room_id = $1 AND stream_pos < $2 ORDER BY stream_pos DESC LIMIT $3",
				[roomId, fromPos, limit],
			));
		}

		const events = rows.map((r) => ({
			event: r.event_json,
			eventId: r.event_id as EventId,
		}));
		const lastRow = rows[rows.length - 1];
		const end = lastRow
			? parseInt(lastRow.stream_pos as string, 10)
			: undefined;
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
		const { rows } = await pool.query(
			"SELECT event_id, event_json FROM state_events WHERE room_id = $1 AND event_type = $2 AND state_key = $3",
			[roomId, eventType, stateKey],
		);
		if (!rows[0]) return undefined;
		return { event: rows[0].event_json, eventId: rows[0].event_id as EventId };
	};

	const getAllState = async (
		roomId: RoomId,
	): Promise<{ event: PDU; eventId: EventId }[]> => {
		const { rows } = await pool.query(
			"SELECT event_id, event_json FROM state_events WHERE room_id = $1",
			[roomId],
		);
		return rows.map((r) => ({
			event: r.event_json,
			eventId: r.event_id as EventId,
		}));
	};

	const setStateEvent = async (
		roomId: RoomId,
		event: PDU,
		eventId: EventId,
	): Promise<void> => {
		await pool.query(
			`INSERT INTO state_events (room_id, event_type, state_key, event_id, event_json) VALUES ($1, $2, $3, $4, $5)
			 ON CONFLICT (room_id, event_type, state_key) DO UPDATE SET event_id = EXCLUDED.event_id, event_json = EXCLUDED.event_json`,
			[
				roomId,
				event.type,
				event.state_key ?? "",
				eventId,
				JSON.stringify(event),
			],
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
		const { rows } = await pool.query(
			"SELECT event_id, event_json FROM state_events WHERE room_id = $1 AND event_type = 'm.room.member'",
			[roomId],
		);
		return rows.map((r) => ({
			event: r.event_json,
			eventId: r.event_id as EventId,
		}));
	};

	const getTxnEventId = async (
		userId: UserId,
		deviceId: DeviceId,
		txnId: string,
	): Promise<EventId | undefined> => {
		const { rows } = await pool.query(
			"SELECT event_id FROM txn_map WHERE user_id = $1 AND device_id = $2 AND txn_id = $3",
			[userId, deviceId, txnId],
		);
		return rows[0] ? (rows[0].event_id as EventId) : undefined;
	};

	const setTxnEventId = async (
		userId: UserId,
		deviceId: DeviceId,
		txnId: string,
		eventId: EventId,
	): Promise<void> => {
		await pool.query(
			"INSERT INTO txn_map (user_id, device_id, txn_id, event_id) VALUES ($1, $2, $3, $4) ON CONFLICT (user_id, device_id, txn_id) DO UPDATE SET event_id = EXCLUDED.event_id",
			[userId, deviceId, txnId, eventId],
		);
	};

	const getRoomsForUserWithMembership = async (
		userId: UserId,
	): Promise<{ roomId: RoomId; membership: string }[]> => {
		const { rows } = await pool.query(
			"SELECT room_id, event_json->'content'->>'membership' AS membership FROM state_events WHERE event_type = 'm.room.member' AND state_key = $1",
			[userId],
		);
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
		const {
			rows: [countRow],
		} = await pool.query(
			"SELECT COUNT(*) AS cnt FROM events WHERE room_id = $1 AND stream_pos > $2",
			[roomId, since],
		);
		const total = parseInt(countRow.cnt, 10);
		const limited = total > limit;

		let rows: { event_id: string; event_json: PDU; stream_pos: string }[];
		if (limited) {
			({ rows } = await pool.query(
				"SELECT event_id, event_json, stream_pos FROM events WHERE room_id = $1 AND stream_pos > $2 ORDER BY stream_pos DESC LIMIT $3",
				[roomId, since, limit],
			));
			rows.reverse();
		} else {
			({ rows } = await pool.query(
				"SELECT event_id, event_json, stream_pos FROM events WHERE room_id = $1 AND stream_pos > $2 ORDER BY stream_pos ASC",
				[roomId, since],
			));
		}

		const events = rows.map((r) => ({
			event: r.event_json,
			eventId: r.event_id as EventId,
			streamPos: parseInt(r.stream_pos as string, 10),
		}));
		return { events, limited };
	};

	const getStrippedState = async (
		roomId: RoomId,
	): Promise<StrippedStateEvent[]> => {
		const { rows } = await pool.query(
			"SELECT event_json FROM state_events WHERE room_id = $1 AND event_type = ANY($2)",
			[roomId, INVITE_STATE_TYPES],
		);
		return rows.map((r) => {
			const event = r.event_json as PDU;
			return eventToStrippedState(event);
		});
	};

	const getProfile = async (
		userId: UserId,
	): Promise<UserProfile | undefined> => {
		const { rows } = await pool.query(
			"SELECT displayname, avatar_url FROM users WHERE user_id = $1",
			[userId],
		);
		if (!rows[0]) return undefined;
		const profile: UserProfile = {};
		if (rows[0].displayname) profile.displayname = rows[0].displayname;
		if (rows[0].avatar_url) profile.avatar_url = rows[0].avatar_url;
		return profile;
	};

	const setDisplayName = async (
		userId: UserId,
		displayname: string | null,
	): Promise<void> => {
		await pool.query("UPDATE users SET displayname = $1 WHERE user_id = $2", [
			displayname,
			userId,
		]);
	};

	const setAvatarUrl = async (
		userId: UserId,
		avatarUrl: string | null,
	): Promise<void> => {
		await pool.query("UPDATE users SET avatar_url = $1 WHERE user_id = $2", [
			avatarUrl,
			userId,
		]);
	};

	const getDevice = async (
		userId: UserId,
		deviceId: DeviceId,
	): Promise<Device | undefined> => {
		const { rows } = await pool.query(
			"SELECT device_id, display_name, last_seen_ip, last_seen_ts FROM sessions WHERE user_id = $1 AND device_id = $2 LIMIT 1",
			[userId, deviceId],
		);
		if (!rows[0]) return undefined;
		return {
			device_id: rows[0].device_id as DeviceId,
			display_name: rows[0].display_name ?? undefined,
			last_seen_ip: rows[0].last_seen_ip ?? undefined,
			last_seen_ts: rows[0].last_seen_ts
				? Number(rows[0].last_seen_ts)
				: undefined,
		};
	};

	const getAllDevices = async (userId: UserId): Promise<Device[]> => {
		const { rows } = await pool.query(
			"SELECT DISTINCT ON (device_id) device_id, display_name, last_seen_ip, last_seen_ts FROM sessions WHERE user_id = $1",
			[userId],
		);
		return rows.map((r) => ({
			device_id: r.device_id as DeviceId,
			display_name: r.display_name ?? undefined,
			last_seen_ip: r.last_seen_ip ?? undefined,
			last_seen_ts: r.last_seen_ts ? Number(r.last_seen_ts) : undefined,
		}));
	};

	const updateDeviceDisplayName = async (
		userId: UserId,
		deviceId: DeviceId,
		displayName: string,
	): Promise<void> => {
		await pool.query(
			"UPDATE sessions SET display_name = $1 WHERE user_id = $2 AND device_id = $3",
			[displayName, userId, deviceId],
		);
	};

	const deleteDeviceSession = async (
		userId: UserId,
		deviceId: DeviceId,
	): Promise<void> => {
		await pool.query(
			"DELETE FROM sessions WHERE user_id = $1 AND device_id = $2",
			[userId, deviceId],
		);
	};

	const updatePassword = async (
		userId: UserId,
		newPasswordHash: string,
	): Promise<void> => {
		await pool.query("UPDATE users SET password_hash = $1 WHERE user_id = $2", [
			newPasswordHash,
			userId,
		]);
	};

	const deactivateUser = async (userId: UserId): Promise<void> => {
		await pool.query(
			"UPDATE users SET is_deactivated = TRUE WHERE user_id = $1",
			[userId],
		);
		await deleteAllSessions(userId);
	};

	const createRoomAlias = async (
		roomAlias: RoomAlias,
		roomId: RoomId,
		servers: ServerName[],
		creator: UserId,
	): Promise<void> => {
		await pool.query(
			"INSERT INTO room_aliases (room_alias, room_id, servers, creator) VALUES ($1, $2, $3, $4) ON CONFLICT (room_alias) DO UPDATE SET room_id = EXCLUDED.room_id, servers = EXCLUDED.servers, creator = EXCLUDED.creator",
			[roomAlias, roomId, JSON.stringify(servers), creator],
		);
	};

	const deleteRoomAlias = async (roomAlias: RoomAlias): Promise<boolean> => {
		const result = await pool.query(
			"DELETE FROM room_aliases WHERE room_alias = $1",
			[roomAlias],
		);
		return (result.rowCount ?? 0) > 0;
	};

	const getRoomByAlias = async (
		roomAlias: RoomAlias,
	): Promise<{ room_id: RoomId; servers: ServerName[] } | undefined> => {
		const { rows } = await pool.query(
			"SELECT room_id, servers FROM room_aliases WHERE room_alias = $1",
			[roomAlias],
		);
		if (!rows[0]) return undefined;
		return { room_id: rows[0].room_id as RoomId, servers: rows[0].servers };
	};

	const getAliasesForRoom = async (roomId: RoomId): Promise<RoomAlias[]> => {
		const { rows } = await pool.query(
			"SELECT room_alias FROM room_aliases WHERE room_id = $1",
			[roomId],
		);
		return rows.map((r) => r.room_alias as RoomAlias);
	};

	const getAliasCreator = async (
		roomAlias: RoomAlias,
	): Promise<UserId | undefined> => {
		const { rows } = await pool.query(
			"SELECT creator FROM room_aliases WHERE room_alias = $1",
			[roomAlias],
		);
		return rows[0] ? (rows[0].creator as UserId) : undefined;
	};

	const setRoomVisibility = async (
		roomId: RoomId,
		visibility: "public" | "private",
	): Promise<void> => {
		await pool.query(
			"INSERT INTO room_directory (room_id, visibility) VALUES ($1, $2) ON CONFLICT (room_id) DO UPDATE SET visibility = EXCLUDED.visibility",
			[roomId, visibility],
		);
	};

	const getRoomVisibility = async (
		roomId: RoomId,
	): Promise<"public" | "private"> => {
		const { rows } = await pool.query(
			"SELECT visibility FROM room_directory WHERE room_id = $1",
			[roomId],
		);
		return (rows[0]?.visibility as "public" | "private") ?? "private";
	};

	const getPublicRoomIds = async (): Promise<RoomId[]> => {
		const { rows } = await pool.query(
			"SELECT room_id FROM room_directory WHERE visibility = 'public'",
		);
		return rows.map((r) => r.room_id as RoomId);
	};

	const getGlobalAccountData = async (
		userId: UserId,
		type: string,
	): Promise<JsonObject | undefined> => {
		const { rows } = await pool.query(
			"SELECT content FROM global_account_data WHERE user_id = $1 AND type = $2",
			[userId, type],
		);
		return rows[0]?.content ?? undefined;
	};

	const setGlobalAccountData = async (
		userId: UserId,
		type: string,
		content: JsonObject,
	): Promise<void> => {
		await pool.query(
			"INSERT INTO global_account_data (user_id, type, content, stream_pos) VALUES ($1, $2, $3, $4) ON CONFLICT (user_id, type) DO UPDATE SET content = EXCLUDED.content, stream_pos = EXCLUDED.stream_pos",
			[userId, type, JSON.stringify(content), ++eph.streamCounter],
		);
		eph.wakeWaiters();
	};

	const getAllGlobalAccountData = async (
		userId: UserId,
	): Promise<{ type: string; content: JsonObject }[]> => {
		const { rows } = await pool.query(
			// Exclude MSC3391 deletion tombstones (content '{}') from initial sync.
			"SELECT type, content FROM global_account_data WHERE user_id = $1 AND content <> '{}'::jsonb",
			[userId],
		);
		return rows.map((r) => ({ type: r.type, content: r.content }));
	};

	const getGlobalAccountDataSince = async (
		userId: UserId,
		since: number,
	): Promise<{ type: string; content: JsonObject }[]> => {
		const { rows } = await pool.query(
			// Include tombstones so incremental sync surfaces deletions.
			"SELECT type, content FROM global_account_data WHERE user_id = $1 AND stream_pos > $2",
			[userId, since],
		);
		return rows.map((r) => ({ type: r.type, content: r.content }));
	};

	const getRoomAccountData = async (
		userId: UserId,
		roomId: RoomId,
		type: string,
	): Promise<JsonObject | undefined> => {
		const { rows } = await pool.query(
			"SELECT content FROM room_account_data WHERE user_id = $1 AND room_id = $2 AND type = $3",
			[userId, roomId, type],
		);
		return rows[0]?.content ?? undefined;
	};

	const setRoomAccountData = async (
		userId: UserId,
		roomId: RoomId,
		type: string,
		content: JsonObject,
	): Promise<void> => {
		await pool.query(
			"INSERT INTO room_account_data (user_id, room_id, type, content, stream_pos) VALUES ($1, $2, $3, $4, $5) ON CONFLICT (user_id, room_id, type) DO UPDATE SET content = EXCLUDED.content, stream_pos = EXCLUDED.stream_pos",
			[userId, roomId, type, JSON.stringify(content), ++eph.streamCounter],
		);
		eph.wakeWaiters();
	};
	const deleteGlobalAccountData = async (
		userId: UserId,
		type: string,
	): Promise<void> => {
		// MSC3391: leave a tombstone (content '{}') with a fresh stream position
		// rather than removing the row, so incremental sync can surface it.
		await pool.query(
			"INSERT INTO global_account_data (user_id, type, content, stream_pos) VALUES ($1, $2, '{}'::jsonb, $3) ON CONFLICT (user_id, type) DO UPDATE SET content = EXCLUDED.content, stream_pos = EXCLUDED.stream_pos",
			[userId, type, ++eph.streamCounter],
		);
		eph.wakeWaiters();
	};
	const deleteRoomAccountData = async (
		userId: UserId,
		roomId: RoomId,
		type: string,
	): Promise<void> => {
		await pool.query(
			"INSERT INTO room_account_data (user_id, room_id, type, content, stream_pos) VALUES ($1, $2, $3, '{}'::jsonb, $4) ON CONFLICT (user_id, room_id, type) DO UPDATE SET content = EXCLUDED.content, stream_pos = EXCLUDED.stream_pos",
			[userId, roomId, type, ++eph.streamCounter],
		);
		eph.wakeWaiters();
	};

	const getAllRoomAccountData = async (
		userId: UserId,
		roomId: RoomId,
	): Promise<{ type: string; content: JsonObject }[]> => {
		const { rows } = await pool.query(
			// Exclude MSC3391 deletion tombstones from initial sync.
			"SELECT type, content FROM room_account_data WHERE user_id = $1 AND room_id = $2 AND content <> '{}'::jsonb",
			[userId, roomId],
		);
		return rows.map((r) => ({ type: r.type, content: r.content }));
	};

	const getRoomAccountDataSince = async (
		userId: UserId,
		since: number,
	): Promise<{ roomId: RoomId; type: string; content: JsonObject }[]> => {
		const { rows } = await pool.query(
			// Include tombstones so incremental sync surfaces deletions.
			"SELECT room_id, type, content FROM room_account_data WHERE user_id = $1 AND stream_pos > $2",
			[userId, since],
		);
		return rows.map((r) => ({
			roomId: r.room_id as RoomId,
			type: r.type,
			content: r.content,
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
		await pool.query(
			"INSERT INTO receipts (room_id, user_id, event_id, receipt_type, ts, thread_id) VALUES ($1, $2, $3, $4, $5, $6) ON CONFLICT (room_id, user_id, receipt_type, thread_id) DO UPDATE SET event_id = EXCLUDED.event_id, ts = EXCLUDED.ts",
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
		const { rows } = await pool.query(
			"SELECT event_id, receipt_type, user_id, ts, thread_id FROM receipts WHERE room_id = $1",
			[roomId],
		);
		return collapseReceiptsMsc4102(
			rows.map((r) => ({
				eventId: r.event_id as EventId,
				receiptType: r.receipt_type,
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
		await pool.query(
			`INSERT INTO media (origin, media_id, user_id, content_type, upload_name, file_size, content_hash, created_at, quarantined, data)
			 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
			 ON CONFLICT (origin, media_id) DO UPDATE SET user_id = EXCLUDED.user_id, content_type = EXCLUDED.content_type, upload_name = EXCLUDED.upload_name,
				file_size = EXCLUDED.file_size, content_hash = EXCLUDED.content_hash, created_at = EXCLUDED.created_at, quarantined = EXCLUDED.quarantined, data = EXCLUDED.data`,
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
		const { rows } = await pool.query(
			"SELECT * FROM media WHERE origin = $1 AND media_id = $2",
			[serverName, mediaId],
		);
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
		await pool.query(
			"UPDATE media SET content_type = $1, upload_name = $2, file_size = $3, content_hash = $4, data = $5 WHERE origin = $6 AND media_id = $7",
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
		await pool.query(
			"INSERT INTO filters (user_id, filter_id, filter_json) VALUES ($1, $2, $3) ON CONFLICT (user_id, filter_id) DO UPDATE SET filter_json = EXCLUDED.filter_json",
			[userId, filterId, JSON.stringify(filter)],
		);
		return filterId;
	};

	const getFilter = async (
		userId: UserId,
		filterId: string,
	): Promise<JsonObject | undefined> => {
		const { rows } = await pool.query(
			"SELECT filter_json FROM filters WHERE user_id = $1 AND filter_id = $2",
			[userId, filterId],
		);
		return rows[0]?.filter_json ?? undefined;
	};

	const setDeviceKeys = async (
		userId: UserId,
		deviceId: DeviceId,
		keys: DeviceKeys,
	): Promise<void> => {
		await pool.query(
			"INSERT INTO device_keys (user_id, device_id, keys_json) VALUES ($1, $2, $3) ON CONFLICT (user_id, device_id) DO UPDATE SET keys_json = EXCLUDED.keys_json",
			[userId, deviceId, JSON.stringify(keys)],
		);
		await recordDeviceKeyChange(userId);
	};

	const recordDeviceKeyChange = async (userId: UserId): Promise<void> => {
		await pool.query(
			"INSERT INTO device_list_stream (user_id, stream_pos) VALUES ($1, $2)",
			[userId, ++eph.streamCounter],
		);
		eph.wakeWaiters();
	};

	const getChangedDeviceUsers = async (
		since: number,
		until: number,
	): Promise<UserId[]> => {
		const { rows } = await pool.query<{ user_id: string }>(
			"SELECT DISTINCT user_id FROM device_list_stream WHERE stream_pos > $1 AND stream_pos <= $2",
			[since, until],
		);
		return rows.map((r) => r.user_id as UserId);
	};

	const getDeviceKeys = async (
		userId: UserId,
		deviceId: DeviceId,
	): Promise<DeviceKeys | undefined> => {
		const { rows } = await pool.query(
			"SELECT keys_json FROM device_keys WHERE user_id = $1 AND device_id = $2",
			[userId, deviceId],
		);
		return rows[0]?.keys_json ?? undefined;
	};

	const getAllDeviceKeys = async (
		userId: UserId,
	): Promise<Record<DeviceId, DeviceKeys>> => {
		const { rows } = await pool.query(
			"SELECT device_id, keys_json FROM device_keys WHERE user_id = $1",
			[userId],
		);
		const result: Record<DeviceId, DeviceKeys> = {};
		for (const r of rows) result[r.device_id as DeviceId] = r.keys_json;
		return result;
	};

	const deleteDeviceKeys = async (userId: UserId): Promise<void> => {
		await pool.query("DELETE FROM device_keys WHERE user_id = $1", [userId]);
	};

	const addOneTimeKeys = async (
		userId: UserId,
		deviceId: DeviceId,
		keys: Record<KeyId, string | OneTimeKey>,
	): Promise<void> => {
		const client = await pool.connect();
		try {
			await client.query("BEGIN");
			for (const [keyId, key] of Object.entries(keys)) {
				const algorithm = keyId.split(":")[0] as string;
				await client.query(
					"INSERT INTO one_time_keys (user_id, device_id, key_id, algorithm, key_json) VALUES ($1, $2, $3, $4, $5) ON CONFLICT (user_id, device_id, key_id) DO UPDATE SET key_json = EXCLUDED.key_json",
					[userId, deviceId, keyId, algorithm, JSON.stringify(key)],
				);
			}
			await client.query("COMMIT");
		} catch (e) {
			await client.query("ROLLBACK");
			throw e;
		} finally {
			client.release();
		}
	};

	const claimOneTimeKey = async (
		userId: UserId,
		deviceId: DeviceId,
		algorithm: string,
	): Promise<{ keyId: KeyId; key: string | OneTimeKey } | undefined> => {
		const { rows } = await pool.query(
			"DELETE FROM one_time_keys WHERE ctid = (SELECT ctid FROM one_time_keys WHERE user_id = $1 AND device_id = $2 AND algorithm = $3 LIMIT 1) RETURNING key_id, key_json",
			[userId, deviceId, algorithm],
		);
		if (rows[0])
			return { keyId: rows[0].key_id as KeyId, key: rows[0].key_json };

		const { rows: fallbackRows } = await pool.query(
			"SELECT key_id, key_json FROM fallback_keys WHERE user_id = $1 AND device_id = $2 AND key_id LIKE $3 LIMIT 1",
			[userId, deviceId, `${algorithm}:%`],
		);
		if (fallbackRows[0])
			return {
				keyId: fallbackRows[0].key_id as KeyId,
				key: fallbackRows[0].key_json,
			};
		return undefined;
	};

	const getOneTimeKeyCounts = async (
		userId: UserId,
		deviceId: DeviceId,
	): Promise<Record<string, number>> => {
		const { rows } = await pool.query(
			"SELECT algorithm, COUNT(*)::int AS cnt FROM one_time_keys WHERE user_id = $1 AND device_id = $2 GROUP BY algorithm",
			[userId, deviceId],
		);
		const counts: Record<string, number> = {};
		for (const r of rows) counts[r.algorithm] = r.cnt;
		return counts;
	};

	const setFallbackKeys = async (
		userId: UserId,
		deviceId: DeviceId,
		keys: Record<KeyId, string | OneTimeKey>,
	): Promise<void> => {
		const client = await pool.connect();
		try {
			await client.query("BEGIN");
			await client.query(
				"DELETE FROM fallback_keys WHERE user_id = $1 AND device_id = $2",
				[userId, deviceId],
			);
			for (const [keyId, key] of Object.entries(keys)) {
				await client.query(
					"INSERT INTO fallback_keys (user_id, device_id, key_id, key_json) VALUES ($1, $2, $3, $4)",
					[userId, deviceId, keyId, JSON.stringify(key)],
				);
			}
			await client.query("COMMIT");
		} catch (e) {
			await client.query("ROLLBACK");
			throw e;
		} finally {
			client.release();
		}
	};

	const getFallbackKeyTypes = async (
		userId: UserId,
		deviceId: DeviceId,
	): Promise<string[]> => {
		const { rows } = await pool.query(
			"SELECT DISTINCT key_id FROM fallback_keys WHERE user_id = $1 AND device_id = $2",
			[userId, deviceId],
		);
		const types = new Set<string>();
		for (const r of rows) types.add(r.key_id.split(":")[0] as string);
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
			await pool.query(
				"INSERT INTO cross_signing_keys (user_id, key_type, key_json) VALUES ($1, $2, $3) ON CONFLICT (user_id, key_type) DO UPDATE SET key_json = EXCLUDED.key_json",
				[userId, keyType, JSON.stringify(key)],
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
		const { rows } = await pool.query(
			"SELECT key_type, key_json FROM cross_signing_keys WHERE user_id = $1",
			[userId],
		);
		return rowsToCrossSigningKeys(rows, (j) =>
			typeof j === "string" ? JSON.parse(j) : (j as CrossSigningKey),
		);
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
				for (const [crossKeyType, key] of Object.entries(crossKeys) as [
					string,
					CrossSigningKey,
				][]) {
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
						await pool.query(
							"UPDATE cross_signing_keys SET key_json = $1 WHERE user_id = $2 AND key_type = $3",
							[JSON.stringify(key), targetUserId, crossKeyType],
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
		const { rows } = await pool.query<{ m: string | null }>(
			"SELECT MAX(version::int) AS m FROM key_backup_versions WHERE user_id = $1",
			[userId],
		);
		const nextVersion = String((rows[0]?.m ? parseInt(rows[0].m, 10) : 0) + 1);
		await pool.query(
			"INSERT INTO key_backup_versions (user_id, version, algorithm, auth_data) VALUES ($1, $2, $3, $4)",
			[userId, nextVersion, algorithm, JSON.stringify(authData)],
		);
		return nextVersion;
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
		let rows: { version: string; algorithm: string; auth_data: string }[];
		if (version) {
			({ rows } = await pool.query(
				"SELECT version, algorithm, auth_data FROM key_backup_versions WHERE user_id = $1 AND version = $2",
				[userId, version],
			));
		} else {
			({ rows } = await pool.query(
				"SELECT version, algorithm, auth_data FROM key_backup_versions WHERE user_id = $1 ORDER BY version::int DESC LIMIT 1",
				[userId],
			));
		}
		if (!rows[0]) return undefined;
		const v = rows[0];

		const {
			rows: [countRow],
		} = await pool.query<{ cnt: string }>(
			"SELECT COUNT(*)::int AS cnt FROM key_backup_data WHERE user_id = $1 AND version = $2",
			[userId, v.version],
		);
		const count = parseInt(countRow!.cnt, 10);

		const authData =
			typeof v.auth_data === "string" ? JSON.parse(v.auth_data) : v.auth_data;

		return {
			version: v.version,
			algorithm: v.algorithm,
			auth_data: authData,
			count,
			etag: await computeBackupEtagPg(userId, v.version),
		};
	};

	const computeBackupEtagPg = async (
		userId: string,
		version: string,
	): Promise<string> => {
		const { rows } = await pool.query(
			"SELECT room_id, session_id FROM key_backup_data WHERE user_id = $1 AND version = $2",
			[userId, version],
		);
		return keyBackupEtag(rows);
	};

	const updateKeyBackupVersion = async (
		userId: UserId,
		version: string,
		authData: JsonObject,
	): Promise<boolean> => {
		const result = await pool.query(
			"UPDATE key_backup_versions SET auth_data = $1 WHERE user_id = $2 AND version = $3",
			[JSON.stringify(authData), userId, version],
		);
		return (result.rowCount ?? 0) > 0;
	};

	const deleteKeyBackupVersion = async (
		userId: UserId,
		version: string,
	): Promise<boolean> => {
		await pool.query(
			"DELETE FROM key_backup_data WHERE user_id = $1 AND version = $2",
			[userId, version],
		);
		const result = await pool.query(
			"DELETE FROM key_backup_versions WHERE user_id = $1 AND version = $2",
			[userId, version],
		);
		return (result.rowCount ?? 0) > 0;
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
		// Verify version exists and is latest
		const { rows: versionRows } = await pool.query(
			"SELECT version FROM key_backup_versions WHERE user_id = $1 ORDER BY version::int DESC LIMIT 1",
			[userId],
		);
		if (!versionRows[0] || versionRows[0].version !== version) return undefined;

		const entries = flattenKeyBackupEntries(roomId, sessionId, keys);

		for (const [rid, sid, data] of entries) {
			await mergeBackupKeyPg(userId, version, rid, sid, data);
		}

		const {
			rows: [countRow],
		} = await pool.query<{ cnt: string }>(
			"SELECT COUNT(*)::int AS cnt FROM key_backup_data WHERE user_id = $1 AND version = $2",
			[userId, version],
		);
		const count = parseInt(countRow!.cnt, 10);
		return { count, etag: await computeBackupEtagPg(userId, version) };
	};

	const mergeBackupKeyPg = async (
		userId: string,
		version: string,
		roomId: RoomId,
		sessionId: string,
		newData: KeyBackupData,
	): Promise<void> => {
		const { rows } = await pool.query(
			"SELECT key_json FROM key_backup_data WHERE user_id = $1 AND version = $2 AND room_id = $3 AND session_id = $4",
			[userId, version, roomId, sessionId],
		);
		if (rows[0]) {
			const existing =
				typeof rows[0].key_json === "string"
					? (JSON.parse(rows[0].key_json) as KeyBackupData)
					: (rows[0].key_json as KeyBackupData);
			if (!shouldReplaceBackupKey(newData, existing)) return;
		}
		await pool.query(
			"INSERT INTO key_backup_data (user_id, version, room_id, session_id, key_json) VALUES ($1, $2, $3, $4, $5) ON CONFLICT (user_id, version, room_id, session_id) DO UPDATE SET key_json = EXCLUDED.key_json",
			[userId, version, roomId, sessionId, JSON.stringify(newData)],
		);
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
			const { rows } = await pool.query(
				"SELECT key_json FROM key_backup_data WHERE user_id = $1 AND version = $2 AND room_id = $3 AND session_id = $4",
				[userId, version, roomId, sessionId],
			);
			if (!rows[0]) return undefined;
			return typeof rows[0].key_json === "string"
				? JSON.parse(rows[0].key_json)
				: rows[0].key_json;
		} else if (roomId) {
			const { rows } = await pool.query(
				"SELECT session_id, key_json FROM key_backup_data WHERE user_id = $1 AND version = $2 AND room_id = $3",
				[userId, version, roomId],
			);
			const sessions: Record<string, KeyBackupData> = {};
			for (const r of rows) {
				sessions[r.session_id] =
					typeof r.key_json === "string" ? JSON.parse(r.key_json) : r.key_json;
			}
			return { sessions };
		} else {
			const { rows } = await pool.query(
				"SELECT room_id, session_id, key_json FROM key_backup_data WHERE user_id = $1 AND version = $2",
				[userId, version],
			);
			const result: Record<
				RoomId,
				{ sessions: Record<string, KeyBackupData> }
			> = {};
			for (const r of rows) {
				const rid = r.room_id as RoomId;
				if (!result[rid]) result[rid] = { sessions: {} };
				result[rid]!.sessions[r.session_id] =
					typeof r.key_json === "string" ? JSON.parse(r.key_json) : r.key_json;
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
		// Verify version exists
		const { rows: versionRows } = await pool.query(
			"SELECT version FROM key_backup_versions WHERE user_id = $1 AND version = $2",
			[userId, version],
		);
		if (!versionRows[0]) return undefined;

		if (roomId && sessionId) {
			await pool.query(
				"DELETE FROM key_backup_data WHERE user_id = $1 AND version = $2 AND room_id = $3 AND session_id = $4",
				[userId, version, roomId, sessionId],
			);
		} else if (roomId) {
			await pool.query(
				"DELETE FROM key_backup_data WHERE user_id = $1 AND version = $2 AND room_id = $3",
				[userId, version, roomId],
			);
		} else {
			await pool.query(
				"DELETE FROM key_backup_data WHERE user_id = $1 AND version = $2",
				[userId, version],
			);
		}

		const {
			rows: [countRow],
		} = await pool.query<{ cnt: string }>(
			"SELECT COUNT(*)::int AS cnt FROM key_backup_data WHERE user_id = $1 AND version = $2",
			[userId, version],
		);
		const count = parseInt(countRow!.cnt, 10);
		return { count, etag: await computeBackupEtagPg(userId, version) };
	};

	const sendToDevice = async (
		userId: UserId,
		deviceId: DeviceId,
		event: ToDeviceEvent,
	): Promise<void> => {
		await pool.query(
			"INSERT INTO to_device (user_id, device_id, event_json) VALUES ($1, $2, $3)",
			[userId, deviceId, JSON.stringify(event)],
		);
		eph.wakeWaiters();
	};

	const getToDeviceMessages = async (
		userId: UserId,
		deviceId: DeviceId,
	): Promise<ToDeviceEvent[]> => {
		const { rows } = await pool.query(
			"SELECT event_json FROM to_device WHERE user_id = $1 AND device_id = $2 ORDER BY id",
			[userId, deviceId],
		);
		return rows.map((r) => r.event_json);
	};

	const clearToDeviceMessages = async (
		userId: UserId,
		deviceId: DeviceId,
	): Promise<void> => {
		await pool.query(
			"DELETE FROM to_device WHERE user_id = $1 AND device_id = $2",
			[userId, deviceId],
		);
	};

	const getPushers = async (userId: UserId): Promise<Pusher[]> => {
		const { rows } = await pool.query(
			"SELECT pusher_json FROM pushers WHERE user_id = $1",
			[userId],
		);
		return rows.map((r) => r.pusher_json);
	};

	const setPusher = async (userId: UserId, pusher: Pusher): Promise<void> => {
		await pool.query(
			"INSERT INTO pushers (user_id, app_id, pushkey, pusher_json) VALUES ($1, $2, $3, $4) ON CONFLICT (user_id, app_id, pushkey) DO UPDATE SET pusher_json = EXCLUDED.pusher_json",
			[userId, pusher.app_id, pusher.pushkey, JSON.stringify(pusher)],
		);
	};

	const deletePusher = async (
		userId: UserId,
		appId: string,
		pushkey: string,
	): Promise<void> => {
		await pool.query(
			"DELETE FROM pushers WHERE user_id = $1 AND app_id = $2 AND pushkey = $3",
			[userId, appId, pushkey],
		);
	};

	const deletePusherByKey = async (
		appId: string,
		pushkey: string,
	): Promise<void> => {
		await pool.query("DELETE FROM pushers WHERE app_id = $1 AND pushkey = $2", [
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
		const { rows } = await pool.query(
			"SELECT event_json, stream_pos FROM events WHERE event_id = $1",
			[eventId],
		);
		if (!rows[0]) return;
		const event = rows[0].event_json as PDU;
		const streamPos = parseInt(rows[0].stream_pos, 10);
		await pool.query(
			"INSERT INTO relations (event_id, room_id, rel_type, target_event_id, key, sender, event_type, stream_pos) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)",
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
			"SELECT r.event_id, r.stream_pos, e.event_json FROM relations r JOIN events e ON r.event_id = e.event_id WHERE r.target_event_id = $1 AND r.room_id = $2";
		const params: unknown[] = [eventId, roomId];
		let paramIdx = 3;

		if (relType) {
			sql += ` AND r.rel_type = $${paramIdx++}`;
			params.push(relType);
		}
		if (eventType) {
			sql += ` AND r.event_type = $${paramIdx++}`;
			params.push(eventType);
		}

		const fromPos = from ? parseInt(from, 10) : undefined;
		if (fromPos !== undefined) {
			sql +=
				direction === "f"
					? ` AND r.stream_pos > $${paramIdx++}`
					: ` AND r.stream_pos < $${paramIdx++}`;
			params.push(fromPos);
		}

		sql +=
			direction === "f"
				? ` ORDER BY r.stream_pos ASC LIMIT $${paramIdx}`
				: ` ORDER BY r.stream_pos DESC LIMIT $${paramIdx}`;
		params.push(limit);

		const { rows } = await pool.query(sql, params);
		const events = rows.map((r: Record<string, unknown>) => ({
			event: r.event_json as PDU,
			eventId: r.event_id as EventId,
		}));
		const nextBatch =
			rows.length === limit && rows.length > 0
				? String((rows[rows.length - 1] as Record<string, unknown>).stream_pos)
				: undefined;
		return { events, nextBatch };
	};

	const getAnnotationCounts = async (
		eventId: EventId,
	): Promise<{ type: string; key: string; count: number }[]> => {
		const { rows } = await pool.query(
			"SELECT event_type, key, COUNT(*)::int AS cnt FROM relations WHERE target_event_id = $1 AND rel_type = 'm.annotation' AND key IS NOT NULL GROUP BY event_type, key",
			[eventId],
		);
		return rows.map((r) => ({ type: r.event_type, key: r.key, count: r.cnt }));
	};

	const getLatestEdit = async (
		eventId: EventId,
		sender: UserId,
	): Promise<{ event: PDU; eventId: EventId } | undefined> => {
		const { rows } = await pool.query(
			"SELECT r.event_id, e.event_json FROM relations r JOIN events e ON r.event_id = e.event_id WHERE r.target_event_id = $1 AND r.rel_type = 'm.replace' AND r.sender = $2 ORDER BY r.stream_pos DESC LIMIT 1",
			[eventId, sender],
		);
		if (!rows[0]) return undefined;
		return { event: rows[0].event_json, eventId: rows[0].event_id as EventId };
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
		const {
			rows: [countRow],
		} = await pool.query(
			"SELECT COUNT(*)::int AS cnt FROM relations WHERE target_event_id = $1 AND rel_type = 'm.thread'",
			[eventId],
		);
		if (countRow.cnt === 0) return undefined;

		const {
			rows: [latestRow],
		} = await pool.query(
			"SELECT r.event_id, e.event_json FROM relations r JOIN events e ON r.event_id = e.event_id WHERE r.target_event_id = $1 AND r.rel_type = 'm.thread' ORDER BY r.stream_pos DESC LIMIT 1",
			[eventId],
		);
		if (!latestRow) return undefined;

		const {
			rows: [participated],
		} = await pool.query(
			"SELECT 1 FROM relations WHERE target_event_id = $1 AND rel_type = 'm.thread' AND sender = $2 LIMIT 1",
			[eventId, userId],
		);

		return {
			latestEvent: {
				event: latestRow.event_json,
				eventId: latestRow.event_id as EventId,
			},
			count: countRow.cnt,
			currentUserParticipated: !!participated,
		};
	};

	const storeReport = async (
		userId: UserId,
		roomId: RoomId,
		eventId: EventId,
		score?: number,
		reason?: string,
	): Promise<void> => {
		await pool.query(
			"INSERT INTO reports (user_id, room_id, event_id, score, reason, ts) VALUES ($1, $2, $3, $4, $5, $6)",
			[userId, roomId, eventId, score ?? null, reason ?? null, Date.now()],
		);
	};

	const storeOpenIdToken = async (
		token: string,
		userId: UserId,
		expiresAt: Timestamp,
	): Promise<void> => {
		await pool.query(
			"INSERT INTO openid_tokens (token, user_id, expires_at) VALUES ($1, $2, $3) ON CONFLICT (token) DO UPDATE SET user_id = EXCLUDED.user_id, expires_at = EXCLUDED.expires_at",
			[token, userId, expiresAt],
		);
	};

	const getOpenIdToken = async (
		token: string,
	): Promise<{ userId: UserId; expiresAt: Timestamp } | undefined> => {
		const { rows } = await pool.query(
			"SELECT user_id, expires_at FROM openid_tokens WHERE token = $1",
			[token],
		);
		if (!rows[0]) return undefined;
		return {
			userId: rows[0].user_id as UserId,
			expiresAt: Number(rows[0].expires_at),
		};
	};

	const getThreePids = async (
		userId: UserId,
	): Promise<{ medium: string; address: string; added_at: Timestamp }[]> => {
		const { rows } = await pool.query(
			"SELECT medium, address, added_at FROM threepids WHERE user_id = $1",
			[userId],
		);
		return rows.map((r) => ({
			medium: r.medium,
			address: r.address,
			added_at: Number(r.added_at),
		}));
	};

	const addThreePid = async (
		userId: UserId,
		medium: string,
		address: string,
	): Promise<void> => {
		await pool.query(
			"INSERT INTO threepids (user_id, medium, address, added_at) VALUES ($1, $2, $3, $4) ON CONFLICT DO NOTHING",
			[userId, medium, address, Date.now()],
		);
	};

	const deleteThreePid = async (
		userId: UserId,
		medium: string,
		address: string,
	): Promise<void> => {
		await pool.query(
			"DELETE FROM threepids WHERE user_id = $1 AND medium = $2 AND address = $3",
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
		const { rows } = await pool.query(
			"SELECT user_id, displayname, avatar_url FROM users WHERE is_deactivated = FALSE AND (user_id ILIKE $1 OR displayname ILIKE $1) LIMIT $2",
			[term, limit],
		);
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
			SELECT r.target_event_id, MAX(r.stream_pos) AS latest_pos, e.event_json
			FROM relations r
			JOIN events e ON r.target_event_id = e.event_id
			WHERE r.rel_type = 'm.thread' AND r.room_id = $1
		`;
		const params: unknown[] = [roomId];
		let paramIdx = 2;

		if (include === "participated") {
			sql += ` AND r.target_event_id IN (SELECT target_event_id FROM relations WHERE rel_type = 'm.thread' AND sender = $${paramIdx++})`;
			params.push(userId);
		}
		if (from) {
			sql += ` AND r.stream_pos < $${paramIdx++}`;
			params.push(parseInt(from, 10));
		}
		sql += ` GROUP BY r.target_event_id, e.event_json ORDER BY latest_pos DESC LIMIT $${paramIdx}`;
		params.push(limit);

		const { rows } = await pool.query(sql, params);
		const events = rows.map((r: Record<string, unknown>) => ({
			event: r.event_json as PDU,
			eventId: r.target_event_id as EventId,
		}));
		const nextBatch =
			rows.length === limit && rows.length > 0
				? String((rows[rows.length - 1] as Record<string, unknown>).latest_pos)
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

		const { rows } = await pool.query(
			"SELECT event_id, event_json, stream_pos FROM events WHERE room_id = ANY($1) ORDER BY stream_pos DESC",
			[roomIds],
		);

		const allMatches: { event: PDU; eventId: EventId; streamPos: number }[] =
			[];
		for (const row of rows) {
			const event = row.event_json as PDU;
			if (eventMatchesSearchTerm(event, keys, searchTerm)) {
				allMatches.push({
					event,
					eventId: row.event_id as EventId,
					streamPos: parseInt(row.stream_pos, 10),
				});
			}
		}

		return paginateSearchMatches(allMatches, limit, from);
	};

	const storeServerKeys = async (
		serverName: ServerName,
		keys: ServerKeys,
	): Promise<void> => {
		const client = await pool.connect();
		try {
			await client.query("BEGIN");
			for (const [keyId, val] of Object.entries(keys.verify_keys)) {
				await client.query(
					"INSERT INTO server_keys (server_name, key_id, key, valid_until) VALUES ($1, $2, $3, $4) ON CONFLICT (server_name, key_id) DO UPDATE SET key = EXCLUDED.key, valid_until = EXCLUDED.valid_until",
					[serverName, keyId, val.key, keys.valid_until_ts],
				);
			}
			await client.query("COMMIT");
		} catch (e) {
			await client.query("ROLLBACK");
			throw e;
		} finally {
			client.release();
		}
	};

	const getServerKeys = async (
		serverName: ServerName,
		keyId: KeyId,
	): Promise<{ key: string; validUntil: number } | undefined> => {
		const { rows } = await pool.query(
			"SELECT key, valid_until FROM server_keys WHERE server_name = $1 AND key_id = $2",
			[serverName, keyId],
		);
		if (!rows[0]) return undefined;
		return { key: rows[0].key, validUntil: Number(rows[0].valid_until) };
	};

	const getAuthChain = async (eventIds: EventId[]): Promise<PDU[]> => {
		const visited = new Set<EventId>();
		const result: PDU[] = [];
		const queue = [...eventIds];

		while (queue.length > 0) {
			const id = queue.shift() as EventId;
			if (visited.has(id)) continue;
			visited.add(id);
			const { rows } = await pool.query(
				"SELECT event_json FROM events WHERE event_id = $1",
				[id],
			);
			if (!rows[0]) continue;
			const event = rows[0].event_json as PDU;
			result.push(event);
			for (const authId of event.auth_events) {
				if (!visited.has(authId)) queue.push(authId);
			}
		}
		return result;
	};

	const getServersInRoom = async (roomId: RoomId): Promise<ServerName[]> => {
		const { rows } = await pool.query(
			"SELECT state_key FROM state_events WHERE room_id = $1 AND event_type = 'm.room.member' AND event_json->'content'->>'membership' = 'join'",
			[roomId],
		);
		const servers = new Set<ServerName>();
		for (const r of rows) {
			const serverName = r.state_key
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
		await pool.query("DELETE FROM events WHERE event_id = $1", [eventId]);
		await pool.query("DELETE FROM state_events WHERE event_id = $1", [eventId]);
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
		const { rows } = await pool.query(
			"SELECT 1 FROM federation_txns WHERE origin = $1 AND txn_id = $2",
			[origin, txnId],
		);
		return rows.length > 0;
	};

	const setFederationTxn = async (
		origin: ServerName,
		txnId: string,
	): Promise<void> => {
		await pool.query(
			"INSERT INTO federation_txns (origin, txn_id) VALUES ($1, $2) ON CONFLICT DO NOTHING",
			[origin, txnId],
		);
	};

	const enqueueFederationEdu = async (
		destination: ServerName,
		edu: EDU,
	): Promise<number> => {
		const { rows } = await pool.query(
			"INSERT INTO pending_federation_edus (destination, edu_json) VALUES ($1, $2) RETURNING id",
			[destination, JSON.stringify(edu)],
		);
		const id = Number((rows[0] as { id: string | number }).id);
		// Enforce the per-destination cap: delete oldest rows beyond the cap.
		const { rowCount } = await pool.query(
			"DELETE FROM pending_federation_edus WHERE id IN (SELECT id FROM pending_federation_edus WHERE destination = $1 ORDER BY id ASC OFFSET $2)",
			[destination, PENDING_FEDERATION_EDU_CAP],
		);
		if (rowCount && rowCount > 0) {
			console.warn(
				`pending_federation_edus: dropped ${rowCount} EDU(s) for ${destination} (queue cap ${PENDING_FEDERATION_EDU_CAP} exceeded)`,
			);
		}
		return id;
	};

	const getPendingFederationEdus = async (
		destination: ServerName,
		limit: number,
	): Promise<{ id: number; edu: EDU }[]> => {
		const { rows } = await pool.query(
			"SELECT id, edu_json FROM pending_federation_edus WHERE destination = $1 ORDER BY id ASC LIMIT $2",
			[destination, limit],
		);
		return (rows as { id: string | number; edu_json: string }[]).map((r) => ({
			id: Number(r.id),
			edu: JSON.parse(r.edu_json) as EDU,
		}));
	};

	const deleteFederationEdu = async (id: number): Promise<void> => {
		await pool.query("DELETE FROM pending_federation_edus WHERE id = $1", [id]);
	};

	const getPendingFederationDestinations = async (): Promise<ServerName[]> => {
		const { rows } = await pool.query(
			"SELECT DISTINCT destination FROM pending_federation_edus",
		);
		return (rows as { destination: string }[]).map(
			(r) => r.destination as ServerName,
		);
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
		const client = await pool.connect();
		try {
			await client.query("BEGIN");
			for (const event of authChain) {
				const eventId = computeEventId(event, roomVersion);
				eph.streamCounter++;
				await client.query(
					"INSERT INTO events (event_id, room_id, stream_pos, event_json) VALUES ($1, $2, $3, $4) ON CONFLICT (event_id) DO NOTHING",
					[eventId, event.room_id, eph.streamCounter, JSON.stringify(event)],
				);
			}

			let maxDepth = 0;
			const extremities: EventId[] = [];
			for (const event of stateEvents) {
				const eventId = computeEventId(event, roomVersion);
				eph.streamCounter++;
				await client.query(
					"INSERT INTO events (event_id, room_id, stream_pos, event_json) VALUES ($1, $2, $3, $4) ON CONFLICT (event_id) DO NOTHING",
					[eventId, event.room_id, eph.streamCounter, JSON.stringify(event)],
				);
				await client.query(
					`INSERT INTO state_events (room_id, event_type, state_key, event_id, event_json) VALUES ($1, $2, $3, $4, $5)
					 ON CONFLICT (room_id, event_type, state_key) DO UPDATE SET event_id = EXCLUDED.event_id, event_json = EXCLUDED.event_json`,
					[
						roomId,
						event.type,
						event.state_key ?? "",
						eventId,
						JSON.stringify(event),
					],
				);
				if (event.depth > maxDepth) maxDepth = event.depth;
				extremities.length = 0;
				extremities.push(eventId);
			}

			await client.query(
				`INSERT INTO rooms (room_id, room_version, depth, forward_extremities) VALUES ($1, $2, $3, $4)
				 ON CONFLICT (room_id) DO UPDATE SET room_version = EXCLUDED.room_version, depth = EXCLUDED.depth, forward_extremities = EXCLUDED.forward_extremities`,
				[roomId, roomVersion, maxDepth + 1, JSON.stringify(extremities)],
			);
			await client.query("COMMIT");
		} catch (e) {
			await client.query("ROLLBACK");
			throw e;
		} finally {
			client.release();
		}
		eph.wakeWaiters();
	};

	pool = new pg.Pool({ connectionString, max: 20 });
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
