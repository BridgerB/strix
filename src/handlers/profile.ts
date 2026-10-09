import { badJson, forbidden, notFound } from "../errors.ts";
import { buildEvent, checkEventAuth, selectAuthEvents } from "../events.ts";
import type { FederationClient } from "../federation/client.ts";
import { fanoutEvent } from "../federation/outbound.ts";
import type { Handler } from "../router.ts";
import type { SigningKey } from "../signing.ts";
import type { Storage } from "../storage/interface.ts";
import type { ServerName, UserId } from "../types/index.ts";
import type { JsonObject } from "../types/json.ts";

const MAX_DISPLAYNAME_BYTES = 256;
const MAX_AVATAR_URL_BYTES = 1000;

/** In-memory store for extended profile fields */
const extendedProfileFields = new Map<string, unknown>();

const profileFieldKey = (userId: UserId, keyName: string): string =>
	`${userId}\x1f${keyName}`;

const propagateProfileToRooms = async (
	storage: Storage,
	serverName: string,
	userId: UserId,
	signingKey?: SigningKey,
	federationClient?: FederationClient,
): Promise<void> => {
	const profile = await storage.getProfile(userId);
	const rooms = await storage.getRoomsForUser(userId);

	for (const roomId of rooms) {
		const room = await storage.getRoom(roomId);
		if (!room) continue;

		const currentMember = room.state_events.get(`m.room.member\x1f${userId}`);
		if (!currentMember) continue;

		const currentContent = currentMember.content as Record<string, unknown>;
		if (currentContent.membership !== "join") continue;

		const newContent: JsonObject = { membership: "join" };
		if (profile?.displayname) newContent.displayname = profile.displayname;
		if (profile?.avatar_url) newContent.avatar_url = profile.avatar_url;

		const authEvents = selectAuthEvents("m.room.member", userId, room, userId);

		const { event, eventId } = buildEvent({
			roomId,
			sender: userId,
			type: "m.room.member",
			content: newContent,
			stateKey: userId,
			depth: room.depth + 1,
			prevEvents: room.forward_extremities,
			authEvents,
			serverName,
			roomVersion: room.room_version,
			signingKey,
		});

		checkEventAuth(event, eventId, room);
		await storage.setStateEvent(roomId, event, eventId);
		room.depth += 1;
		room.forward_extremities = [eventId];

		// Federate the membership update to the room's servers (including those
		// recorded for a partial-state room), so remote members see the new
		// display name / avatar. Requires our signing key + a federation client.
		if (signingKey && federationClient) {
			await fanoutEvent(
				storage,
				serverName,
				signingKey,
				federationClient,
				roomId as Parameters<typeof fanoutEvent>[4],
				event,
				eventId,
			);
		}
	}
};

/** Collect all extended profile fields for a user */
const getExtendedFields = (userId: UserId): Record<string, unknown> => {
	const prefix = `${userId}\x1f`;
	const fields: Record<string, unknown> = {};
	for (const [key, value] of extendedProfileFields) {
		if (key.startsWith(prefix)) {
			const fieldName = key.slice(prefix.length);
			fields[fieldName] = value;
		}
	}
	return fields;
};

export const getProfile =
	(
		storage: Storage,
		serverName?: string,
		federationClient?: FederationClient,
	): Handler =>
	async (req) => {
		const userId = req.params.userId as UserId;

		// Remote user: fetch their profile over federation.
		const userServer = userId.slice(userId.indexOf(":") + 1);
		if (serverName && userServer !== serverName && federationClient) {
			try {
				const res = await federationClient.request(
					userServer as ServerName,
					"GET",
					`/_matrix/federation/v1/query/profile?user_id=${encodeURIComponent(userId)}`,
				);
				if (res.status !== 200) throw notFound("User not found");
				const p = res.body as {
					displayname?: string;
					avatar_url?: string;
				};
				return {
					status: 200,
					body: { displayname: p.displayname, avatar_url: p.avatar_url },
				};
			} catch {
				throw notFound("User not found");
			}
		}

		const profile = await storage.getProfile(userId);
		if (!profile) throw notFound("User not found");
		const extended = getExtendedFields(userId);
		return { status: 200, body: { ...profile, ...extended } };
	};

/** Fetch a remote user's profile over federation; undefined if the user is local. */
const fetchRemoteProfile = async (
	userId: UserId,
	serverName: string | undefined,
	federationClient: FederationClient | undefined,
): Promise<{ displayname?: string; avatar_url?: string } | undefined> => {
	const userServer = userId.slice(userId.indexOf(":") + 1);
	if (!serverName || userServer === serverName || !federationClient) {
		return undefined;
	}
	const res = await federationClient.request(
		userServer as ServerName,
		"GET",
		`/_matrix/federation/v1/query/profile?user_id=${encodeURIComponent(userId)}`,
	);
	if (res.status !== 200) throw notFound("User not found");
	return res.body as { displayname?: string; avatar_url?: string };
};

export const getDisplayName =
	(
		storage: Storage,
		serverName?: string,
		federationClient?: FederationClient,
	): Handler =>
	async (req) => {
		const userId = req.params.userId as UserId;
		const remote = await fetchRemoteProfile(
			userId,
			serverName,
			federationClient,
		);
		if (remote) {
			return { status: 200, body: { displayname: remote.displayname ?? null } };
		}
		const profile = await storage.getProfile(userId);
		if (!profile) throw notFound("User not found");
		return { status: 200, body: { displayname: profile.displayname ?? null } };
	};

export const getAvatarUrl =
	(
		storage: Storage,
		serverName?: string,
		federationClient?: FederationClient,
	): Handler =>
	async (req) => {
		const userId = req.params.userId as UserId;
		const remote = await fetchRemoteProfile(
			userId,
			serverName,
			federationClient,
		);
		if (remote) {
			return { status: 200, body: { avatar_url: remote.avatar_url ?? null } };
		}
		const profile = await storage.getProfile(userId);
		if (!profile) throw notFound("User not found");
		return { status: 200, body: { avatar_url: profile.avatar_url ?? null } };
	};

export const putDisplayName =
	(
		storage: Storage,
		serverName: string,
		signingKey?: SigningKey,
		federationClient?: FederationClient,
	): Handler =>
	async (req) => {
		const targetUserId = req.params.userId as UserId;
		if (req.userId !== targetUserId)
			throw forbidden("Cannot set displayname for another user");

		const body = req.body as Record<string, unknown>;
		const displayname = body.displayname as string | undefined;

		if (displayname !== undefined && displayname !== null) {
			if (Buffer.byteLength(displayname, "utf-8") > MAX_DISPLAYNAME_BYTES)
				throw badJson(`Displayname exceeds ${MAX_DISPLAYNAME_BYTES} bytes`);
		}

		await storage.setDisplayName(targetUserId, displayname ?? null);
		await storage.recordProfileUpdate(
			targetUserId,
			"displayname",
			displayname ?? null,
		);
		await propagateProfileToRooms(
			storage,
			serverName,
			targetUserId,
			signingKey,
			federationClient,
		);
		return { status: 200, body: {} };
	};

export const putAvatarUrl =
	(
		storage: Storage,
		serverName: string,
		signingKey?: SigningKey,
		federationClient?: FederationClient,
	): Handler =>
	async (req) => {
		const targetUserId = req.params.userId as UserId;
		if (req.userId !== targetUserId)
			throw forbidden("Cannot set avatar_url for another user");

		const body = req.body as Record<string, unknown>;
		const avatarUrl = body.avatar_url as string | undefined;

		if (avatarUrl !== undefined && avatarUrl !== null) {
			if (Buffer.byteLength(avatarUrl, "utf-8") > MAX_AVATAR_URL_BYTES)
				throw badJson(`Avatar URL exceeds ${MAX_AVATAR_URL_BYTES} bytes`);
		}

		await storage.setAvatarUrl(targetUserId, avatarUrl ?? null);
		await storage.recordProfileUpdate(
			targetUserId,
			"avatar_url",
			avatarUrl ?? null,
		);
		await propagateProfileToRooms(
			storage,
			serverName,
			targetUserId,
			signingKey,
			federationClient,
		);
		return { status: 200, body: {} };
	};

export const getProfileField =
	(storage: Storage): Handler =>
	async (req) => {
		const userId = req.params.userId as UserId;
		const keyName = req.params.keyName as string;

		// Handle well-known profile keys
		if (keyName === "displayname") {
			const profile = await storage.getProfile(userId);
			if (!profile) throw notFound("User not found");
			return {
				status: 200,
				body: { displayname: profile.displayname ?? null },
			};
		}
		if (keyName === "avatar_url") {
			const profile = await storage.getProfile(userId);
			if (!profile) throw notFound("User not found");
			return {
				status: 200,
				body: { avatar_url: profile.avatar_url ?? null },
			};
		}

		// Extended profile fields
		const profile = await storage.getProfile(userId);
		if (!profile) throw notFound("User not found");

		const value = extendedProfileFields.get(profileFieldKey(userId, keyName));
		if (value === undefined) throw notFound("Profile field not found");

		return {
			status: 200,
			body: { [keyName]: value },
		};
	};

export const putProfileField =
	(storage: Storage, serverName: string): Handler =>
	async (req) => {
		const targetUserId = req.params.userId as UserId;
		const keyName = req.params.keyName as string;

		if (req.userId !== targetUserId)
			throw forbidden("Cannot set profile fields for another user");

		const body = (req.body ?? {}) as Record<string, unknown>;

		// Handle well-known profile keys by delegating
		if (keyName === "displayname") {
			const displayname = body.displayname as string | undefined;
			if (displayname !== undefined && displayname !== null) {
				if (Buffer.byteLength(displayname, "utf-8") > MAX_DISPLAYNAME_BYTES)
					throw badJson(`Displayname exceeds ${MAX_DISPLAYNAME_BYTES} bytes`);
			}
			await storage.setDisplayName(targetUserId, displayname ?? null);
			await storage.recordProfileUpdate(
				targetUserId,
				"displayname",
				displayname ?? null,
			);
			await propagateProfileToRooms(storage, serverName, targetUserId);
			return { status: 200, body: {} };
		}
		if (keyName === "avatar_url") {
			const avatarUrl = body.avatar_url as string | undefined;
			if (avatarUrl !== undefined && avatarUrl !== null) {
				if (Buffer.byteLength(avatarUrl, "utf-8") > MAX_AVATAR_URL_BYTES)
					throw badJson(`Avatar URL exceeds ${MAX_AVATAR_URL_BYTES} bytes`);
			}
			await storage.setAvatarUrl(targetUserId, avatarUrl ?? null);
			await storage.recordProfileUpdate(
				targetUserId,
				"avatar_url",
				avatarUrl ?? null,
			);
			await propagateProfileToRooms(storage, serverName, targetUserId);
			return { status: 200, body: {} };
		}

		// Store extended profile field (MSC4133) and record it for MSC4429 sync.
		const value = body[keyName];
		extendedProfileFields.set(profileFieldKey(targetUserId, keyName), value);
		await storage.recordProfileUpdate(targetUserId, keyName, value);
		return { status: 200, body: {} };
	};

/** DELETE /_matrix/client/v3/profile/:userId/:keyName — clear a profile field. */
export const deleteProfileField =
	(storage: Storage, serverName: string): Handler =>
	async (req) => {
		const targetUserId = req.params.userId as UserId;
		const keyName = req.params.keyName as string;

		if (req.userId !== targetUserId)
			throw forbidden("Cannot delete profile fields for another user");

		if (keyName === "displayname") {
			await storage.setDisplayName(targetUserId, null);
			await propagateProfileToRooms(storage, serverName, targetUserId);
		} else if (keyName === "avatar_url") {
			await storage.setAvatarUrl(targetUserId, null);
			await propagateProfileToRooms(storage, serverName, targetUserId);
		} else {
			extendedProfileFields.delete(profileFieldKey(targetUserId, keyName));
		}
		// MSC4429: a cleared field is advertised as a null update in /sync.
		await storage.recordProfileUpdate(targetUserId, keyName, null);
		return { status: 200, body: {} };
	};
