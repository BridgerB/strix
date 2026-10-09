import { randomBytes } from "node:crypto";
import { generateRoomId } from "../crypto.ts";
import {
	badJson,
	forbidden,
	MatrixError,
	missingParam,
	notFound,
	roomNotFound,
} from "../errors.ts";
import {
	buildEvent,
	checkEventAuth,
	computeEventId,
	computeRoomIdV12,
	type EventContext,
	findAuthorisingLocalUser,
	getJoinRule,
	getMembership,
	getPowerLevels,
	getUserPowerLevel,
	isRoomVersion12Plus,
	iterMembers,
	membershipOf,
	selectAuthEvents,
	sendStateEvent,
	serverHasMember,
	userSatisfiesRestrictedAllow,
	validateAdditionalCreators,
} from "../events.ts";
import type { FederationClient } from "../federation/client.ts";
import { fanoutEdu, fanoutEvent } from "../federation/outbound.ts";
import { domainOf } from "../ids.ts";
import { getInviteRuleForTarget } from "../invite-filter.ts";
import type { Handler } from "../router.ts";
import type { SigningKey } from "../signing.ts";
import { signEvent } from "../signing.ts";
import type { Storage } from "../storage/interface.ts";
import { fullInviteState } from "../storage/ephemeral.ts";
import type { EDU, PDU } from "../types/events.ts";
import type {
	DeviceId,
	EventId,
	MatrixErrorCode,
	RoomId,
	ServerName,
	UserId,
} from "../types/index.ts";
import type { RoomState } from "../types/internal.ts";
import type { JsonObject } from "../types/json.ts";
import type { CreateRoomRequest } from "../types/room-operations.ts";
import type { RoomVersion } from "../types/room-versions.ts";
import type { RoomPowerLevelsContent } from "../types/state-events.ts";
import { resyncOutgoingDeviceListPokes } from "./e2ee.ts";
import { copyPredecessorPushRulesOnJoin } from "./room-upgrade.ts";

/**
 * For a restricted (or knock_restricted) room, find a LOCAL user who is joined
 * to this room and has permission to issue invites. This user is recorded in a
 * restricted join event's `content.join_authorised_via_users_server`. Returns
 * undefined if no such local user exists.
 *
 * Mirrors synapse's `get_users_which_can_issue_invite` (handlers/room_member.py):
 * a joined user can issue invites if they are a room creator (MSC4289, infinite
 * power in v11/v12 — surfaced via `getUserPowerLevel`) OR their power level is at
 * least the room's `invite` level. We pick the HIGHEST-power qualifying local
 * user (ties broken by user ID) rather than the first one we happen to iterate.
 * This makes the choice deterministic regardless of `state_events` Map ordering
 * and prefers the most authoritative local user (e.g. a creator over a user that
 * only marginally meets the invite level), which is the safest authoriser to
 * record so the join passes auth on every participating server.
 */
/**
 * Compute the set of REMOTE servers (excluding our own) that currently have a
 * joined user able to issue invites in this room. When our server is resident in
 * a restricted room but has no local user who can authorise a join (see
 * `findAuthorisingLocalUser`), the join must be performed over federation via one
 * of these servers — they are the only ones able to vouch for the joining user.
 *
 * Mirrors synapse's `_should_perform_remote_join`: when the local host is not in
 * `get_servers_from_users(get_users_which_can_issue_invite(state))`, it returns
 * those servers as the prospective remote-join hosts (handlers/room_member.py).
 */
const serversThatCanIssueInvite = (
	room: RoomState,
	localServerName: string,
): ServerName[] => {
	const pl = getPowerLevels(room);
	const invitePl = pl.invite ?? 0;

	const servers: ServerName[] = [];
	for (const { userId, membership } of iterMembers(room.state_events)) {
		if (membership !== "join") continue;
		if (getUserPowerLevel(userId, room) < invitePl) continue;

		const memberServer = domainOf(userId);
		if (!memberServer || memberServer === localServerName) continue;
		if (!servers.includes(memberServer as ServerName)) {
			servers.push(memberServer as ServerName);
		}
	}
	return servers;
};

/**
 * Determine whether our server is "resident" in a locally-known room, i.e. it
 * has full room state and at least one local user who is currently joined.
 *
 * A room can exist locally without us being resident: e.g. when we have only
 * received and stored a stripped invite (via PUT /federation/.../invite) for a
 * remote-owned room, the room has no `m.room.create` event and no joined local
 * member. In that situation a join must be performed over federation (mirroring
 * dendrite's `serverInRoom` check in roomserver/internal/perform/perform_join.go:
 * a forced federated join when we are not in the room).
 */
const isServerResidentInRoom = (
	room: RoomState,
	localServerName: string,
): boolean => {
	// Without the create event we never have authoritative room state and cannot
	// build valid events locally.
	if (!room.state_events.has("m.room.create\x1f")) return false;

	return serverHasMember(room.state_events, localServerName, "join");
};

/**
 * Collect the remote servers that should be told about a membership change for
 * `targetUserId`, computed from the CURRENT room state (i.e. before the change
 * is stored). This is the union of:
 *   - every remote server currently resident in the room (join/invite/knock),
 *     mirroring `getServersInRoom`, and
 *   - the target user's own server.
 *
 * The target's server is included explicitly because a leave (kick/unban/invite
 * rescission) flips the target's membership to `leave`/`ban` and, once stored,
 * `getServersInRoom` no longer counts that server. Without capturing it up front
 * the very server that needs to observe the departure would be dropped from the
 * fanout (the root cause of TestUnbanViaInvite and the "rescind invite over
 * federation" case of TestFederationRoomsInvite). Our own server is excluded.
 */
const collectMembershipDestinations = async (
	storage: Storage,
	serverName: string,
	roomId: RoomId,
	targetUserId: UserId,
	sender?: string,
): Promise<ServerName[]> => {
	const destinations = new Set<ServerName>();

	let servers: ServerName[] = [];
	try {
		servers = await storage.getServersInRoom(roomId);
	} catch {
		servers = [];
	}
	for (const s of servers) {
		if (s && s !== serverName) destinations.add(s as ServerName);
	}

	const targetServer = domainOf(targetUserId);
	if (targetServer && targetServer !== serverName) {
		destinations.add(targetServer as ServerName);

		// A server that knows the room ONLY through the target's pending invite
		// (out-of-band) hears about a change to that invite only from the original
		// inviter. A third party kicking the invitee must NOT reach the invitee's
		// otherwise-non-resident server — from that server's view the invite still
		// stands (TestFederationRoomsInvite "Non-invitee user cannot rescind invite
		// over federation"). We therefore drop the target's server when (a) the
		// caller named a `sender`, (b) the target is merely invited, (c) that
		// sender is not the inviter, and (d) the server has no OTHER member keeping
		// it in the room. The inviter's own rescission, a change to a joined
		// target, or another resident member all keep the server as a destination.
		if (sender) {
			const members = await storage.getMemberEvents(roomId);
			let targetMembership: string | undefined;
			let targetInviter: string | undefined;
			let otherMemberOnTargetServer = false;
			for (const { event } of members) {
				const sk = event.state_key;
				if (!sk) continue;
				const m = membershipOf(event);
				if (sk === targetUserId) {
					targetMembership = m;
					targetInviter = event.sender;
				} else if (
					(m === "join" || m === "invite" || m === "knock") &&
					domainOf(sk) === targetServer
				) {
					otherMemberOnTargetServer = true;
				}
			}
			const inviteOnly = targetMembership === "invite";
			if (
				inviteOnly &&
				targetInviter !== sender &&
				!otherMemberOnTargetServer
			) {
				destinations.delete(targetServer as ServerName);
			}
		}
	}

	return [...destinations];
};

/**
 * Deliver an already-signed event to an explicit list of remote servers via PUT
 * /_matrix/federation/v1/send/{txnId}. Unlike `fanoutEvent`, the destination set
 * is supplied by the caller rather than recomputed from current room state, so it
 * can include servers that the membership change has just removed from the room
 * (e.g. the kicked/unbanned user's server). Per-destination delivery is
 * fire-and-forget and never throws.
 */
const deliverEventToServers = async (
	serverName: string,
	federationClient: FederationClient,
	event: PDU,
	eventId: EventId,
	destinations: ServerName[],
): Promise<void> => {
	const targets = destinations.filter((s) => s && s !== serverName);
	for (const destination of targets) {
		const txnId = randomBytes(16).toString("base64url");
		const body = {
			origin: serverName,
			origin_server_ts: Date.now(),
			pdus: [event],
			edus: [],
		};
		void federationClient
			.request(
				destination,
				"PUT",
				`/_matrix/federation/v1/send/${encodeURIComponent(txnId)}`,
				body,
			)
			.then((resp) => {
				if (resp.status >= 400) {
					console.error(
						`deliverEventToServers: ${destination} rejected ${eventId} (status ${resp.status})`,
					);
				}
			})
			.catch((err) => {
				console.error(
					`deliverEventToServers: delivery of ${eventId} to ${destination} failed:`,
					(err as Error).message,
				);
			});
	}
};

export const postCreateRoom =
	(
		storage: Storage,
		serverName: string,
		signingKey?: SigningKey,
		federationClient?: FederationClient,
	): Handler =>
	async (req) => {
		const body = (req.body ?? {}) as CreateRoomRequest;
		const userId = req.userId as string;
		const roomVersion = body.room_version ?? "10";
		const v12Plus = isRoomVersion12Plus(roomVersion);

		// Validate room_version is a known version
		const KNOWN_ROOM_VERSIONS = new Set([
			"1",
			"2",
			"3",
			"4",
			"5",
			"6",
			"7",
			"8",
			"9",
			"10",
			"11",
			"12",
			// MSC3757 (owned state events) unstable room version
			"org.matrix.msc3757.10",
		]);
		if (
			body.room_version !== undefined &&
			typeof body.room_version !== "string"
		) {
			throw badJson("room_version must be a string");
		}
		if (
			body.room_version !== undefined &&
			!KNOWN_ROOM_VERSIONS.has(body.room_version)
		) {
			throw new MatrixError(
				"M_UNSUPPORTED_ROOM_VERSION",
				`Unsupported room version: ${body.room_version}`,
				400,
			);
		}

		// Validate visibility
		if (
			body.visibility !== undefined &&
			body.visibility !== "public" &&
			body.visibility !== "private"
		) {
			throw badJson("visibility must be 'public' or 'private'");
		}

		// Validate room_alias_name (local part only, no special chars)
		if (body.room_alias_name !== undefined) {
			if (!/^[a-zA-Z0-9._=\-/]+$/.test(body.room_alias_name)) {
				throw badJson("room_alias_name contains invalid characters");
			}
		}

		let roomId: string;

		// One timestamp shared between the temporary create event (used to derive
		// the v12 room ID) and the actual stored create event, so the stored
		// create event's ID equals the room ID (MSC4291). Without this, the two
		// builds call Date.now() independently and a millisecond boundary between
		// them makes room_id != create event ID (flaky v12 room creation).
		const createOriginServerTs = Date.now();

		const preset =
			body.preset ??
			(body.visibility === "public" ? "public_chat" : "private_chat");

		// `room_version` and `creator` in creation_content are ignored — the server
		// sets them authoritatively (spec: POST /createRoom creation_content).
		const {
			room_version: _ignoredVersion,
			creator: _ignoredCreator,
			...creationContentRest
		} = (body.creation_content ?? {}) as JsonObject;
		const createContent: JsonObject = {
			...creationContentRest,
			room_version: roomVersion,
		};

		// Room versions before 11 require "creator" in create event content
		const roomVersionNum = parseInt(roomVersion, 10);
		if (!Number.isNaN(roomVersionNum) && roomVersionNum < 11) {
			createContent.creator = userId;
		}

		if (v12Plus) {
			// MSC4289: validate `additional_creators` (check_valid_additional_creators)
			// BEFORE a room is created, so malformed values 400 early. We reuse the
			// exact validation exported from events.ts.
			if (createContent.additional_creators !== undefined) {
				validateAdditionalCreators(createContent.additional_creators);
			}

			// MSC4289: in v12+ the `trusted_private_chat` preset makes the invited
			// users room creators rather than PL100 admins. They are merged (and
			// deduped) into the create event's `additional_creators` alongside any
			// explicitly-supplied ones, instead of being written to
			// power_levels.users.
			if (preset === "trusted_private_chat" && body.invite) {
				const existing = (createContent.additional_creators ?? []) as string[];
				const merged = [...existing];
				for (const invitee of body.invite) {
					if (invitee !== userId && !merged.includes(invitee)) {
						merged.push(invitee);
					}
				}
				if (merged.length > 0) {
					createContent.additional_creators = merged;
				}
			}

			// For v12, we need to compute the room ID from the create event hash.
			// Build a temporary create event with a placeholder room_id to compute the hash.
			const tempRoomId = "!placeholder:temp" as RoomId;
			const { event: tempCreateEvent } = buildEvent({
				roomId: tempRoomId,
				sender: userId,
				type: "m.room.create",
				content: createContent,
				stateKey: "",
				depth: 0,
				prevEvents: [],
				authEvents: [],
				serverName,
				roomVersion,
				originServerTs: createOriginServerTs,
			});
			// Remove room_id from the temp event before hashing for v12
			const createForHash = { ...tempCreateEvent };
			delete (createForHash as Record<string, unknown>).room_id;
			roomId = computeRoomIdV12(createForHash);
		} else {
			roomId = generateRoomId(serverName);
		}

		const roomState: RoomState = {
			room_id: roomId,
			room_version: roomVersion,
			state_events: new Map(),
			depth: 0,
			forward_extremities: [],
		};
		await storage.createRoom(roomState);

		const ctx: EventContext = { roomState, depth: 0, prevEvents: [] };

		await sendStateEvent(
			storage,
			serverName,
			ctx,
			userId,
			"m.room.create",
			"",
			createContent,
			signingKey,
			federationClient,
			createOriginServerTs,
		);

		await sendStateEvent(
			storage,
			serverName,
			ctx,
			userId,
			"m.room.member",
			userId,
			{ membership: "join" },
			signingKey,
		);

		// In v12+, room creators have infinite power level implicitly,
		// so they must NOT appear in the users field of m.room.power_levels
		const plContent: RoomPowerLevelsContent = v12Plus
			? {
					users: {},
					users_default: 0,
					events_default: 0,
					state_default: 50,
					ban: 50,
					kick: 50,
					redact: 50,
					invite: 0,
					events: {
						"m.room.name": 50,
						"m.room.power_levels": 100,
						"m.room.history_visibility": 100,
						"m.room.canonical_alias": 50,
						"m.room.avatar": 50,
						"m.room.tombstone": 150,
						"m.room.server_acl": 100,
						"m.room.encryption": 100,
					},
				}
			: {
					users: { [userId]: 100 },
					users_default: 0,
					events_default: 0,
					state_default: 50,
					ban: 50,
					kick: 50,
					redact: 50,
					invite: 0,
					events: {
						"m.room.name": 50,
						"m.room.power_levels": 100,
						"m.room.history_visibility": 100,
						"m.room.canonical_alias": 50,
						"m.room.avatar": 50,
						"m.room.tombstone": 100,
						"m.room.server_acl": 100,
						"m.room.encryption": 100,
					},
				};
		if (preset === "trusted_private_chat" && body.invite) {
			for (const invitee of body.invite) {
				// MSC4289: in v12+ trusted_private_chat invitees are room creators
				// (added to create.content.additional_creators above), so they must
				// NOT appear in power_levels.users. For pre-v12 rooms they remain
				// PL100 admins as before.
				if (v12Plus) continue;
				(plContent.users as Record<string, number>)[invitee] = 100;
			}
		}
		if (body.power_level_content_override) {
			// MSC4289: do NOT strip the creator / additional_creators from the
			// override's users map. For v12 rooms creators must not appear in
			// power_levels.users, so passing them through lets checkEventAuth (in
			// events.ts) reject the power_levels event with a 400
			// ("power_level_content_override cannot set the room creator"). Non-creator
			// overrides flow through unchanged.
			Object.assign(plContent, body.power_level_content_override);
		}
		await sendStateEvent(
			storage,
			serverName,
			ctx,
			userId,
			"m.room.power_levels",
			"",
			plContent as unknown as JsonObject,
			signingKey,
		);

		const joinRule = preset === "public_chat" ? "public" : "invite";
		await sendStateEvent(
			storage,
			serverName,
			ctx,
			userId,
			"m.room.join_rules",
			"",
			{
				join_rule: joinRule,
			},
			signingKey,
		);

		await sendStateEvent(
			storage,
			serverName,
			ctx,
			userId,
			"m.room.history_visibility",
			"",
			{
				history_visibility: "shared",
			},
			signingKey,
		);

		// Guest access mirrors synapse's per-preset `guest_can_join`:
		//   public_chat               -> guest_can_join: false -> NO guest_access event
		//   private_chat / trusted_*  -> guest_can_join: true  -> guest_access: can_join
		// Emitting an m.room.guest_access for public_chat diverges from synapse and
		// breaks tests that assert public rooms have no guest_access state
		// (e.g. TestInboundCanReturnMissingEvents). So we only emit it when the
		// preset permits guests.
		if (preset !== "public_chat") {
			await sendStateEvent(
				storage,
				serverName,
				ctx,
				userId,
				"m.room.guest_access",
				"",
				{
					guest_access: "can_join",
				},
				signingKey,
			);
		}

		if (body.initial_state) {
			for (const stateInput of body.initial_state) {
				await sendStateEvent(
					storage,
					serverName,
					ctx,
					userId,
					stateInput.type,
					stateInput.state_key ?? "",
					stateInput.content,
					signingKey,
				);
			}
		}

		if (body.name) {
			await sendStateEvent(
				storage,
				serverName,
				ctx,
				userId,
				"m.room.name",
				"",
				{
					name: body.name,
				},
				signingKey,
			);
		}

		if (body.topic) {
			await sendStateEvent(
				storage,
				serverName,
				ctx,
				userId,
				"m.room.topic",
				"",
				{
					topic: body.topic,
					"m.topic": {
						"m.text": [{ body: body.topic }],
					},
				},
				signingKey,
			);
		}

		if (body.invite) {
			// Mirror synapse (handlers/room.py): when a room is created with
			// `is_direct: true`, every invite's m.room.member content carries
			// `is_direct: true` so the invitee can detect a DM in their /sync
			// invite_state. The flag is only added when truthy.
			const inviteContent: JsonObject = { membership: "invite" };
			if (body.is_direct) inviteContent.is_direct = true;
			for (const invitee of body.invite) {
				const inviteeServer = invitee.includes(":")
					? domainOf(invitee)
					: serverName;
				if (signingKey && federationClient && inviteeServer !== serverName) {
					// Remote invitee: invite over federation so their server learns of
					// (and co-signs) the invite. performOutboundInvite reads the room's
					// current depth/forward_extremities from storage, so make sure the
					// in-memory ctx is flushed back onto the room first.
					roomState.depth = ctx.depth;
					roomState.forward_extremities = [...ctx.prevEvents] as EventId[];
					await performOutboundInvite(
						storage,
						serverName,
						signingKey,
						federationClient,
						inviteeServer as ServerName,
						roomId as RoomId,
						userId,
						invitee as UserId,
						undefined,
						body.is_direct === true,
					);
					// Re-sync ctx from the room state mutated by performOutboundInvite.
					ctx.depth = roomState.depth;
					ctx.prevEvents = [...roomState.forward_extremities];
				} else {
					await sendStateEvent(
						storage,
						serverName,
						ctx,
						userId,
						"m.room.member",
						invitee,
						{ ...inviteContent },
						signingKey,
					);
				}
			}
		}

		if (body.room_alias_name) {
			const roomAlias = `#${body.room_alias_name}:${serverName}`;
			const existing = await storage.getRoomByAlias(roomAlias);
			if (existing) throw badJson(`Room alias ${roomAlias} already exists`);
			await storage.createRoomAlias(roomAlias, roomId, [serverName], userId);
			await sendStateEvent(
				storage,
				serverName,
				ctx,
				userId,
				"m.room.canonical_alias",
				"",
				{
					alias: roomAlias,
				},
				signingKey,
			);
		}

		if (body.visibility === "public") {
			await storage.setRoomVisibility(roomId, "public");
		}

		return { status: 200, body: { room_id: roomId } };
	};
export const getJoinedRooms =
	(storage: Storage): Handler =>
	async (req) => {
		const rooms = await storage.getRoomsForUser(req.userId as string);
		return { status: 200, body: { joined_rooms: rooms } };
	};
const sendMembershipEvent = async (
	storage: Storage,
	serverName: string,
	roomId: string,
	sender: string,
	targetUserId: string,
	membership: string,
	reason?: string,
	extraContent?: JsonObject,
	signingKey?: SigningKey,
	federationClient?: FederationClient,
): Promise<string> => {
	const room = await storage.getRoom(roomId);
	if (!room) throw roomNotFound();

	// Merge any client-supplied content first, then force the
	// server-controlled fields (membership and reason) on top so they
	// can never be overridden to an invalid value.
	const content: JsonObject = { ...(extraContent ?? {}), membership };
	if (reason) content.reason = reason;

	const ctx: EventContext = {
		roomState: room,
		depth: room.depth,
		prevEvents: [...room.forward_extremities],
	};

	// Capture the destination servers BEFORE applying the change. For a
	// leave/kick/ban the target's membership flips to leave/ban, after which
	// getServersInRoom (which only counts join/invite/knock) would no longer
	// include the target's home server — so the normal fanout in sendStateEvent
	// would never tell that server (and thus the affected user) about their own
	// removal. Collect the target's server up-front and deliver explicitly.
	const destinations =
		signingKey && federationClient
			? await collectMembershipDestinations(
					storage,
					serverName,
					roomId,
					targetUserId,
					sender,
				)
			: [];

	// sendStateEvent signs the event (when a key is given) and fans it out to
	// remote servers in the room (when a federation client is given), so local
	// membership changes (join/leave/kick/ban) propagate to other servers.
	const eventId = await sendStateEvent(
		storage,
		serverName,
		ctx,
		sender,
		"m.room.member",
		targetUserId,
		content,
		signingKey,
		federationClient,
	);

	// Explicitly deliver to pre-change destinations the post-change room no longer
	// includes — e.g. the target's own server after a leave/kick/ban. Servers
	// still in the room were already reached by sendStateEvent's fanout above, so
	// we exclude them here to avoid sending a DUPLICATE membership PDU (a strict
	// receiver like Complement's test server flags the second copy as unexpected).
	if (destinations.length > 0 && signingKey && federationClient) {
		const postServers = new Set(
			await storage.getServersInRoom(roomId as RoomId),
		);
		const extra = destinations.filter((d) => !postServers.has(d as ServerName));
		if (extra.length > 0) {
			const stored = await storage.getEvent(eventId as EventId);
			if (stored) {
				await deliverEventToServers(
					serverName,
					federationClient,
					stored.event,
					eventId as EventId,
					extra,
				);
			}
		}
	}

	return eventId;
};

// Monotonic per-process counter for device-list update stream IDs emitted when
// a local user joins a room that brings in new remote servers. The spec only
// requires stream_id to be a monotonically increasing integer per user; a
// process-wide counter satisfies that, and the Complement join test only
// asserts on user_id/device_id.
let deviceListJoinStreamCounter = 0;

/**
 * After a LOCAL user joins a room, notify the remote servers now resident in
 * that room about the user's device list by sending an `m.device_list_update`
 * EDU for each of the user's devices. This is required so a remote server that
 * was not previously receiving updates for this user (because it did not share
 * a room with them) learns of the user's devices once they join a shared room.
 *
 * Mirrors Synapse's DeviceHandler.notify_device_update (handlers/device.py):
 * whenever a user joins a room containing servers that are not already
 * receiving updates for that user's device list, those servers must be sent an
 * `m.device_list_update` EDU (see Synapse PR #16875). We fan the EDU out via
 * `fanoutEdu`, which resolves the remote servers resident in the joined room.
 *
 * Fire-and-forget: callers invoke this without awaiting its effect on the
 * client response, and `fanoutEdu` swallows per-destination delivery failures.
 */
const notifyDeviceListUpdateOnJoin = async (
	storage: Storage,
	serverName: string,
	signingKey: SigningKey | undefined,
	federationClient: FederationClient | undefined,
	roomId: RoomId,
	userId: UserId,
): Promise<void> => {
	if (!signingKey || !federationClient) return;

	// MSC3706: while the room is partial-state, device tracking is deferred until
	// the resync completes; do not announce device lists yet (peers mid-resync
	// would treat the m.device_list_update as unexpected).
	if (await storage.getRoomPartialState(roomId)) return;

	// Only the joining user's own server announces that user's devices.
	const userServer = domainOf(userId);
	if (userServer !== serverName) return;

	// Enumerate the user's devices. The device list update is per-device; when
	// the device has uploaded E2EE keys we include them so the remote can
	// populate /keys/query without a round-trip, mirroring Synapse.
	const devices = await storage.getAllDevices(userId);
	if (devices.length === 0) return;

	for (const device of devices) {
		const deviceId = device.device_id as DeviceId;
		const streamId = ++deviceListJoinStreamCounter;
		const content: Record<string, unknown> = {
			user_id: userId,
			device_id: deviceId,
			stream_id: streamId,
			prev_id: [],
			deleted: false,
		};
		if (device.display_name) content.device_display_name = device.display_name;
		const keys = await storage.getDeviceKeys(userId, deviceId);
		if (keys) content.keys = keys;

		const edu: EDU = {
			edu_type: "m.device_list_update",
			content: content as EDU["content"],
		};
		await fanoutEdu(
			storage,
			serverName,
			signingKey,
			federationClient,
			roomId,
			edu,
			true, // durable: device-list updates must survive a peer outage
		);
	}
};

export const postJoin =
	(
		storage: Storage,
		serverName: string,
		signingKey?: SigningKey,
		federationClient?: FederationClient,
	): Handler =>
	async (req) => {
		const roomIdOrAlias = req.params.roomIdOrAlias ?? req.params.roomId;
		if (!roomIdOrAlias) throw badJson("Missing room ID or alias");

		let roomId: string;
		const aliasServers: string[] = [];
		if (roomIdOrAlias.startsWith("#")) {
			const resolved = await storage.getRoomByAlias(roomIdOrAlias);
			if (resolved) {
				roomId = resolved.room_id;
				aliasServers.push(...resolved.servers);
			} else {
				// A remote alias must be resolved over federation via the alias's
				// home server (GET /_matrix/federation/v1/query/directory).
				const aliasDomain = roomIdOrAlias.slice(roomIdOrAlias.indexOf(":") + 1);
				if (aliasDomain && aliasDomain !== serverName && federationClient) {
					const dirRes = await federationClient.request(
						aliasDomain as ServerName,
						"GET",
						`/_matrix/federation/v1/query/directory?room_alias=${encodeURIComponent(roomIdOrAlias)}`,
					);
					const dir = dirRes.body as {
						room_id?: string;
						servers?: string[];
					};
					if (dirRes.status !== 200 || !dir.room_id) {
						throw notFound(`Room alias ${roomIdOrAlias} not found`);
					}
					roomId = dir.room_id;
					aliasServers.push(...(dir.servers ?? [aliasDomain]));
				} else {
					throw notFound(`Room alias ${roomIdOrAlias} not found`);
				}
			}
		} else {
			roomId = roomIdOrAlias;
		}

		// Make any servers learned from alias resolution available to the
		// federation-join fallback (alongside ?server_name= query params).
		for (const s of aliasServers) {
			if (s && !req.query.getAll("server_name").includes(s)) {
				req.query.append("server_name", s);
			}
		}

		const userId = req.userId as string;

		// The request body may carry arbitrary fields to merge into the
		// resulting m.room.member (join) event content (e.g. a custom key).
		// `reason` is pulled out and applied as the standard membership reason;
		// `membership` is stripped so it can't override the forced "join".
		const joinBody = (req.body ?? {}) as JsonObject;
		const {
			reason: joinReason,
			membership: _ignoredMembership,
			...extraJoinContent
		} = joinBody;

		// A banned user cannot join (or rejoin) — reject locally before federating.
		// A remote resident that hasn't seen our ban (or the Complement test
		// server, which doesn't enforce it) would otherwise let them back in.
		// (TestPartialStateJoin Leave_during_resync/can_be_triggered_by_remote_ban.)
		const knownRoom = await storage.getRoom(roomId as RoomId);
		if (knownRoom && getMembership(knownRoom, userId as UserId) === "ban") {
			throw forbidden("You are banned from this room");
		}

		// Attempt a federation join through any of the candidate servers. Used
		// both when the room is unknown locally and when the room is known but we
		// are not resident (e.g. we only hold a stripped invite). `priorityServers`
		// are tried first: for a restricted room where we are resident but cannot
		// authorise locally, these are the servers known to have a user who can
		// issue invites, so they must be preferred over the generic candidates.
		const attemptFederationJoin = async (
			priorityServers: ServerName[] = [],
		): Promise<{
			status: number;
			body: { room_id: string };
		}> => {
			if (!signingKey || !federationClient) {
				throw roomNotFound();
			}

			// Candidate servers to contact, in priority order:
			//  0. servers known to be able to authorise this restricted join
			//     (computed by us from room state — always trustworthy)
			//  1. ?server_name= query params (Complement passes these)
			//  2. the server in the room ID
			//  3. servers of any remote users who invited us (so an invite from a
			//     remote server lets us join via that server, per dendrite). Derived
			//     from actual room state, so safe to keep regardless.
			const serverNameParams = req.query.getAll("server_name");
			const roomServer = roomId.includes(":") ? domainOf(roomId) : undefined;

			const serversToTry: string[] = [];
			for (const s of priorityServers) {
				if (s !== serverName && !serversToTry.includes(s)) {
					serversToTry.push(s);
				}
			}
			for (const s of serverNameParams) {
				if (s !== serverName && !serversToTry.includes(s)) {
					serversToTry.push(s);
				}
			}
			// The room-ID server and inviter server are implicit FALLBACKS, used
			// only when the client gave no useful *remote* candidate (priority
			// servers + non-self `server_name`). When the client did name a remote
			// server we try exactly that, in order, and let the join fail if it
			// can't authorise — TestRestrictedRoomsRemoteJoinFailOver requires a
			// join via only a non-authorising server to FAIL rather than silently
			// fall over to the room's home server. Gating on the candidate list
			// being empty (not on `server_name` being present) is what keeps
			// TestRestrictedRoomsRemoteJoinLocalUser working: there the client
			// passes its OWN server as `server_name`, which filters out to nothing,
			// so the roomServer fallback must still apply.
			if (serversToTry.length === 0) {
				if (
					roomServer &&
					roomServer !== serverName &&
					!serversToTry.includes(roomServer)
				) {
					serversToTry.push(roomServer);
				}
				const existing = await storage.getRoom(roomId);
				if (existing) {
					const inviteEvent = existing.state_events.get(
						`m.room.member\x1f${userId}`,
					);
					const inviter = inviteEvent?.sender;
					if (typeof inviter === "string") {
						const inviterServer = domainOf(inviter);
						if (
							inviterServer &&
							inviterServer !== serverName &&
							!serversToTry.includes(inviterServer)
						) {
							serversToTry.push(inviterServer);
						}
					}
				}
			}

			if (serversToTry.length === 0) {
				throw roomNotFound();
			}

			let lastError: unknown;
			for (const remoteServer of serversToTry) {
				try {
					return await performFederationJoin(
						storage,
						serverName,
						signingKey,
						federationClient,
						remoteServer as ServerName,
						roomId as RoomId,
						userId,
					);
				} catch (err) {
					console.error(
						`Federation join to ${remoteServer} failed:`,
						(err as Error).message,
					);
					lastError = err;
				}
			}

			if (lastError instanceof Error) throw lastError;
			throw roomNotFound();
		};

		// Check if room exists locally
		const room = await storage.getRoom(roomId);
		// We are resident only if we have full room state and a joined local user.
		// If the room is known locally but we are not resident (e.g. we only hold
		// a stripped invite for a remote room), the join must go over federation —
		// we cannot build a valid join event locally. This mirrors dendrite forcing
		// a federated join when the server is not in the room.
		if (room && !isServerResidentInRoom(room, serverName)) {
			return attemptFederationJoin();
		}
		if (room) {
			// For a restricted (or knock_restricted) room, a join that is neither a
			// rejoin nor the acceptance of an invite must be authorised by a local
			// user who has invite power, recorded in
			// content.join_authorised_via_users_server. Without it the join event
			// fails auth.
			const joinContent: JsonObject = { ...extraJoinContent };
			const joinRule = getJoinRule(room);
			const currentMembership = getMembership(room, userId);
			if (
				(joinRule === "restricted" || joinRule === "knock_restricted") &&
				currentMembership !== "join" &&
				currentMembership !== "invite"
			) {
				// Per synapse's _should_perform_remote_join, the decision of
				// local-vs-remote join is made FIRST, based purely on whether this
				// server has a local user who can issue invites. The restricted
				// allow-rule check (does the joining user belong to an allowed
				// room?) is only performed when we are going to do the LOCAL join —
				// in the remote-join case the authorising remote server validates it
				// for us, and we may not even be resident in the allowed room (e.g.
				// the joining user is only joined to it on another server).
				const authoriser = findAuthorisingLocalUser(room, serverName);
				if (!authoriser) {
					// We are resident in this restricted room but have no local
					// user able to authorise the join. The join must then be
					// performed over federation via one of the servers that DOES
					// have a user who can issue invites. Prefer those servers; fall
					// back to the generic candidates (?server_name=, room server)
					// inside attemptFederationJoin.
					if (signingKey && federationClient) {
						return attemptFederationJoin(
							serversThatCanIssueInvite(room, serverName),
						);
					}
					throw forbidden("No local user able to authorise this join");
				} else {
					// We will do a local join. Now enforce the allow rules: the
					// joining user must belong to one of the allowed rooms we can
					// see, otherwise the local join must be refused.
					const satisfies = await userSatisfiesRestrictedAllow(
						storage,
						room,
						userId as UserId,
					);
					if (!satisfies) {
						throw forbidden(
							"You are not a member of any room that grants access to this room",
						);
					}
					joinContent.join_authorised_via_users_server = authoriser;
					await sendMembershipEvent(
						storage,
						serverName,
						roomId,
						userId,
						userId,
						"join",
						typeof joinReason === "string" ? joinReason : undefined,
						joinContent,
						signingKey,
						federationClient,
					);
					await clearForgottenMarker(storage, userId, roomId);
					void notifyDeviceListUpdateOnJoin(
						storage,
						serverName,
						signingKey,
						federationClient,
						roomId as RoomId,
						userId as UserId,
					).catch(() => {});
					await copyPredecessorPushRulesOnJoin(
						storage,
						userId as UserId,
						roomId as RoomId,
					);
					return { status: 200, body: { room_id: roomId } };
				}
			} else {
				// Non-restricted local join (or rejoin / invite acceptance).
				await sendMembershipEvent(
					storage,
					serverName,
					roomId,
					userId,
					userId,
					"join",
					typeof joinReason === "string" ? joinReason : undefined,
					extraJoinContent,
					signingKey,
					federationClient,
				);
				await clearForgottenMarker(storage, userId, roomId);
				void notifyDeviceListUpdateOnJoin(
					storage,
					serverName,
					signingKey,
					federationClient,
					roomId as RoomId,
					userId as UserId,
				).catch(() => {});
				await copyPredecessorPushRulesOnJoin(
					storage,
					userId as UserId,
					roomId as RoomId,
				);
				return { status: 200, body: { room_id: roomId } };
			}
		}

		// Room not found locally — attempt a federation join.
		return attemptFederationJoin();
	};

const performFederationJoin = async (
	storage: Storage,
	serverName: string,
	signingKey: SigningKey,
	federationClient: FederationClient,
	remoteServer: ServerName,
	roomId: RoomId,
	userId: string,
): Promise<{ status: number; body: { room_id: string } }> => {
	// 1. make_join — get a join event template from the remote server
	const makeJoinResp = await federationClient.request(
		remoteServer,
		"GET",
		`/_matrix/federation/v1/make_join/${encodeURIComponent(roomId)}/${encodeURIComponent(userId)}`,
	);

	if (makeJoinResp.status !== 200) {
		const respBody = makeJoinResp.body as Record<string, unknown> | undefined;
		// Propagate the remote server's client-meaningful error (e.g. a knock room
		// rejecting an uninvited join with 403 M_FORBIDDEN) rather than letting a
		// plain Error become a 500. Map 5xx upstream errors to 502.
		const mjStatus =
			makeJoinResp.status >= 400 && makeJoinResp.status < 500
				? makeJoinResp.status
				: 502;
		throw new MatrixError(
			(respBody?.errcode as MatrixErrorCode) ?? "M_UNKNOWN",
			(respBody?.error as string) ??
				`make_join failed: status ${makeJoinResp.status}`,
			mjStatus,
		);
	}

	const makeJoinBody = makeJoinResp.body as {
		room_version?: string;
		event?: PDU;
	};
	const template = makeJoinBody.event;
	if (!template) throw new Error("make_join response missing event template");

	const roomVersion = (makeJoinBody.room_version ?? "10") as RoomVersion;

	// 2. Fill in the template and sign it.
	// The template's content (membership: "join") is used as-is, which preserves
	// any `join_authorised_via_users_server` the resident server set for a
	// restricted-room join. This field is required for the join event to pass
	// auth on every participating server.
	template.origin_server_ts = Date.now();

	// Sign the event (this computes content hash and signs)
	const signedEvent = signEvent(
		template,
		serverName as ServerName,
		signingKey,
		roomVersion,
	);
	const eventId = computeEventId(signedEvent, roomVersion);

	// 3. send_join — send the signed event to the remote server. We request a
	// PARTIAL-STATE response (omit_members=true, MSC3706 faster joins): the
	// resident may then elide the room's member events so our join returns
	// immediately, and we backfill the omitted members via a background resync.
	const sendJoinResp = await federationClient.request(
		remoteServer,
		"PUT",
		`/_matrix/federation/v2/send_join/${encodeURIComponent(roomId)}/${encodeURIComponent(eventId)}?omit_members=true`,
		signedEvent,
	);

	if (sendJoinResp.status !== 200) {
		const respBody = sendJoinResp.body as Record<string, unknown> | undefined;
		const sjStatus =
			sendJoinResp.status >= 400 && sendJoinResp.status < 500
				? sendJoinResp.status
				: 502;
		throw new MatrixError(
			(respBody?.errcode as MatrixErrorCode) ?? "M_UNKNOWN",
			(respBody?.error as string) ??
				`send_join failed: status ${sendJoinResp.status}`,
			sjStatus,
		);
	}

	const sendJoinBody = sendJoinResp.body as {
		state?: PDU[];
		auth_chain?: PDU[];
		event?: PDU;
		members_omitted?: boolean;
		servers_in_room?: string[];
	};

	const stateEvents = sendJoinBody.state ?? [];
	const authChain = sendJoinBody.auth_chain ?? [];

	// 4. Import the room state
	// Include our join event in the state.
	const allState = [...stateEvents, sendJoinBody.event ?? signedEvent];

	// In room version 12+, the m.room.create event has no `room_id` in its body
	// (the room ID is derived from the create event hash). Storage needs a
	// non-null room_id on every event row, so inject it onto any event that is
	// missing it before importing. This does not affect event IDs/signatures
	// because those are computed over the redacted event, and for v12 create
	// events `room_id` is not part of the redacted/reference form.
	const ensureRoomId = (events: PDU[]): PDU[] =>
		events.map((e) => (e.room_id ? e : ({ ...e, room_id: roomId } as PDU)));

	// Are we joining a room we ALREADY hold? The cached room handed out by getRoom
	// is by-reference and importRoomState does not refresh it, so without help the
	// cache would not show our new join and /members etc. would treat us as not
	// joined. This happens on a rejoin after leave/ban AND on a fresh join into a
	// room another local user partial-joined (e.g. Alice partial-joins and leaves,
	// then Bob joins the same still-partial room). Re-apply our own membership via
	// setStateEvent in those cases. Excludes an invite-accept (membership
	// "invite"): re-applying state into a resident room's cache there regressed
	// restricted-join invite auth.
	const priorRoom = await storage.getRoom(roomId);
	const priorMembership = priorRoom
		? getMembership(priorRoom, userId)
		: undefined;
	const wasDeparted =
		!!priorRoom && priorMembership !== "join" && priorMembership !== "invite";

	await storage.importRoomState(
		roomId,
		roomVersion,
		ensureRoomId(allState),
		ensureRoomId(authChain),
	);

	// importRoomState writes to the store but does not refresh the by-reference
	// room cache that getRoom hands out, so on a re-join the cached membership
	// stays stale at "leave" and we'd be treated as a departed reader. Re-apply
	// just our join membership via setStateEvent (updates the cache in place).
	if (wasDeparted) {
		await storage.setStateEvent(roomId, signedEvent, eventId as EventId);
	}

	// Update the room's forward extremities and depth to include our join
	const room = await storage.getRoom(roomId);
	if (room) {
		room.forward_extremities = [eventId as EventId];
		room.depth = Math.max(room.depth, signedEvent.depth + 1);
	}

	// We have just joined a remote-owned room, so its remote servers (previously
	// unknown to us, hence not receiving this user's device-list updates) must
	// now be told about the local user's devices via an m.device_list_update EDU.
	// See notifyDeviceListUpdateOnJoin / Synapse handlers/device.py. For a
	// PARTIAL-STATE join we defer this: device tracking is reconciled when the
	// resync completes, and emitting it mid-resync would deliver an unexpected
	// m.device_list_update to peers.
	if (!sendJoinBody.members_omitted) {
		void notifyDeviceListUpdateOnJoin(
			storage,
			serverName,
			signingKey,
			federationClient,
			roomId,
			userId as UserId,
		).catch(() => {});
	}

	// MSC3706 partial-state join: the resident omitted the room's member events,
	// so we hold only critical state + our own membership. Mark the room
	// partial-state and start a background resync to fetch the full member state.
	// Until it completes, inbound make/send_join/knock are rejected (404), eager
	// /sync hides the room, and /members blocks. Mirrors synapse do_invite_join ->
	// _start_partial_state_room_sync.
	// If the room is ALREADY partial-state (e.g. a rejoin while the first resync
	// is still running, or another local user joining mid-resync), the in-flight
	// resync already covers it — do not start a second one (which would issue a
	// duplicate /state_ids the resident no longer expects).
	if (
		sendJoinBody.members_omitted &&
		!(await storage.getRoomPartialState(roomId))
	) {
		// Servers to try for the resync, in order: the server we joined THROUGH
		// (synapse's `joined_via` — it gave us the partial state and is the
		// authoritative source for the state at our join), then the others it named
		// in servers_in_room, then any we can derive from the critical state we DO
		// hold (e.g. the create / power-levels senders). Trying the join-through
		// server first also gives the other residents time to learn we joined — so
		// they will not refuse our /state_ids — before we fall back to them, and is
		// what lets us recover when the join-through server serves garbage state
		// (PartialStateJoinSyncsUsingOtherHomeservers).
		const stateSenderServers = (sendJoinBody.state ?? [])
			.map((e) => (e.sender ? domainOf(e.sender) : ""))
			.filter((s): s is string => !!s);
		const resyncServers = [
			...new Set(
				[
					remoteServer,
					...(sendJoinBody.servers_in_room ?? []),
					...stateSenderServers,
				].filter((s): s is string => !!s && s !== serverName),
			),
		] as ServerName[];
		// The full state we need is the state the join was built on — i.e. the
		// state AT the join's prev_event(s). synapse fetches /state_ids+/state for
		// those, and the Complement harness registers its handlers keyed to that
		// event id, not the join event's.
		const resyncTarget = (signedEvent.prev_events?.[0] ?? eventId) as EventId;
		await storage.markRoomPartialState(roomId, resyncServers, resyncTarget);
		void resyncPartialStateRoom(
			storage,
			serverName as ServerName,
			federationClient,
			roomId,
			resyncTarget,
			resyncServers,
			roomVersion,
		).catch((e) =>
			console.error(
				`partial-state resync failed for ${roomId}:`,
				(e as Error).message,
			),
		);
		// Give the resync a brief window to finish before returning. When the
		// resident can serve full state immediately (the common case — a real join
		// between cooperating servers) the room un-partial-states within
		// milliseconds and the caller never observes a partial-state room, so an
		// ordinary join is fully transparent. Only when the resync is genuinely
		// slow/blocked (the Complement partial-join harness deliberately stalls
		// /state_ids) does this time out and leave the room partial for the feature
		// to exercise. This keeps faster-joins from regressing normal remote joins.
		await storage.waitForPartialStateClear(roomId, 5000);
	}

	// If this room replaces an upgraded one, copy the joining user's room-scoped
	// push rule across (the upgrade happened on a remote server; we only learn of
	// it now). The create event carrying the predecessor is critical state we
	// hold even for a partial-state join.
	await copyPredecessorPushRulesOnJoin(storage, userId as UserId, roomId);

	return { status: 200, body: { room_id: roomId } };
};

/**
 * Background state resync for a partial-state (faster) join. Fetches the full
 * state at the join event from one of the servers that was in the room, imports
 * the previously-omitted member (and any other) state events, then clears the
 * partial-state flag (which unblocks /members and lets eager /sync surface the
 * room). Mirrors synapse's _sync_partial_state_room.
 */
const resyncPartialStateRoom = async (
	storage: Storage,
	serverName: ServerName,
	federationClient: FederationClient,
	roomId: RoomId,
	stateAtEventId: EventId,
	servers: ServerName[],
	roomVersion: RoomVersion,
): Promise<void> => {
	for (const server of servers) {
		try {
			// 1. /state_ids at the join event. The Complement harness gates the
			//    whole resync on this request, releasing it when the test is ready.
			const idsResp = await federationClient.request(
				server,
				"GET",
				`/_matrix/federation/v1/state_ids/${encodeURIComponent(roomId)}?event_id=${encodeURIComponent(stateAtEventId)}`,
			);
			if (idsResp.status !== 200) continue;
			// A valid /state_ids response lists the state event IDs in `pdu_ids`.
			// An empty/garbage response (e.g. `{}`) means this server cannot serve
			// the state — fall back to the next server WITHOUT issuing /state to it
			// (which it would not expect). PartialStateJoinSyncsUsingOtherHomeservers.
			const idsBody = idsResp.body as {
				pdu_ids?: string[];
				auth_chain_ids?: string[];
			};
			if (!idsBody.pdu_ids || idsBody.pdu_ids.length === 0) continue;

			// 2. /state — the full state event PDUs at the join.
			const stateResp = await federationClient.request(
				server,
				"GET",
				`/_matrix/federation/v1/state/${encodeURIComponent(roomId)}?event_id=${encodeURIComponent(stateAtEventId)}`,
			);
			if (stateResp.status !== 200) continue;
			const body = stateResp.body as {
				auth_chain?: PDU[];
				pdus?: PDU[];
				state?: PDU[];
			};
			const stateEvents = body.state ?? body.pdus ?? [];
			const authChain = body.auth_chain ?? [];
			if (stateEvents.length === 0) continue;

			// 3. Persist the auth chain, then store + set every returned state event
			//    as current state — this fills in the omitted members.
			for (const ev of authChain) {
				try {
					const id = computeEventId(ev, roomVersion);
					if (!(await storage.getEvent(id))) await storage.storeEvent(ev, id);
				} catch {
					/* skip malformed auth event */
				}
			}
			const current = await storage.getRoom(roomId);
			const revealedMembers: UserId[] = [];
			// The resident's authoritative state at the join, keyed by type+state_key
			// — used below to revert a rejected state event to its proper value.
			const residentState = new Map<string, { ev: PDU; id: EventId }>();
			for (const raw of stateEvents) {
				const ev =
					raw.room_id || roomVersion === "12"
						? raw
						: ({ ...raw, room_id: roomId } as PDU);
				if (ev.room_id && ev.room_id !== roomId) continue;
				let id: EventId;
				try {
					id = computeEventId(ev, roomVersion);
				} catch {
					continue;
				}
				const key = `${ev.type}\x1f${ev.state_key ?? ""}`;
				residentState.set(key, { ev, id });
				// Fill in state we don't already hold (the omitted members). Skip
				// re-setting state we already hold as the SAME event (create/power-
				// levels/our own membership). When we hold a DIFFERENT event for this
				// key, overwrite ONLY a stale/learned guess the resident has
				// superseded — i.e. the resident's value is newer (>= depth). A value
				// we received LIVE during the partial join that is NEWER than the
				// resident's target-time snapshot (e.g. a member who LEFT after our
				// join) must be kept, or we would resurrect them.
				const existing = current?.state_events.get(key);
				if (existing) {
					let existingId: EventId | undefined;
					try {
						existingId = computeEventId(existing, roomVersion);
					} catch {
						/* fall through to overwrite */
					}
					if (existingId === id) continue;
					if (existing.depth > ev.depth) continue;
				}
				// Store as HISTORICAL state: it joins current state but is kept out of
				// the forward timeline (pre-existing state we just learned, not new
				// activity), so it surfaces in /sync's `state` block and /members
				// rather than as a live timeline event.
				await storage.setStateEventHistorical(roomId, ev, id);
				if (
					ev.type === "m.room.member" &&
					membershipOf(ev) === "join" &&
					ev.state_key
				) {
					revealedMembers.push(ev.state_key as UserId);
				}
			}

			// Device-list reconciliation (synapse handle_room_un_partial_stated):
			// while partial-state we could not surface device-list changes for the
			// omitted members. A device-list update that arrived for such a member
			// during the resync was recorded on the change stream, but at a point
			// before we knew they shared a room with our users, so it was dropped
			// from device_lists.changed. Now that they are revealed, re-record a
			// change for each newly-revealed member that ALREADY has a pending
			// change, so local syncers are told to refetch their keys. Members with
			// no pending change are not re-recorded, or they would appear
			// spuriously in device_lists.changed.
			if (revealedMembers.length > 0) {
				const everChanged = new Set(
					await storage.getChangedDeviceUsers(0, Number.MAX_SAFE_INTEGER),
				);
				for (const member of revealedMembers) {
					if (everChanged.has(member)) {
						await storage.recordDeviceKeyChange(member);
					}
				}
			}

			// Re-auth events accepted under partial state against the now-complete
			// state. An event we accepted because we lacked full state (e.g. a state
			// event from a user who had actually already left) may no longer pass —
			// reject it: deleteEvent removes it so /event 404s and it vanishes from
			// state and /sync. Genuinely-valid events still pass and are untouched.
			// Mirrors synapse update_state_for_partial_state_event.
			// (State_accepted/rejected_incorrectly, Rejected_events_remain_rejected.)
			// Process newest-first (descending depth) and re-read the room before
			// each check, so a rejection + revert (e.g. a bad kick that reverts the
			// target's membership) is reflected when we then re-auth the EARLIER
			// events that depended on the reverted state (e.g. a state event the
			// target legitimately sent before being wrongly kicked).
			// Re-auth every event we processed under partial state against the
			// now-complete state and reconcile its accepted/rejected status, mirroring
			// synapse update_state_for_partial_state_event:
			//   - an event we ACCEPTED optimistically that no longer passes is rejected
			//     (deleteEvent → 404 / gone from state & /sync), reverting its state key;
			//   - an event we REJECTED under incomplete state that now passes is ACCEPTED
			//     (unrejectEvent) and, if a state event, made current.
			// We loop to a fixpoint because rejecting one event can revert a membership
			// that flips an earlier event's validity (e.g. a bad kick is rejected →
			// the target reverts to joined → a state event they sent becomes valid).
			type ReEval = { id: EventId; event: PDU; rejected: boolean };
			const entries: ReEval[] = [];
			for (const evId of await storage.takePartialStateEvents(roomId)) {
				const e = await storage.getEvent(evId);
				if (e) {
					entries.push({
						id: evId,
						event: e.event,
						rejected: e.rejected ?? false,
					});
				}
			}
			// Index by state key (objects shared, so .rejected stays live).
			const psByKey = new Map<string, ReEval[]>();
			for (const e of entries) {
				if (e.event.state_key === undefined) continue;
				const k = `${e.event.type}\x1f${e.event.state_key}`;
				const arr = psByKey.get(k);
				if (arr) arr.push(e);
				else psByKey.set(k, [e]);
			}
			entries.sort((a, b) => b.event.depth - a.event.depth);
			const isSelfMembership = (ev: PDU): boolean =>
				ev.type === "m.room.member" && ev.sender === ev.state_key;
			let changed = true;
			let pass = 0;
			while (changed && pass < 10) {
				changed = false;
				pass++;
				for (const entry of entries) {
					const { id: evId, event } = entry;
					// A self-membership transition (sender == state_key) is
					// self-authorising; re-authing it against the final state is circular
					// (a member's own leave would look invalid), so keep its status.
					if (isSelfMembership(event)) continue;
					const reconciled = await storage.getRoom(roomId);
					if (!reconciled) break;
					let passes = true;
					try {
						checkEventAuth(event, evId, reconciled);
					} catch {
						passes = false;
					}
					if (passes && entry.rejected) {
						// ACCEPT a previously-rejected event.
						await storage.unrejectEvent(evId);
						entry.rejected = false;
						if (event.state_key !== undefined) {
							const key = `${event.type}\x1f${event.state_key}`;
							const supersededByNewer = (psByKey.get(key) ?? []).some(
								(c) =>
									c.id !== evId && !c.rejected && c.event.depth > event.depth,
							);
							if (!supersededByNewer) {
								await storage.setStateEventHistorical(roomId, event, evId);
							}
						}
						changed = true;
					} else if (!passes && !entry.rejected) {
						// REJECT a previously-accepted event.
						entry.rejected = true;
						// Only repair the key if this event is still its LIVE value; a
						// newer event may have superseded it (don't resurrect a stale value).
						let wasCurrent = true;
						if (event.state_key !== undefined) {
							const curKey = `${event.type}\x1f${event.state_key}`;
							const cur = reconciled.state_events.get(curKey);
							if (cur) {
								try {
									wasCurrent = computeEventId(cur, roomVersion) === evId;
								} catch {
									/* unparseable current event: treat as live to be safe */
								}
							}
						}
						await storage.deleteEvent(evId);
						if (event.state_key !== undefined && wasCurrent) {
							const key = `${event.type}\x1f${event.state_key}`;
							const prior = (psByKey.get(key) ?? [])
								.filter(
									(c) =>
										c.id !== evId && !c.rejected && c.event.depth < event.depth,
								)
								.sort((a, b) => b.event.depth - a.event.depth)[0];
							if (prior) {
								await storage.setStateEventHistorical(
									roomId,
									prior.event,
									prior.id,
								);
							} else {
								const resident = residentState.get(key);
								if (resident) {
									await storage.setStateEventHistorical(
										roomId,
										resident.ev,
										resident.id,
									);
								}
							}
						}
						changed = true;
					}
				}
			}

			// Outbound device-list reconciliation: re-send any local device-list
			// changes we made while partial-state to servers that should have had
			// them but didn't because we didn't know they were in the room. The
			// candidate set (built below, mirroring synapse) is every server whose
			// membership changed between the join snapshot and the now-complete state,
			// plus every currently-joined server, minus the servers the resident named
			// at join (resyncOutgoingDeviceListPokes subtracts those and ourselves).
			const serversAtJoin = new Set<ServerName>();
			const addMemberServer = (sk: string | undefined): void => {
				if (!sk) return;
				const srv = domainOf(sk);
				if (srv) serversAtJoin.add(srv as ServerName);
			};
			// Membership at the join snapshot (resident's /state), keyed by user.
			const joinMembership = new Map<string, string | undefined>();
			for (const ev of stateEvents) {
				if (ev.type === "m.room.member") {
					joinMembership.set(ev.state_key ?? "", membershipOf(ev));
				}
			}
			// Current membership (after reconciliation): collect currently-joined
			// servers and note each member's current membership for the diff below.
			const reconciledRoom = await storage.getRoom(roomId);
			const currentMembership = new Map<string, string | undefined>();
			if (reconciledRoom) {
				for (const { userId: sk, membership } of iterMembers(
					reconciledRoom.state_events,
				)) {
					currentMembership.set(sk, membership);
					if (membership === "join") addMemberServer(sk);
				}
			}
			// Servers whose membership CHANGED between the join snapshot and now
			// (synapse handle_room_un_partial_stated). Essential for a server whose
			// user joined AFTER our join then left/was-kicked before resync: absent
			// from the join snapshot and not currently joined, so neither endpoint
			// alone surfaces it, but its membership did change.
			const memberKeys = new Set<string>([
				...joinMembership.keys(),
				...currentMembership.keys(),
			]);
			for (const sk of memberKeys) {
				if (joinMembership.get(sk) !== currentMembership.get(sk)) {
					addMemberServer(sk);
				}
			}
			await resyncOutgoingDeviceListPokes(
				storage,
				serverName,
				federationClient,
				roomId,
				serversAtJoin,
				new Set(servers),
			);

			// 4. Resync complete — clear the flag (wakes /members and /sync waiters).
			await storage.clearRoomPartialState(roomId);
			return;
		} catch (_e) {
			// Try the next server (PartialStateJoinSyncsUsingOtherHomeservers).
		}
	}
};

/**
 * Resume background resyncs for rooms still in partial state — called once at
 * startup. A resync runs in-process, so a restart mid-resync would otherwise
 * leave the room partial forever. The sqlite backend persists the partial-state
 * flag (room id, servers to retry, the event to fetch state at) across a
 * restart, so we re-kick the resync for each. Mirrors synapse
 * `_resume_partial_state_room_sync`. (TestPartialStateJoinContinuesAfterRestart.)
 */
export const resumePartialStateResyncs = async (
	storage: Storage,
	serverName: ServerName,
	federationClient: FederationClient,
): Promise<void> => {
	const partials = await storage.getAllPartialStateRooms();
	for (const { roomId, servers, joinEventId } of partials) {
		const room = await storage.getRoom(roomId);
		if (!room) continue;
		void resyncPartialStateRoom(
			storage,
			serverName,
			federationClient,
			roomId,
			joinEventId,
			servers,
			room.room_version,
		).catch((e) =>
			console.error(
				`partial-state resync resume failed for ${roomId}:`,
				(e as Error).message,
			),
		);
	}
};

export const postLeave =
	(
		storage: Storage,
		serverName: string,
		signingKey?: SigningKey,
		federationClient?: FederationClient,
	): Handler =>
	async (req) => {
		const roomId = req.params.roomId as string;
		const userId = req.userId as string;
		const body = (req.body ?? {}) as { reason?: string };

		// A leave of a remote-owned room must be performed over federation via
		// make_leave/send_leave so the room's owning/resident servers learn about
		// it. A purely local leave would never reach them. We key off room
		// ownership (the server in the room ID) rather than our own residency,
		// because even when a local user is the only member we know about, the
		// authoritative copy of the room lives on the owning server and must be
		// told. This mirrors how dendrite/synapse distribute membership changes.
		const roomServer = roomId.includes(":") ? domainOf(roomId) : undefined;
		// If we are resident (hold the room's state with a joined local user) we can
		// build the leave event ourselves and fan it out as a normal PDU — including
		// to the owning server — rather than round-tripping make_leave/send_leave.
		// This is required for partial-state rooms (synapse leaves locally; the
		// resident learns of it via /send, which is what TestPartialStateJoin's
		// WithWaitForLeave expects) and is correct for any room we are joined to.
		const leaveRoom = await storage.getRoom(roomId as RoomId);
		const leaveMembership = leaveRoom
			? getMembership(leaveRoom, userId as UserId)
			: undefined;
		// Leaving a room we have already left (or been banned from) is a no-op —
		// return 200 without re-federating a make_leave/send_leave (synapse). This
		// matters for partial-state cleanup, where the user already left during the
		// resync and a second /leave would otherwise round-trip make_leave to a
		// resident that no longer expects it.
		if (leaveMembership === "leave" || leaveMembership === "ban") {
			return { status: 200, body: {} };
		}
		const canLeaveLocally =
			!!leaveRoom &&
			isServerResidentInRoom(leaveRoom, serverName) &&
			(leaveMembership === "join" || leaveMembership === "invite");
		const needsFederation =
			signingKey !== undefined &&
			federationClient !== undefined &&
			roomServer !== undefined &&
			roomServer !== serverName &&
			!canLeaveLocally;

		if (needsFederation) {
			try {
				await performFederationLeave(
					storage,
					serverName,
					signingKey as SigningKey,
					federationClient as FederationClient,
					roomServer as ServerName,
					roomId as RoomId,
					userId,
					body.reason,
				);
				return { status: 200, body: {} };
			} catch (err) {
				console.error(
					`Federation leave to ${roomServer} failed:`,
					(err as Error).message,
				);
				// Fall through to a best-effort local leave so the client at least
				// stops seeing the room.
			}
		}

		await sendMembershipEvent(
			storage,
			serverName,
			roomId,
			userId,
			userId,
			"leave",
			body.reason,
			undefined,
			signingKey,
			federationClient,
		);
		return { status: 200, body: {} };
	};

/**
 * Perform a federation leave of a remote-owned room on behalf of a local user.
 * Mirrors dendrite/synapse: GET make_leave to obtain a template, fill + sign it,
 * then PUT send_leave. On success the local membership is recorded as "leave"
 * so the user's own /sync reflects the departure.
 */
const performFederationLeave = async (
	storage: Storage,
	serverName: string,
	signingKey: SigningKey,
	federationClient: FederationClient,
	remoteServer: ServerName,
	roomId: RoomId,
	userId: string,
	reason?: string,
): Promise<void> => {
	const makeLeaveResp = await federationClient.request(
		remoteServer,
		"GET",
		`/_matrix/federation/v1/make_leave/${encodeURIComponent(roomId)}/${encodeURIComponent(userId)}`,
	);
	if (makeLeaveResp.status !== 200) {
		const b = makeLeaveResp.body as Record<string, unknown> | undefined;
		throw new Error(
			`make_leave failed: ${b?.error ?? b?.errcode ?? `status ${makeLeaveResp.status}`}`,
		);
	}

	const makeLeaveBody = makeLeaveResp.body as {
		room_version?: string;
		event?: PDU;
	};
	const template = makeLeaveBody.event;
	if (!template) throw new Error("make_leave response missing event template");

	// Fall back to the locally-known room version if make_leave omits it, then to
	// our server default. The signature/ID must use the room's redaction rules.
	const roomVersion =
		makeLeaveBody.room_version ??
		(await storage.getRoom(roomId))?.room_version ??
		"10";

	if (!template.room_id) {
		(template as unknown as Record<string, unknown>).room_id = roomId;
	}
	const content = (template.content ?? {}) as Record<string, unknown>;
	content.membership = "leave";
	if (reason) content.reason = reason;
	template.content = content as PDU["content"];
	template.origin_server_ts = Date.now();

	const signedEvent = signEvent(
		template,
		serverName as ServerName,
		signingKey,
		roomVersion,
	);
	const eventId = computeEventId(signedEvent, roomVersion);

	const sendLeaveResp = await federationClient.request(
		remoteServer,
		"PUT",
		`/_matrix/federation/v2/send_leave/${encodeURIComponent(roomId)}/${encodeURIComponent(eventId)}`,
		signedEvent,
	);
	if (sendLeaveResp.status !== 200) {
		const b = sendLeaveResp.body as Record<string, unknown> | undefined;
		throw new Error(
			`send_leave failed: ${b?.error ?? b?.errcode ?? `status ${sendLeaveResp.status}`}`,
		);
	}

	// Record the leave locally so the user's own /sync reflects the departure.
	const room = await storage.getRoom(roomId);
	if (room) {
		await storage.setStateEvent(roomId, signedEvent, eventId);
		room.depth = Math.max(room.depth, signedEvent.depth + 1);
		room.forward_extremities = [eventId];
	} else {
		await storage.importRoomState(
			roomId,
			(makeLeaveBody.room_version ?? "10") as RoomVersion,
			[signedEvent],
			[],
		);
	}
};

export const postInvite =
	(
		storage: Storage,
		serverName: string,
		signingKey?: SigningKey,
		federationClient?: FederationClient,
	): Handler =>
	async (req) => {
		const roomId = req.params.roomId as string;
		const body = req.body as
			| { user_id?: string; reason?: string; is_direct?: boolean }
			| undefined;
		if (!body?.user_id) throw missingParam("Missing 'user_id'");

		const inviteeServer = body.user_id.includes(":")
			? domainOf(body.user_id)
			: serverName;

		// MSC4155 invite filtering: when the invitee is local to this server, honour
		// the invite permission config they published in their global account data.
		// A "block" rule rejects the invite outright (403); an "ignore" rule lets the
		// request succeed (200) but the invite is silently dropped so it never
		// reaches the invitee's /sync. "allow" (the default, including no config) is
		// a no-op. Inviters on other servers reach us via inbound federation
		// (putFederationInvite), which applies the same filtering on that path.
		if (inviteeServer === serverName) {
			const rule = await getInviteRuleForTarget(
				storage,
				body.user_id as UserId,
				req.userId as string,
			);
			if (rule === "block") {
				throw forbidden("You are not permitted to invite this user.");
			}
			if (rule === "ignore") {
				return { status: 200, body: {} };
			}
		}

		// A remote invitee must be invited over federation (PUT /v2/invite) so the
		// invitee's server learns about (and co-signs) the invite. Mirrors
		// synapse's FederationHandler.send_invite / the inbound putFederationInvite
		// we already implement on the receiving side.
		if (signingKey && federationClient && inviteeServer !== serverName) {
			await performOutboundInvite(
				storage,
				serverName,
				signingKey,
				federationClient,
				inviteeServer as ServerName,
				roomId as RoomId,
				req.userId as string,
				body.user_id as UserId,
				body.reason,
				body.is_direct === true,
			);
			return { status: 200, body: {} };
		}

		// Thread `is_direct` into the invite member content when the caller marks
		// this as a direct (DM) invite, mirroring synapse so the invitee can detect
		// the DM in their /sync invite_state.
		const inviteExtra: JsonObject | undefined =
			body.is_direct === true ? { is_direct: true } : undefined;
		await sendMembershipEvent(
			storage,
			serverName,
			roomId,
			req.userId as string,
			body.user_id,
			"invite",
			body.reason,
			inviteExtra,
			signingKey,
			federationClient,
		);
		return { status: 200, body: {} };
	};

/**
 * Invite a remote user over federation. Builds and signs the m.room.member
 * (invite) event locally, PUTs it to the invitee's server at
 * /_matrix/federation/v2/invite/{roomId}/{eventId} along with the room version
 * and the room's stripped state, then stores the co-signed event returned by
 * that server. Mirrors the inbound putFederationInvite co-sign pattern and
 * dendrite/synapse outbound invite flow.
 */
const performOutboundInvite = async (
	storage: Storage,
	serverName: string,
	signingKey: SigningKey,
	federationClient: FederationClient,
	inviteeServer: ServerName,
	roomId: RoomId,
	sender: string,
	targetUserId: UserId,
	reason?: string,
	isDirect?: boolean,
): Promise<void> => {
	const room = await storage.getRoom(roomId);
	if (!room) throw roomNotFound();

	const content: JsonObject = { membership: "invite" };
	if (reason) content.reason = reason;
	if (isDirect) content.is_direct = true;

	const authEvents = selectAuthEvents(
		"m.room.member",
		targetUserId,
		room,
		sender as UserId,
	);
	const { event, eventId } = buildEvent({
		roomId,
		sender: sender as UserId,
		type: "m.room.member",
		content,
		stateKey: targetUserId,
		depth: room.depth,
		prevEvents: [...room.forward_extremities],
		authEvents,
		serverName: serverName as ServerName,
		signingKey,
		roomVersion: room.room_version,
	});

	// Local auth check before sending — the inviter must have permission.
	checkEventAuth(event, eventId, room);

	// MSC4311: invite_room_state carries FULL events (not the stripped form) so
	// the invitee's server can verify them; m.room.create is always included.
	const inviteRoomState = fullInviteState(room);

	const inviteResp = await federationClient.request(
		inviteeServer,
		"PUT",
		`/_matrix/federation/v2/invite/${encodeURIComponent(roomId)}/${encodeURIComponent(eventId)}`,
		{
			room_version: room.room_version,
			event,
			invite_room_state: inviteRoomState,
		},
	);

	if (inviteResp.status !== 200) {
		const b = inviteResp.body as Record<string, unknown> | undefined;
		throw new MatrixError(
			(typeof b?.errcode === "string"
				? b.errcode
				: "M_UNKNOWN") as MatrixErrorCode,
			typeof b?.error === "string"
				? b.error
				: `invite failed: status ${inviteResp.status}`,
			inviteResp.status === 403 ? 403 : 400,
		);
	}

	// The remote server returns the invite event co-signed with its signature.
	// Store that (it merges both servers' signatures) so our copy is fully
	// signed. Fall back to our locally-signed event if the response is malformed.
	const respBody = inviteResp.body as { event?: PDU } | undefined;
	const storedEvent =
		respBody?.event && typeof respBody.event === "object"
			? respBody.event
			: event;

	await storage.setStateEvent(roomId, storedEvent, eventId);
	room.depth = room.depth + 1;
	room.forward_extremities = [eventId];

	// Also propagate to any OTHER remote servers already in the room (the
	// invitee's own server already has it via /invite).
	await fanoutEvent(
		storage,
		serverName,
		signingKey,
		federationClient,
		roomId,
		storedEvent,
		eventId,
	);
};

export const postKnock =
	(
		storage: Storage,
		serverName: string,
		signingKey?: SigningKey,
		federationClient?: FederationClient,
	): Handler =>
	async (req) => {
		const roomIdOrAlias = req.params.roomIdOrAlias ?? req.params.roomId;
		if (!roomIdOrAlias) throw badJson("Missing room ID or alias");

		let roomId: string;
		if (roomIdOrAlias.startsWith("#")) {
			const resolved = await storage.getRoomByAlias(roomIdOrAlias);
			if (!resolved) throw notFound(`Room alias ${roomIdOrAlias} not found`);
			roomId = resolved.room_id;
		} else {
			roomId = roomIdOrAlias;
		}

		const userId = req.userId as string;
		const body = (req.body ?? {}) as { reason?: string };

		const room = await storage.getRoom(roomId);

		// If the room is remote-owned and we are not resident, knock over
		// federation (make_knock/send_knock) so the resident servers learn of the
		// knock. Candidate servers come from ?server_name= and the room ID, plus
		// any server we already know holds this room.
		const roomServer = roomId.includes(":") ? domainOf(roomId) : undefined;
		const needsFederation =
			signingKey !== undefined &&
			federationClient !== undefined &&
			(room === undefined || !isServerResidentInRoom(room, serverName)) &&
			roomServer !== serverName;

		if (needsFederation) {
			const serversToTry: string[] = [];
			for (const s of req.query.getAll("server_name")) {
				if (!serversToTry.includes(s)) serversToTry.push(s);
			}
			if (roomServer && !serversToTry.includes(roomServer)) {
				serversToTry.push(roomServer);
			}
			if (serversToTry.length === 0) throw roomNotFound();

			let lastError: unknown;
			for (const remoteServer of serversToTry) {
				try {
					await performFederationKnock(
						storage,
						serverName,
						signingKey as SigningKey,
						federationClient as FederationClient,
						remoteServer as ServerName,
						roomId as RoomId,
						userId,
						body.reason,
					);
					return { status: 200, body: { room_id: roomId } };
				} catch (err) {
					console.error(
						`Federation knock to ${remoteServer} failed:`,
						(err as Error).message,
					);
					lastError = err;
				}
			}
			if (lastError instanceof MatrixError) throw lastError;
			if (lastError instanceof Error) throw lastError;
			throw roomNotFound();
		}

		await sendMembershipEvent(
			storage,
			serverName,
			roomId,
			userId,
			userId,
			"knock",
			body.reason,
			undefined,
			signingKey,
			federationClient,
		);
		return { status: 200, body: { room_id: roomId } };
	};

/**
 * Perform a federation knock on a remote-owned room for a local user. Mirrors
 * synapse's FederationHandler.do_knock: GET make_knock to obtain a template,
 * fill in the reason + sign it, then PUT send_knock. The send_knock response
 * carries `knock_room_state` (stripped state) which we stash on the knock
 * event's unsigned so it can be surfaced in the knocker's /sync (rooms.knock).
 * The knock member event is then stored locally as an out-of-band membership.
 */
const performFederationKnock = async (
	storage: Storage,
	serverName: string,
	signingKey: SigningKey,
	federationClient: FederationClient,
	remoteServer: ServerName,
	roomId: RoomId,
	userId: string,
	reason?: string,
): Promise<void> => {
	const makeKnockResp = await federationClient.request(
		remoteServer,
		"GET",
		`/_matrix/federation/v1/make_knock/${encodeURIComponent(roomId)}/${encodeURIComponent(userId)}?ver=1&ver=2&ver=3&ver=4&ver=5&ver=6&ver=7&ver=8&ver=9&ver=10&ver=11&ver=12`,
	);
	if (makeKnockResp.status !== 200) {
		const b = makeKnockResp.body as Record<string, unknown> | undefined;
		const errcode = (
			typeof b?.errcode === "string" ? b.errcode : "M_FORBIDDEN"
		) as MatrixErrorCode;
		const error =
			typeof b?.error === "string"
				? b.error
				: `make_knock failed: status ${makeKnockResp.status}`;
		throw new MatrixError(
			errcode,
			error,
			makeKnockResp.status === 403 ? 403 : 400,
		);
	}

	const makeKnockBody = makeKnockResp.body as {
		room_version?: string;
		event?: PDU;
	};
	const template = makeKnockBody.event;
	if (!template) throw new Error("make_knock response missing event template");

	const roomVersion =
		makeKnockBody.room_version ??
		(await storage.getRoom(roomId))?.room_version ??
		"10";

	if (!template.room_id) {
		(template as unknown as Record<string, unknown>).room_id = roomId;
	}
	const content = (template.content ?? {}) as Record<string, unknown>;
	content.membership = "knock";
	if (reason) content.reason = reason;
	template.content = content as PDU["content"];
	template.origin_server_ts = Date.now();

	const signedEvent = signEvent(
		template,
		serverName as ServerName,
		signingKey,
		roomVersion,
	);
	const eventId = computeEventId(signedEvent, roomVersion);

	const sendKnockResp = await federationClient.request(
		remoteServer,
		"PUT",
		`/_matrix/federation/v1/send_knock/${encodeURIComponent(roomId)}/${encodeURIComponent(eventId)}`,
		signedEvent,
	);
	if (sendKnockResp.status !== 200) {
		const b = sendKnockResp.body as Record<string, unknown> | undefined;
		const errcode = (
			typeof b?.errcode === "string" ? b.errcode : "M_FORBIDDEN"
		) as MatrixErrorCode;
		const error =
			typeof b?.error === "string"
				? b.error
				: `send_knock failed: status ${sendKnockResp.status}`;
		throw new MatrixError(
			errcode,
			error,
			sendKnockResp.status === 403 ? 403 : 400,
		);
	}

	const sendKnockBody = sendKnockResp.body as {
		knock_room_state?: unknown[];
	};
	const knockRoomState = Array.isArray(sendKnockBody.knock_room_state)
		? sendKnockBody.knock_room_state
		: [];

	// Stash the stripped room state on the knock event's unsigned so sync can
	// surface it under rooms.knock.<roomId>.knock_state (mirrors synapse storing
	// knock_room_state in unsigned).
	const storedEvent = {
		...signedEvent,
		unsigned: {
			...((signedEvent.unsigned as Record<string, unknown>) ?? {}),
			knock_room_state: knockRoomState,
		},
	} as PDU;

	// Persist the knock as an out-of-band membership so the knocker's /sync
	// reflects it. If we have no prior room record, seed a minimal one from the
	// stripped state plus our knock event.
	const room = await storage.getRoom(roomId);
	if (room) {
		await storage.setStateEvent(roomId, storedEvent, eventId);
		room.depth = Math.max(room.depth, storedEvent.depth + 1);
		room.forward_extremities = [eventId];
	} else {
		await storage.importRoomState(
			roomId,
			(makeKnockBody.room_version ?? "7") as RoomVersion,
			[storedEvent],
			[],
		);
	}
};

export const postKick =
	(
		storage: Storage,
		serverName: string,
		signingKey?: SigningKey,
		federationClient?: FederationClient,
	): Handler =>
	async (req) => {
		const roomId = req.params.roomId as string;
		const body = req.body as { user_id?: string; reason?: string } | undefined;
		if (!body?.user_id) throw missingParam("Missing 'user_id'");

		// The client /kick endpoint may only kick a user who is currently in the
		// room — join (a normal kick), invite (rescinding an invite) or knock
		// (rejecting a knock). Kicking a user who has already left or was never
		// present is a 403 (Users cannot kick users who have already left /
		// are not in the room). This endpoint-level guard is stricter than the
		// federation event-auth rules (which authorise a kick purely by power
		// level per the spec); synapse/dendrite enforce the same at the C-S API.
		const targetRoom = await storage.getRoom(roomId as RoomId);
		const targetMembership = targetRoom
			? getMembership(targetRoom, body.user_id as UserId)
			: undefined;
		if (
			targetMembership !== "join" &&
			targetMembership !== "invite" &&
			targetMembership !== "knock"
		) {
			throw forbidden("Cannot kick a user who is not in the room");
		}

		// Capture the kicked user's server BEFORE their membership flips to `leave`.
		// When the target is a remote user who was only *invited* (an invite
		// rescission, see TestFederationRoomsInvite "Inviter user can rescind invite
		// over federation"), that server is in the room solely because of this
		// pending invite. Once we store the leave, `getServersInRoom` (used by the
		// normal fanout inside sendMembershipEvent) no longer counts them, so the
		// rescission would never reach them. We therefore deliver to the target's
		// server explicitly after sending.
		const extraDestinations = await collectMembershipDestinations(
			storage,
			serverName,
			roomId as RoomId,
			body.user_id as UserId,
			req.userId as string,
		);

		const eventId = await sendMembershipEvent(
			storage,
			serverName,
			roomId,
			req.userId as string,
			body.user_id,
			"leave",
			body.reason,
			undefined,
			signingKey,
			federationClient,
		);

		// Deliver the leave to the kicked user's server even though it is no longer
		// resident per the post-kick state. The stored leave event is fetched back
		// so we forward exactly what was persisted (signed form).
		if (signingKey && federationClient && extraDestinations.length > 0) {
			const stored = await storage.getEvent(eventId as EventId);
			if (stored) {
				await deliverEventToServers(
					serverName,
					federationClient,
					stored.event,
					eventId as EventId,
					extraDestinations,
				);
			}
		}
		return { status: 200, body: {} };
	};

export const postBan =
	(
		storage: Storage,
		serverName: string,
		signingKey?: SigningKey,
		federationClient?: FederationClient,
	): Handler =>
	async (req) => {
		const roomId = req.params.roomId as string;
		const body = req.body as { user_id?: string; reason?: string } | undefined;
		if (!body?.user_id) throw missingParam("Missing 'user_id'");
		await sendMembershipEvent(
			storage,
			serverName,
			roomId,
			req.userId as string,
			body.user_id,
			"ban",
			body.reason,
			undefined,
			signingKey,
			federationClient,
		);
		return { status: 200, body: {} };
	};

export const postUnban =
	(
		storage: Storage,
		serverName: string,
		signingKey?: SigningKey,
		federationClient?: FederationClient,
	): Handler =>
	async (req) => {
		const roomId = req.params.roomId as string;
		const body = req.body as { user_id?: string; reason?: string } | undefined;
		if (!body?.user_id) throw missingParam("Missing 'user_id'");

		const room = await storage.getRoom(roomId);
		if (!room) throw roomNotFound();
		const sender = req.userId as string;
		const targetUserId = body.user_id;
		const currentMembership = getMembership(room, targetUserId);
		if (currentMembership !== "ban") throw forbidden("User is not banned");

		// Unban is a `leave` event sent by another user against a banned target.
		// The shared auth check (checkMembershipAuth in src/events.ts, "leave" case)
		// rejects this because it treats every leave-against-another-user as a kick
		// and requires the target to currently be join/invite. Per the spec, an unban
		// (leave where the target is banned) is valid when the sender is joined and has
		// the ban power level. We therefore perform the unban authorization here and
		// store the resulting leave event directly, bypassing the kick-only check.
		const senderMembership = getMembership(room, sender);
		if (senderMembership !== "join") {
			throw forbidden("Sender is not in the room");
		}
		const pl = getPowerLevels(room);
		const banPl = pl.ban ?? 50;
		const senderPl = getUserPowerLevel(sender, room);
		if (senderPl < banPl) {
			throw forbidden(
				`Insufficient power level to unban: need ${banPl}, have ${senderPl}`,
			);
		}

		const content: JsonObject = { membership: "leave" };
		if (body.reason) content.reason = body.reason;

		const authEvents = selectAuthEvents(
			"m.room.member",
			targetUserId,
			room,
			sender as UserId,
		);
		// Capture the set of remote servers that must be told about the unban
		// BEFORE we mutate room state. The banned target's own server is the most
		// important destination: it currently has the user as `ban`, and unless it
		// observes this `leave` it will keep rejecting any subsequent re-invite as
		// "user is banned" (see TestUnbanViaInvite, where hs1 must see the unban
		// before hs2's re-invite is accepted). `getServersInRoom` ignores banned
		// members, so the target's server would otherwise be missed entirely.
		const unbanDestinations = await collectMembershipDestinations(
			storage,
			serverName,
			roomId as RoomId,
			targetUserId as UserId,
		);

		// Sign the leave (when federation is enabled) so it is acceptable to remote
		// servers — they reject unsigned PDUs. Signing is additive and does not
		// change the event ID, so storage and federation agree on the same ID.
		const { event, eventId } = buildEvent({
			roomId: room.room_id as RoomId,
			sender: sender as UserId,
			type: "m.room.member",
			content,
			stateKey: targetUserId,
			depth: room.depth,
			prevEvents: [...room.forward_extremities],
			authEvents,
			serverName: serverName as ServerName,
			roomVersion: room.room_version,
			signingKey,
		});

		await storage.setStateEvent(room.room_id, event, eventId);
		room.depth = room.depth + 1;
		room.forward_extremities = [eventId];

		// Fan the unban out to the destinations captured above. We deliver to the
		// pre-computed set (including the now-unbanned user's server) rather than
		// relying on the post-mutation `getServersInRoom`, which omits the target.
		if (signingKey && federationClient) {
			await deliverEventToServers(
				serverName,
				federationClient,
				event,
				eventId as EventId,
				unbanDestinations,
			);
		}

		return { status: 200, body: {} };
	};

export const postForget =
	(storage: Storage): Handler =>
	async (req) => {
		const roomId = req.params.roomId as string;
		const userId = req.userId as string;

		const room = await storage.getRoom(roomId);
		if (!room) throw roomNotFound();

		const membership = getMembership(room, userId);
		if (membership !== "leave" && membership !== "ban") {
			throw new MatrixError(
				"M_UNKNOWN",
				"User must have left the room before forgetting it",
				400,
			);
		}

		// There is no dedicated "forgotten" storage flag, so we record the
		// forgotten state as a per-user room account-data entry under the
		// internal type `m.internal.forgotten`. The access-control checks in
		// /messages, /state and the room filter in /sync read this marker to
		// reject/skip forgotten rooms (see FORGOTTEN_ROOM_MARKER consumers).
		await storage.setRoomAccountData(
			userId as UserId,
			roomId as RoomId,
			FORGOTTEN_ROOM_MARKER,
			{ forgotten: true },
		);

		return { status: 200, body: {} };
	};

/**
 * Internal room account-data type used to mark a room as "forgotten" by a
 * particular user. Stored via `setRoomAccountData(userId, roomId, ...)`.
 * Consumers (in room-events.ts and sync.ts) read this marker and treat
 * `content.forgotten === true` as "this user has forgotten this room".
 */
export const FORGOTTEN_ROOM_MARKER = "m.internal.forgotten";

/**
 * Clear the forgotten marker for a user/room. Called when the user re-joins a
 * previously forgotten room so that /messages, /state and /sync stop treating
 * the room as forgotten. (Synapse clears `forgotten` on the membership row when
 * a new membership event is recorded for the user.)
 */
const clearForgottenMarker = async (
	storage: Storage,
	userId: string,
	roomId: string,
): Promise<void> => {
	const existing = await storage.getRoomAccountData(
		userId as UserId,
		roomId as RoomId,
		FORGOTTEN_ROOM_MARKER,
	);
	if (existing && (existing as { forgotten?: unknown }).forgotten === true) {
		await storage.setRoomAccountData(
			userId as UserId,
			roomId as RoomId,
			FORGOTTEN_ROOM_MARKER,
			{ forgotten: false },
		);
	}
};
