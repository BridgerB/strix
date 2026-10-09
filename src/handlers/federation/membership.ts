import {
	forbidden,
	MatrixError,
	missingParam,
	notFound,
	unableToAuthoriseJoin,
} from "../../errors.ts";
import {
	checkEventAuth,
	computeEventId,
	findAuthorisingLocalUser,
	getJoinRule,
	getMembership,
	isRoomVersion12Plus,
	selectAuthEvents,
	stripV12CreateRoomId,
	userSatisfiesRestrictedAllow,
} from "../../events.ts";
import { fullInviteState } from "../../storage/ephemeral.ts";
import { isServerAllowedByAcl } from "../../federation/acl.ts";
import type { FederationClient } from "../../federation/client.ts";
import { fanoutEvent } from "../../federation/outbound.ts";
import { verifyOriginSignature } from "../../federation/verify.ts";
import { domainOf } from "../../ids.ts";
import { getInviteRuleForTarget } from "../../invite-filter.ts";
import type { Handler } from "../../router.ts";
import type { SigningKey } from "../../signing.ts";
import { signEvent } from "../../signing.ts";
import type { Storage } from "../../storage/interface.ts";
import type { PDU, StrippedStateEvent } from "../../types/events.ts";
import type { EventId, RoomId, ServerName, UserId } from "../../types/index.ts";
import type { RoomState } from "../../types/internal.ts";
import type { RoomVersion } from "../../types/room-versions.ts";

/**
 * Strict structural validation shared by send_join / send_leave / send_knock,
 * mirroring synapse's `_on_send_membership_event` and dendrite's
 * federationapi/routing/{join,leave}.go. The body must be a complete
 * m.room.member *state* event whose:
 *   - room_id matches the room_id in the request path,
 *   - type is m.room.member with a state_key present,
 *   - content.membership equals the membership expected by the endpoint,
 *   - state_key matches the sender (a membership event only ever affects its
 *     own sender's membership).
 *
 * Any failure raises a 400 M_BAD_JSON. This is what the Complement tests
 * TestCannotSendNon{Join,Leave,Knock}Via* assert: regular events, non-state
 * membership events, wrong membership types and mismatched state keys must all
 * be rejected with 400 before any auth/storage work happens.
 */
const validateMembershipEvent = (
	event: PDU,
	roomId: RoomId,
	expectedMembership: string,
): void => {
	if (!event || typeof event !== "object") {
		throw new MatrixError("M_BAD_JSON", "Missing membership event", 400);
	}
	if (event.room_id && event.room_id !== roomId) {
		throw new MatrixError(
			"M_BAD_JSON",
			"Room ID in body does not match that in request path",
			400,
		);
	}
	if (event.type !== "m.room.member" || typeof event.state_key !== "string") {
		throw new MatrixError("M_BAD_JSON", "Not an m.room.member event", 400);
	}
	if (
		(event.content as Record<string, unknown>)?.membership !==
		expectedMembership
	) {
		throw new MatrixError(
			"M_BAD_JSON",
			`Not a ${expectedMembership} event`,
			400,
		);
	}
	// A membership event must target its own sender (state_key === sender).
	// dendrite: "Event state key must match the event sender." This is what
	// rejects the "mismatched state key" Complement case.
	if (event.state_key !== event.sender) {
		throw new MatrixError(
			"M_BAD_JSON",
			"Event state key must match the event sender",
			400,
		);
	}
};

/**
 * Coerce an arbitrary value (from request body or event unsigned) into an array
 * of well-formed stripped state events. Anything malformed is dropped so a bad
 * `invite_room_state` can never crash the handler.
 */
const toStrippedState = (value: unknown): StrippedStateEvent[] => {
	if (!Array.isArray(value)) return [];
	const out: StrippedStateEvent[] = [];
	for (const entry of value) {
		if (!entry || typeof entry !== "object") continue;
		const e = entry as Record<string, unknown>;
		if (typeof e.type !== "string") continue;
		if (typeof e.sender !== "string") continue;
		if (typeof e.state_key !== "string") continue;
		if (!e.content || typeof e.content !== "object") continue;
		out.push({
			content: e.content as StrippedStateEvent["content"],
			sender: e.sender as StrippedStateEvent["sender"],
			state_key: e.state_key,
			type: e.type,
		});
	}
	return out;
};

export const getMakeJoin =
	(storage: Storage, serverName: string): Handler =>
	async (req) => {
		const roomId = req.params.roomId as RoomId;
		const userId = req.params.userId as UserId;

		// MSC3706: while we are only partially joined we do not hold the full state
		// and cannot authorise another server's membership change — reject with 404
		// (synapse federation_server._on_send_membership_event).
		if (await storage.getRoomPartialState(roomId))
			throw notFound(
				"Unable to handle this request right now; this server is not fully joined.",
			);

		const room = await storage.getRoom(roomId);
		if (!room) throw notFound("Room not found");

		const createContent = room.state_events.get("m.room.create\x1f")?.content as
			| Record<string, unknown>
			| undefined;
		if (createContent?.federate === false)
			throw forbidden("Room does not federate");

		if (!isServerAllowedByAcl(req.origin as ServerName, room))
			throw forbidden("Server is denied by ACL");

		const joinRule = getJoinRule(room);

		const currentMembership = getMembership(room, userId);
		if (currentMembership === "ban") throw forbidden("User is banned");

		const content: Record<string, unknown> = { membership: "join" };

		const isRestricted =
			joinRule === "restricted" || joinRule === "knock_restricted";

		if (joinRule !== "public" && currentMembership !== "invite") {
			// A rejoin (already joined) is always allowed for any join rule.
			if (currentMembership !== "join") {
				if (isRestricted) {
					// The user must be a member of one of the allowed rooms.
					const satisfies = await userSatisfiesRestrictedAllow(
						storage,
						room,
						userId,
						serverName,
					);
					if (!satisfies) {
						throw unableToAuthoriseJoin(
							"User is not a member of any room in the allow list",
						);
					}
					// We must vouch for the join via a local user who can invite.
					// If we have no such local user, fail so the requesting server
					// can fail over to another resident server.
					const authoriser = findAuthorisingLocalUser(room, serverName);
					if (!authoriser) {
						throw unableToAuthoriseJoin(
							"No local user able to authorise this join",
						);
					}
					content.join_authorised_via_users_server = authoriser;
				} else {
					throw unableToAuthoriseJoin(
						"Room is not public and user is not invited",
					);
				}
			}
		}

		const authEvents = selectAuthEvents("m.room.member", userId, room, userId);

		// For a restricted join authorised via a local user, the join event's
		// auth_events MUST also reference that authorising user's m.room.member
		// event (synapse auth_types_for_event: restricted_join_rule + JOIN +
		// AUTHORISING_USER adds `(m.room.member, authorising_user)`). Without it,
		// a resident server receiving this join over federation (e.g. hs2 in
		// TestRestrictedRoomsRemoteJoinFailOver) cannot prove the authorising user
		// is joined and therefore rejects the join, so other members never observe
		// the new join. selectAuthEvents only adds the *sender's* membership, so
		// append the authoriser's membership here.
		const authoriserUserId = content.join_authorised_via_users_server as
			| UserId
			| undefined;
		if (authoriserUserId) {
			const authoriserMember = room.state_events.get(
				`m.room.member\x1f${authoriserUserId}`,
			);
			if (authoriserMember) {
				const authoriserMemberId = computeEventId(
					authoriserMember,
					room.room_version,
				);
				if (!authEvents.includes(authoriserMemberId)) {
					authEvents.push(authoriserMemberId);
				}
			}
		}

		const template: Partial<PDU> = {
			auth_events: authEvents,
			content: content as PDU["content"],
			depth: room.depth,
			origin_server_ts: Date.now(),
			prev_events: [...room.forward_extremities],
			room_id: roomId,
			sender: userId,
			state_key: userId,
			type: "m.room.member",
		};

		return {
			status: 200,
			body: {
				room_version: room.room_version,
				event: template,
			},
		};
	};
/**
 * Compute the subset of room state to return for an MSC3706 partial-state
 * send_join. Mirrors synapse's `_get_event_ids_for_partial_state_join`:
 *
 *   1. Every NON-member state event.
 *   2. The joining user's own current membership event, if any (it is an auth
 *      event for the new join, so it's cheap to include).
 *   3. If the room has no name and no canonical alias (i.e. a DM-style room that
 *      a client would render from its heroes), also include the membership
 *      events of the room "heroes" so the joining server can display the room.
 *      Heroes are joined members first, then invited members, excluding the
 *      joining user, capped at 5 (per the Room Summary rules used by /sync).
 */
const buildPartialStateEvents = (
	room: RoomState,
	joiningUser: UserId,
): PDU[] => {
	const memberPrefix = "m.room.member\x1f";
	const result: PDU[] = [];

	// 1. All non-member state events.
	for (const [key, ev] of room.state_events) {
		if (!key.startsWith(memberPrefix)) result.push(ev);
	}

	const memberFor = (userId: string): PDU | undefined =>
		room.state_events.get(memberPrefix + userId);
	const added = new Set<string>();
	const pushMember = (userId: string): void => {
		if (added.has(userId)) return;
		const ev = memberFor(userId);
		if (ev) {
			result.push(ev);
			added.add(userId);
		}
	};

	// 2. The joining user's current membership (e.g. an outstanding invite).
	pushMember(joiningUser);

	// 3. Heroes, only when the room has no name / canonical alias.
	const hasName = room.state_events.has("m.room.name\x1f");
	const hasCanonicalAlias = room.state_events.has("m.room.canonical_alias\x1f");
	if (!hasName && !hasCanonicalAlias) {
		const joined: { userId: string; ts: number }[] = [];
		const invited: { userId: string; ts: number }[] = [];
		for (const [key, ev] of room.state_events) {
			if (!key.startsWith(memberPrefix)) continue;
			const userId = key.slice(memberPrefix.length);
			if (userId === joiningUser) continue;
			const membership = (ev.content as Record<string, unknown>).membership;
			const ts = ev.origin_server_ts ?? 0;
			if (membership === "join") joined.push({ userId, ts });
			else if (membership === "invite") invited.push({ userId, ts });
		}
		// Approximate synapse's stream-ordering by origin_server_ts, then mxid.
		const byOrder = (
			a: { userId: string; ts: number },
			b: { userId: string; ts: number },
		): number => a.ts - b.ts || a.userId.localeCompare(b.userId);
		joined.sort(byOrder);
		invited.sort(byOrder);
		const heroes = [...joined, ...invited].slice(0, 5);
		for (const h of heroes) pushMember(h.userId);
	}

	return result;
};
export const putSendJoin =
	(
		storage: Storage,
		serverName: string,
		signingKey: SigningKey,
		federationClient: FederationClient,
	): Handler =>
	async (req) => {
		const roomId = req.params.roomId as RoomId;
		const event = req.body as PDU;
		const origin = req.origin as string;

		// MSC3706: reject another server's join while we are only partially joined.
		if (await storage.getRoomPartialState(roomId))
			throw notFound(
				"Unable to handle this request right now; this server is not fully joined.",
			);

		// Strict structural validation before touching storage/auth: must be a
		// join m.room.member state event whose room_id matches the path and whose
		// state_key matches its sender. (TestCannotSendNonJoinViaSendJoinV1/V2.)
		validateMembershipEvent(event, roomId, "join");

		const room = await storage.getRoom(roomId);
		if (!room) throw notFound("Room not found");

		// The join event must carry the room_id so it can be stored and so that
		// auth/state computations work consistently. v12 templates already include
		// room_id (we put it there in make_join); but be defensive for any client.
		if (!event.room_id) {
			(event as unknown as Record<string, unknown>).room_id = roomId;
		}

		try {
			await verifyOriginSignature(
				event,
				origin,
				storage,
				federationClient,
				room.room_version,
			);
		} catch (err) {
			if (err instanceof MatrixError) throw err;
			throw forbidden(
				`Could not verify join event signature: ${(err as Error).message}`,
			);
		}

		let eventId: EventId;
		try {
			eventId = computeEventId(event, room.room_version);
		} catch (err) {
			throw new MatrixError(
				"M_BAD_JSON",
				`Could not compute event ID: ${(err as Error).message}`,
				400,
			);
		}

		// Auth check. For restricted joins, checkMembershipAuth verifies the
		// join_authorised_via_users_server user is a joined member here.
		checkEventAuth(event, eventId, room);

		let coSigned: PDU;
		try {
			coSigned = signEvent(
				event,
				serverName as ServerName,
				signingKey,
				room.room_version,
			);
		} catch (err) {
			throw new MatrixError(
				"M_UNKNOWN",
				`Could not sign join event: ${(err as Error).message}`,
				500,
			);
		}

		// MSC3706 / partial-state send_join: detect the magic query param BEFORE we
		// persist the join, because the partial-state response is computed from the
		// state of the room *before* this join is added (synapse's `prev_state_ids`).
		// In particular, the joining user's OWN new membership must NOT appear in the
		// returned `state` unless they already had a prior membership (e.g. an
		// outstanding invite). Compute the partial state set now, while
		// room.state_events still reflects the pre-join state.
		const omitMembers =
			req.path.includes("/_matrix/federation/v2/send_join/") &&
			req.query.get("omit_members") === "true";
		const partialStateEvents = omitMembers
			? buildPartialStateEvents(room, event.state_key as UserId)
			: undefined;

		await storage.setStateEvent(roomId, coSigned, eventId);
		room.depth = Math.max(room.depth, event.depth + 1);
		room.forward_extremities = [eventId];

		// A remote user (re)joining means we may have missed their device-list
		// updates while we were not tracking them (no shared room). Evict any
		// cached keys so the next /keys/query re-fetches fresh ones rather than
		// serving a stale cache (TestDeviceListUpdates when_remote_user_rejoins).
		const joiner = event.state_key as UserId;
		if (domainOf(joiner) !== serverName) {
			await storage.deleteDeviceKeys(joiner);
		}

		// Ensure every NON-create state event we return carries room_id (so the
		// receiver can store it). For a v12+ m.room.create event we do the OPPOSITE:
		// strip any room_id, because MSC4291 makes the room ID the create event's
		// reference hash and gomatrixserverlib keeps room_id when redacting — a
		// create event federated WITH room_id would hash to a different ID than the
		// room ID (see stripV12CreateRoomId).
		const withRoomId = (se: PDU): PDU => {
			const stripped = stripV12CreateRoomId(se);
			if (stripped !== se) return stripped; // was a v12 create event
			return se.room_id ? se : ({ ...se, room_id: roomId } as PDU);
		};

		// MSC3706 / partial-state send_join: if the joining server set the
		// `omit_members=true` query param (only honoured on the v2 endpoint, which
		// is where the gomatrixserverlib SendJoinPartialState client sends it), we
		// return a PARTIAL response: `members_omitted: true`, the non-member state
		// events (plus a small set of hero members so DM rooms render), the servers
		// currently in the room, and the auth_chain. The joining server then
		// back-fills the omitted member events lazily. Mirrors synapse
		// federation_server.on_send_join / _get_event_ids_for_partial_state_join.
		// The partial state set was computed above from the PRE-join state, so the
		// joiner's own new membership is correctly excluded.
		let stateEvents: PDU[];
		if (partialStateEvents) {
			stateEvents = partialStateEvents.map(withRoomId);
		} else {
			stateEvents = [...room.state_events.values()].map(withRoomId);
		}

		const authEventIds = stateEvents.flatMap((se) => se.auth_events);

		let authChain: PDU[];
		try {
			authChain = await storage.getAuthChain(authEventIds);
		} catch {
			authChain = [];
		}
		authChain = authChain.map((ae) => {
			const stripped = stripV12CreateRoomId(ae);
			if (stripped !== ae) return stripped; // v12 create: must not carry room_id
			return ae.room_id ? ae : ({ ...ae, room_id: roomId } as PDU);
		});

		// For a partial-state (members_omitted) response, every event needed to
		// authorise the join is already returned under `state` (the heroes design),
		// so the auth_chain must not duplicate them — synapse returns an empty
		// auth_chain here (TestSendJoinPartialStateResponse). Exclude any auth event
		// whose (type, state_key) is already present in the returned state set.
		if (partialStateEvents) {
			const stateKeys = new Set(
				stateEvents.map((se) => `${se.type}${se.state_key ?? ""}`),
			);
			authChain = authChain.filter(
				(ae) => !stateKeys.has(`${ae.type}${ae.state_key ?? ""}`),
			);
		}

		let servers: ServerName[];
		try {
			servers = await storage.getServersInRoom(roomId);
		} catch {
			servers = [serverName as ServerName];
		}
		// `servers_in_room` lists the OTHER servers already resident in the room so
		// the joining server can fetch the omitted state from them. It must not
		// include the joining server itself (its join was just stored above, so
		// getServersInRoom now sees it) — TestSendJoinPartialStateResponse expects
		// only the resident server(s).
		const joiningServer = domainOf(event.state_key as string);
		servers = servers.filter((s) => s !== joiningServer);

		// Distribute the new join to the OTHER servers participating in the room.
		// Synapse's federation_server.on_send_join persists the join via the normal
		// event-persistence path, which drives the federation sender to relay the
		// new membership to every other resident server. Without this, a third
		// homeserver already in the room never observes the joiner.
		//
		// This is exactly what TestRestrictedRoomsRemoteJoinFailOver relies on:
		// charlie (hs3) joins the restricted room via send_join to hs1, and bob
		// (hs2) — already resident — must then see charlie's join over federation
		// (`bob.MustSyncUntil(SyncJoinedTo(charlie))`). We fan out the fully
		// co-signed join event; fanoutEvent excludes our own server AND the joining
		// origin server, which already holds the event (it just sent it to us) and
		// would otherwise receive its own user's join back as an unexpected PDU.
		await fanoutEvent(
			storage,
			serverName,
			signingKey,
			federationClient,
			roomId,
			coSigned,
			eventId,
			[origin as ServerName],
		);

		const responseBody = {
			origin: serverName,
			auth_chain: authChain,
			state: stateEvents,
			event: coSigned,
			servers_in_room: servers,
			members_omitted: omitMembers,
		};

		// The v1 send_join endpoint wraps the response in a [200, {...}] array
		// envelope, whereas v2 returns the bare object. Detect which variant was
		// invoked from the request path.
		if (req.path.includes("/_matrix/federation/v1/send_join/")) {
			return { status: 200, body: [200, responseBody] };
		}

		return { status: 200, body: responseBody };
	};
export const getMakeLeave =
	(storage: Storage, _serverName: string): Handler =>
	async (req) => {
		const roomId = req.params.roomId as RoomId;
		const userId = req.params.userId as UserId;

		const room = await storage.getRoom(roomId);
		if (!room) throw notFound("Room not found");

		const currentMembership = getMembership(room, userId);
		if (currentMembership !== "join" && currentMembership !== "invite") {
			throw forbidden("User is not in the room");
		}

		const authEvents = selectAuthEvents("m.room.member", userId, room, userId);

		const template: Partial<PDU> = {
			auth_events: authEvents,
			content: { membership: "leave" },
			depth: room.depth,
			origin_server_ts: Date.now(),
			prev_events: [...room.forward_extremities],
			room_id: roomId,
			sender: userId,
			state_key: userId,
			type: "m.room.member",
		};

		return {
			status: 200,
			body: {
				room_version: room.room_version,
				event: template,
			},
		};
	};
export const putSendLeave =
	(
		storage: Storage,
		serverName: string,
		signingKey: SigningKey,
		federationClient: FederationClient,
	): Handler =>
	async (req) => {
		const roomId = req.params.roomId as RoomId;
		const event = req.body as PDU;
		const origin = req.origin as string;

		// Strict structural validation: must be a leave m.room.member state event
		// whose room_id matches the path and whose state_key matches its sender.
		// (TestCannotSendNonLeaveViaSendLeaveV1/V2.)
		validateMembershipEvent(event, roomId, "leave");

		const room = await storage.getRoom(roomId);
		if (!room) throw notFound("Room not found");

		if (!event.room_id) {
			(event as unknown as Record<string, unknown>).room_id = roomId;
		}

		await verifyOriginSignature(
			event,
			origin,
			storage,
			federationClient,
			room.room_version,
		);

		const eventId = computeEventId(event, room.room_version);
		checkEventAuth(event, eventId, room);

		// A leave can arrive in two shapes:
		//   (a) a previously *joined* member leaving — this is a genuine event in
		//       our DAG (its prev_events descend from events we hold), so it should
		//       advance depth/forward_extremities like any other event; or
		//   (b) an *out-of-band* membership: a user who was only invited or knocked
		//       rejecting/rescinding that invite/knock. Its depth and prev_events
		//       are expressed in the leaving server's view, not ours. Storing it as
		//       the room's forward extremity would corrupt our DAG — exactly the
		//       hazard putFederationInvite documents for remote invites — because a
		//       subsequent locally-created event would chain off a foreign event
		//       whose ancestry we may not hold. Synapse persists case (b) as an
		//       out-of-band membership (outlier) that updates only the membership
		//       state, never the forward extremities.
		//
		// Decide based on the leaving user's CURRENT membership before we overwrite
		// it: only a prior "join" is a real DAG leave.
		const priorMembership = getMembership(room, event.sender);
		const isDagLeave = priorMembership === "join";

		// Persist the leave BEFORE we read the resident-server set for fanout. A
		// rejected invite removes the leaving server from the room, but other
		// resident servers (e.g. a third homeserver that is still joined) must
		// still be told about the leave. Synapse persists the send_leave event via
		// the normal event-persistence path (`_on_send_membership_event`), which in
		// turn drives the federation sender to distribute the event to every other
		// server in the room. We mirror that here: store the event, then fan it out
		// to the remaining resident servers. Without this, the inviting server
		// silently swallows invite rejections and other participants never observe
		// the leave (TestFederationRejectInvite).
		await storage.setStateEvent(roomId, event, eventId);
		if (isDagLeave) {
			room.depth = Math.max(room.depth, event.depth + 1);
			room.forward_extremities = [eventId];
		}

		// Distribute the leave to the other servers participating in the room. The
		// event is already signed by the leaving server, so it can be relayed
		// as-is. fanoutEvent excludes our own server and only targets joined
		// servers, so the (now-departed) origin server is not echoed back.
		await fanoutEvent(
			storage,
			serverName,
			signingKey,
			federationClient,
			roomId,
			event,
			eventId,
		);

		// v1 send_leave wraps the (empty) response in a [200, {}] array envelope;
		// v2 returns the bare object.
		if (req.path.includes("/_matrix/federation/v1/send_leave/")) {
			return { status: 200, body: [200, {}] };
		}

		return { status: 200, body: {} };
	};
export const putFederationInvite =
	(
		storage: Storage,
		serverName: string,
		signingKey: SigningKey,
		federationClient: FederationClient,
	): Handler =>
	async (req) => {
		const body = req.body as {
			room_version?: string;
			event?: PDU;
			invite_room_state?: unknown[];
		};

		const event = body.event;
		const origin = req.origin as string;

		// Structural validation, mirroring synapse on_invite_request /
		// FederationHandler.on_invite_request: the body must carry an
		// m.room.member invite event with a state key for a local user, sent by
		// the requesting (origin) server.
		if (!event || typeof event !== "object") {
			throw new MatrixError("M_BAD_JSON", "Missing invite event", 400);
		}
		if (typeof event.state_key !== "string") {
			throw new MatrixError(
				"M_BAD_JSON",
				"The invite event did not have a state key",
				400,
			);
		}
		if (event.type !== "m.room.member") {
			throw new MatrixError(
				"M_BAD_JSON",
				"The event was not an m.room.member invite event",
				400,
			);
		}
		if ((event.content as Record<string, unknown>)?.membership !== "invite") {
			throw new MatrixError(
				"M_BAD_JSON",
				"The event was not an m.room.member invite event",
				400,
			);
		}

		// The invite must name the room it applies to. Without a room_id we
		// cannot persist the membership or seed a room from the stripped state, and
		// storage.getRoom(undefined) would silently fall through to the seed branch
		// and create a malformed room keyed on `undefined`. Synapse's
		// on_invite_request reads event.room_id authoritatively; reject up front if
		// it's missing or not a string.
		if (typeof event.room_id !== "string") {
			throw new MatrixError(
				"M_BAD_JSON",
				"The invite event did not have a room_id",
				400,
			);
		}

		const targetServer = domainOf(event.state_key);
		if (targetServer !== serverName)
			throw forbidden("Invited user is not on this server");

		// MSC4155 invite filtering: the invited user (event.state_key) is local to
		// this server, so honour the invite permission config they published in
		// their global account data against the inviting user (event.sender).
		//   - "block": reject the invite (403) so the inviting server's invite fails.
		//   - "ignore": acknowledge the invite (200, co-signed) so the remote side
		//     succeeds, but do NOT persist it locally, so it never reaches the
		//     invitee's /sync.
		//   - "allow" (default / no config): proceed normally.
		const inviteRule = await getInviteRuleForTarget(
			storage,
			event.state_key as UserId,
			event.sender as string,
		);
		if (inviteRule === "block") {
			throw forbidden("You are not permitted to invite this user.");
		}

		// Determine the room version for version-aware redaction/signing. We may
		// not be resident in this room yet, so prefer the room's stored version,
		// then the body's `room_version`, defaulting to "10" (the seed default used
		// below when importing a minimal room from the stripped state).
		const existingRoom = await storage.getRoom(event.room_id);
		const inviteRoomVersion =
			existingRoom?.room_version ?? body.room_version ?? "10";

		await verifyOriginSignature(
			event,
			origin,
			storage,
			federationClient,
			inviteRoomVersion,
		);

		// Co-sign the invite so the inviting server (and the invitee's client)
		// have our signature vouching that the invite was received here.
		const coSigned = signEvent(
			event,
			serverName as ServerName,
			signingKey,
			inviteRoomVersion,
		);
		const eventId = computeEventId(coSigned, inviteRoomVersion);

		// MSC4155 "ignore": acknowledge the invite to the sending server (return the
		// co-signed event with 200) but do not persist it locally, so it never
		// appears in the invitee's /sync.
		if (inviteRule === "ignore") {
			return { status: 200, body: { event: coSigned } };
		}

		// The inviting server provides stripped room state so the invitee can see
		// room metadata (name, join_rules, ...) before joining. It may be sent
		// either as a top-level `invite_room_state` field or inside the event's
		// `unsigned.invite_room_state` (synapse uses the latter). Stash it on the
		// stored event's unsigned and seed the room's state from it so /sync's
		// invite_state and GET .../state both reflect it.
		const unsigned = (coSigned.unsigned ?? {}) as Record<string, unknown>;
		const strippedState = toStrippedState(
			body.invite_room_state ?? unsigned.invite_room_state,
		);

		// MSC4311: for v12+ rooms the invite_room_state MUST include the
		// m.room.create event; reject the invite with 400 M_MISSING_PARAM
		// otherwise (TestMSC4311RejectInvalidStrippedStateFederation).
		if (
			isRoomVersion12Plus(inviteRoomVersion) &&
			!strippedState.some((e) => e.type === "m.room.create")
		) {
			throw missingParam(
				"invite_room_state is missing the m.room.create event",
			);
		}

		unsigned.invite_room_state = strippedState;
		coSigned.unsigned = unsigned as PDU["unsigned"];

		const room = existingRoom;
		if (!room) {
			// We are not resident in this room. Seed a minimal room from the
			// stripped state (create/join_rules/name/...) plus the invite member
			// event, so getStrippedState() returns full invite metadata and the
			// invitee's membership resolves to "invite".
			const seedState: PDU[] = [];
			for (const s of strippedState) {
				// Skip a stray member event for the invitee — the authoritative,
				// co-signed invite member event is appended last below.
				if (s.type === "m.room.member" && s.state_key === event.state_key)
					continue;
				seedState.push({
					auth_events: [],
					content: s.content,
					depth: 0,
					hashes: { sha256: "" },
					origin_server_ts: event.origin_server_ts,
					prev_events: [],
					room_id: event.room_id,
					sender: s.sender as PDU["sender"],
					signatures: {},
					state_key: s.state_key,
					type: s.type,
				} as PDU);
			}
			seedState.push(coSigned);

			await storage.importRoomState(
				event.room_id,
				(body.room_version ?? "10") as RoomVersion,
				seedState,
				[],
			);
		} else {
			// We are already resident in this room. The invite is an *out-of-band*
			// membership originating from the inviting server's DAG: its depth and
			// prev_events are expressed in that server's view, not ours. Storing it
			// as the room's forward extremity (as a normal locally-created event)
			// would corrupt our DAG — any subsequent local event (e.g. the invitee
			// later joining via this resident server) would chain off a foreign
			// event whose ancestors we may not hold, producing an event other
			// servers reject. Synapse persists a remote invite as an out-of-band
			// membership (handlers/federation.py on_invite_request →
			// persist_events with `outliers`) that updates only the membership
			// state, never the room's forward extremities. We mirror that: write
			// the membership state event so /sync and GET .../state reflect the
			// invite, but leave depth/forward_extremities untouched so the local
			// DAG stays consistent.
			await storage.setStateEvent(event.room_id, coSigned, eventId);
		}

		return {
			status: 200,
			body: { event: coSigned },
		};
	};
export const getMakeKnock =
	(storage: Storage, _serverName: string): Handler =>
	async (req) => {
		const roomId = req.params.roomId as RoomId;
		const userId = req.params.userId as UserId;

		// MSC3706: reject knocks while we are only partially joined.
		if (await storage.getRoomPartialState(roomId))
			throw notFound(
				"Unable to handle this request right now; this server is not fully joined.",
			);

		// The knocking user must belong to the requesting (verified) origin server
		// (synapse on_make_knock_request).
		const userServer = domainOf(userId);
		if (userServer !== req.origin)
			throw forbidden("User does not belong to the requesting server");

		const room = await storage.getRoom(roomId);
		if (!room) throw notFound("Room not found");

		const createContent = room.state_events.get("m.room.create\x1f")?.content as
			| Record<string, unknown>
			| undefined;
		if (createContent?.federate === false)
			throw forbidden("Room does not federate");

		if (!isServerAllowedByAcl(req.origin as ServerName, room))
			throw forbidden("Server is denied by ACL");

		const joinRule = getJoinRule(room);

		const currentMembership = getMembership(room, userId);
		if (currentMembership === "ban") throw forbidden("User is banned");
		if (currentMembership === "join")
			throw forbidden("User is already in the room");
		if (currentMembership === "invite")
			throw forbidden("User is already invited to the room");

		if (joinRule !== "knock" && joinRule !== "knock_restricted")
			throw forbidden("Room does not support knocking");

		const authEvents = selectAuthEvents("m.room.member", userId, room, userId);

		const template: Partial<PDU> = {
			auth_events: authEvents,
			content: { membership: "knock" },
			depth: room.depth,
			origin_server_ts: Date.now(),
			prev_events: [...room.forward_extremities],
			room_id: roomId,
			sender: userId,
			state_key: userId,
			type: "m.room.member",
		};

		return {
			status: 200,
			body: {
				room_version: room.room_version,
				event: template,
			},
		};
	};
export const postExchangeThirdPartyInvite = (): Handler => (_req) => ({
	status: 200,
	body: {},
});

export const postThreePidOnBind = (): Handler => (_req) => ({
	status: 200,
	body: {},
});

export const putSendKnock =
	(
		storage: Storage,
		serverName: string,
		signingKey: SigningKey,
		federationClient: FederationClient,
	): Handler =>
	async (req) => {
		const roomId = req.params.roomId as RoomId;
		const event = req.body as PDU;
		const origin = req.origin as string;

		// MSC3706: reject another server's knock while we are only partially joined.
		if (await storage.getRoomPartialState(roomId))
			throw notFound(
				"Unable to handle this request right now; this server is not fully joined.",
			);

		// Strict structural validation, mirroring synapse _on_send_membership_event:
		// the body must be a knock m.room.member *state* event whose room_id
		// matches the request path, whose membership is "knock" and whose
		// state_key matches its sender. This runs before the join_rule/ACL checks
		// so wrong-type or wrong-membership events are rejected with 400 even in
		// rooms that don't support knocking. (TestCannotSendNonKnockViaSendKnock,
		// TestCannotSendKnockViaSendKnockInMSC3787Room.)
		validateMembershipEvent(event, roomId, "knock");

		const room = await storage.getRoom(roomId);
		if (!room) throw notFound("Room not found");

		if (!event.room_id) {
			(event as unknown as Record<string, unknown>).room_id = roomId;
		}

		// The knocking room version must actually support knocking.
		const joinRule = getJoinRule(room);
		if (joinRule !== "knock" && joinRule !== "knock_restricted") {
			throw forbidden("Room does not support knocking");
		}

		if (!isServerAllowedByAcl(origin as ServerName, room))
			throw forbidden("Server is denied by ACL");

		await verifyOriginSignature(
			event,
			origin,
			storage,
			federationClient,
			room.room_version,
		);

		const eventId = computeEventId(event, room.room_version);
		checkEventAuth(event, eventId, room);

		await storage.setStateEvent(roomId, event, eventId);
		room.depth = Math.max(room.depth, event.depth + 1);
		room.forward_extremities = [eventId];

		// Distribute the knock membership event to the other servers
		// participating in the room. Synapse's federation_server.on_send_knock_request
		// persists the knock via the normal event-persistence path, which drives the
		// federation sender to relay the new event to every other resident server
		// (handlers/federation.py / FederationSender). We mirror that: store the
		// event, then fan it out to the remaining joined servers so their members
		// observe the knock (the "Users in the room see a user's membership update
		// when they knock" assertion in TestKnocking).
		//
		// The knock event is already signed by the knocking server, so it is relayed
		// as-is. fanoutEvent targets only servers with a *joined* member and excludes
		// our own server, so the knocking server (whose member is only "knock", not
		// "join") is never echoed the event back to itself.
		// Relay the knock to the room's other resident servers, but NOT back to the
		// knocking server itself — it already has the event and need not (and per
		// the engineered test server, must not) receive an echo (TestMSC4311
		// knock_room_state).
		await fanoutEvent(
			storage,
			serverName,
			signingKey,
			federationClient,
			roomId,
			event,
			eventId,
			[origin as ServerName],
		);

		// Reply with room state so the knocking server's clients can display room
		// metadata while the knock is pending (synapse on_send_knock_request).
		// MSC4311: knock_room_state carries FULL events (incl. m.room.create), not
		// the minimal stripped form.
		const knockRoomState = fullInviteState(room);

		return {
			status: 200,
			body: { knock_room_state: knockRoomState },
		};
	};
