import { createHash } from "node:crypto";
import { badJson, forbidden, notJoined, roomNotFound } from "./errors.ts";
import type { FederationClient } from "./federation/client.ts";
import { fanoutEvent } from "./federation/outbound.ts";
import { domainOf } from "./ids.ts";
import type { SigningKey } from "./signing.ts";
import { signEvent } from "./signing.ts";
import type { Storage } from "./storage/interface.ts";
import type {
	ClientEvent,
	PDU,
	StrippedStateEvent,
	UnsignedData,
} from "./types/events.ts";
import type { EventId, RoomId, ServerName, UserId } from "./types/index.ts";
import type { RoomState } from "./types/internal.ts";
import type { JsonObject } from "./types/json.ts";
import type { RoomPowerLevelsContent } from "./types/state-events.ts";

/**
 * MSC4289: power level assigned to room creators. Matches Synapse's
 * `CREATOR_POWER_LEVEL = 2**53`, which is strictly greater than the largest
 * value representable in canonical JSON (`2**53 - 1`). This guarantees creators
 * outrank every settable power level, so non-creators can never kick/ban/demote
 * them, while creators can act on anyone.
 */
export const CREATOR_POWER_LEVEL = 2 ** 53;

/**
 * Largest/smallest integers representable in canonical JSON (Synapse's
 * `CANONICALJSON_MAX_INT`/`CANONICALJSON_MIN_INT`, i.e. `±(2**53 - 1)`).
 * Power-level values outside this range are rejected.
 */
export const CANONICALJSON_MAX_INT = 2 ** 53 - 1;
export const CANONICALJSON_MIN_INT = -(2 ** 53 - 1);

/**
 * Extract the numeric base version from a room-version string.
 *
 * Handles plain numeric versions ("1".."12") and MSC-style unstable versions
 * of the form `org.matrix.mscXXXX.N` (or `<vendor>.N`), where the trailing
 * numeric component after the final "." is the base version (e.g.
 * `org.matrix.msc3757.10` → 10). A bare numeric prefix like "10-dev" also
 * resolves to 10. Returns `undefined` when no numeric version can be derived,
 * in which case callers default to the newest (v11+) redaction behaviour.
 */
const parseRoomVersionNumber = (
	roomVersion: string | undefined,
): number | undefined => {
	if (!roomVersion) return undefined;
	// Plain numeric ("10") or numeric-prefixed ("10-foo").
	const direct = parseInt(roomVersion, 10);
	if (!Number.isNaN(direct)) return direct;
	// MSC-style "org.matrix.mscXXXX.N": take the trailing numeric component.
	const trailing = roomVersion.match(/\.(\d+)$/);
	if (trailing?.[1]) {
		const n = parseInt(trailing[1], 10);
		if (!Number.isNaN(n)) return n;
	}
	return undefined;
};

/** Check whether a room version is v12 or later */
export const isRoomVersion12Plus = (
	roomVersion: string | undefined,
): boolean => {
	const num = parseRoomVersionNumber(roomVersion);
	return num !== undefined && num >= 12;
};

/**
 * Redaction-relevant room-version feature flags, derived from the version
 * string. Mirrors the booleans Synapse hangs off its `RoomVersion` object
 * (`updated_redaction_rules`, `restricted_join_rule_fix`,
 * `msc4291_room_ids_as_hashes`, `implicit_room_creator`).
 *
 * An unknown/undefined version defaults to the newest behaviour (v11+),
 * matching the previous fixed allow-list this module shipped.
 */
interface RedactionFlags {
	/** v11+: MSC2174/MSC2176/MSC3989 updated redaction rules. */
	updatedRedactionRules: boolean;
	/** v8+: restricted join rules keep `allow` in m.room.join_rules. */
	restrictedJoinRule: boolean;
	/** v9+: keep `join_authorised_via_users_server` in m.room.member redaction. */
	restrictedJoinRuleFix: boolean;
	/** v12+: MSC4291 — create event has no `room_id` (derived from its hash). */
	msc4291: boolean;
	/** v11+: room creator implied by `m.room.create.sender` (no `creator`). */
	implicitRoomCreator: boolean;
	/** MSC3389: redaction preserves m.relates_to (rel_type + event_id). */
	msc3389: boolean;
}

const redactionFlagsFor = (roomVersion: string | undefined): RedactionFlags => {
	const num = parseRoomVersionNumber(roomVersion);
	// Unknown version → newest (v11+) behaviour.
	const v = num ?? 11;
	return {
		updatedRedactionRules: v >= 11,
		restrictedJoinRule: v >= 8,
		restrictedJoinRuleFix: v >= 9,
		msc4291: v >= 12,
		implicitRoomCreator: v >= 11,
		msc3389: isMsc3389Enabled(roomVersion),
	};
};

/**
 * MSC3389: redaction preserves the `m.relates_to` relationship (`rel_type` and
 * `event_id`) so a redacted reaction/edit/thread reply still carries its link.
 * Opt-in via the unstable room version `org.matrix.msc3389.<base version>`
 * (the Complement test uses `org.matrix.msc3389.10`).
 */
const isMsc3389Enabled = (roomVersion: string | undefined): boolean =>
	roomVersion?.startsWith("org.matrix.msc3389.") ?? false;

/**
 * MSC3757 (owned state events).
 *
 * Opt-in is gated on the room version. The MSC's unstable room version is
 * `org.matrix.msc3757.<base version>` (the Complement test uses
 * `org.matrix.msc3757.10`). This mirrors Synapse's `msc3757_enabled` flag on
 * its `MSC3757v10` room version. Stable numeric versions (e.g. "10") do NOT
 * opt in, so `TestWithoutOwnedState` still enforces normal power levels and the
 * "cannot set others' state" restriction without the bypass.
 */
const isMsc3757Enabled = (roomVersion: string | undefined): boolean =>
	roomVersion?.startsWith("org.matrix.msc3757.") ?? false;

// Synapse VALID_HOST_REGEX: \A[0-9a-zA-Z-]+(?:\.[0-9a-zA-Z-]+)*\Z
const VALID_HOST_REGEX = /^[0-9a-zA-Z-]+(?:\.[0-9a-zA-Z-]+)*$/;

/**
 * Validate that `s` is a syntactically valid user ID (`@localpart:server`),
 * matching the subset of Synapse's `UserID.is_valid` relevant to MSC3757 owned
 * state-key parsing. Returns false for things like `@oops` (no colon) or a
 * server part with invalid characters (e.g. `hs1@state`).
 */
const isValidUserId = (s: string): boolean => {
	if (s.length < 1 || s[0] !== "@") return false;
	const colon = s.indexOf(":");
	if (colon === -1) return false;
	const domain = s.slice(colon + 1);
	// Strip optional :port (server names may include a port).
	const portIdx = domain.lastIndexOf(":");
	const host = portIdx === -1 ? domain : domain.slice(0, portIdx);
	// IPv6 literals are wrapped in [...]; accept them as-is.
	if (host.length > 0 && host[host.length - 1] === "]") return true;
	return VALID_HOST_REGEX.test(host);
};
/**
 * MSC4289 `check_valid_additional_creators`. The `additional_creators` field of
 * an `m.room.create` event (and the `/upgrade` request) must be an array of
 * syntactically valid user-ID strings, each at most 255 bytes. Mismatches raise
 * `M_BAD_JSON` (HTTP 400), matching Synapse's `AuthError(400, ...)`.
 *
 * Exported so the createRoom / upgrade handlers can reuse the exact same
 * validation before building the create event.
 */
export const validateAdditionalCreators = (value: unknown): void => {
	if (!Array.isArray(value)) {
		throw badJson("additional_creators must be an array");
	}
	for (const entry of value) {
		if (typeof entry !== "string") {
			throw badJson("entry in additional_creators is not a string");
		}
		if (!isValidUserId(entry)) {
			throw badJson("entry in additional_creators is not a valid user ID");
		}
		if (entry.length > 255 || Buffer.byteLength(entry, "utf-8") > 255) {
			throw badJson("entry in additional_creators too long");
		}
	}
};

export const canonicalJson = (val: unknown): string => {
	if (val === null || val === undefined) return "null";
	if (typeof val === "boolean") return val ? "true" : "false";
	if (typeof val === "number") return JSON.stringify(val);
	if (typeof val === "string") return JSON.stringify(val);
	if (Array.isArray(val)) {
		return `[${val.map((v) => canonicalJson(v)).join(",")}]`;
	}
	if (typeof val === "object") {
		const keys = Object.keys(val as Record<string, unknown>).sort();
		const entries = keys.map(
			(k) =>
				`${JSON.stringify(k)}:${canonicalJson((val as Record<string, unknown>)[k])}`,
		);
		return `{${entries.join(",")}}`;
	}
	return JSON.stringify(val);
};
/**
 * Top-level event keys kept by redaction for ALL room versions. Mirrors
 * Synapse's `prune_event_dict` base `allowed_keys` list.
 */
const ALLOWED_TOP_LEVEL_BASE = [
	"event_id",
	"sender",
	"room_id",
	"hashes",
	"signatures",
	"content",
	"type",
	"state_key",
	"depth",
	"prev_events",
	"auth_events",
	"origin_server_ts",
];

/**
 * Additional top-level keys kept by redaction for room versions BEFORE the
 * updated (v11+) redaction rules: `prev_state`, `membership`, `origin`. These
 * are part of the signed/hashed form for v1–v10 events, so omitting them breaks
 * signature verification and event-ID computation for those rooms.
 */
const ALLOWED_TOP_LEVEL_LEGACY = ["prev_state", "membership", "origin"];

/**
 * Redact an event down to its federation-safe form, applying the redaction
 * rules for the given `roomVersion`. Follows Synapse's `prune_event_dict`
 * (synapse/events/utils.py) exactly.
 *
 * When `roomVersion` is undefined the newest (v11+) rules are applied, matching
 * the fixed allow-list this module previously shipped. For v1–v10 rooms the
 * caller MUST pass the room version, because those rooms keep extra top-level
 * keys (`prev_state`, `membership`, `origin`) and use different content rules —
 * without them the redacted form (and therefore the signature and event ID)
 * will not match what remote servers compute.
 */
export const redactEvent = (event: PDU, roomVersion?: string): PDU => {
	const flags = redactionFlagsFor(roomVersion);

	const allowedKeys = [...ALLOWED_TOP_LEVEL_BASE];
	if (!flags.updatedRedactionRules) {
		allowedKeys.push(...ALLOWED_TOP_LEVEL_LEGACY);
	}

	// MSC4291: v12 create events have no room_id of their own, so it is not an
	// allowed redaction key for them (Synapse drops "room_id" from allowed_keys
	// when msc4291_room_ids_as_hashes is set). This keeps both the reference hash
	// (event ID) and the signed form room_id-free. We detect a v12 create event
	// from its own content (`room_version` 12+), independent of `roomVersion`, so
	// that computeEventId without an explicit version still strips it.
	// Only the v12 CREATE event has its room_id stripped (synapse removes
	// "room_id" from allowed_keys only when `event_type == Create`). Stripping it
	// from non-create v12 events would make their redacted/signed form omit
	// room_id, so signatures from other servers (which keep it) fail to verify.
	const stripRoomId =
		(flags.msc4291 && event.type === "m.room.create") ||
		isV12CreateEvent(event);

	const src = event as unknown as Record<string, unknown>;
	const content = (event.content ?? {}) as Record<string, unknown>;

	const newContent: Record<string, unknown> = {};
	const addFields = (...fields: string[]): void => {
		for (const field of fields) {
			if (field in content) newContent[field] = content[field];
		}
	};

	switch (event.type) {
		case "m.room.member": {
			addFields("membership");
			if (flags.restrictedJoinRuleFix) {
				addFields("join_authorised_via_users_server");
			}
			if (flags.updatedRedactionRules) {
				// Preserve only the `signed` subkey under third_party_invite.
				const tpi = content.third_party_invite;
				if (tpi && typeof tpi === "object" && !Array.isArray(tpi)) {
					const signed = (tpi as Record<string, unknown>).signed;
					newContent.third_party_invite =
						signed !== undefined ? { signed } : {};
				}
			}
			break;
		}
		case "m.room.create": {
			if (flags.updatedRedactionRules) {
				// MSC2176: create events keep their full content.
				Object.assign(newContent, content);
			}
			if (!flags.implicitRoomCreator) {
				addFields("creator");
			}
			break;
		}
		case "m.room.join_rules": {
			addFields("join_rule");
			if (flags.restrictedJoinRule) addFields("allow");
			break;
		}
		case "m.room.power_levels": {
			addFields(
				"users",
				"users_default",
				"events",
				"events_default",
				"state_default",
				"ban",
				"kick",
				"redact",
			);
			if (flags.updatedRedactionRules) addFields("invite");
			break;
		}
		case "m.room.history_visibility": {
			addFields("history_visibility");
			break;
		}
		case "m.room.redaction": {
			if (flags.updatedRedactionRules) addFields("redacts");
			break;
		}
	}

	// MSC3389: preserve the m.relates_to relationship through redaction, reduced
	// to rel_type + event_id (any other keys, e.g. a reaction `key`, are dropped).
	// Applies to any event type that carries a relation (reactions, edits, thread
	// replies).
	if (flags.msc3389) {
		const rel = content["m.relates_to"];
		if (rel && typeof rel === "object" && !Array.isArray(rel)) {
			const r = rel as Record<string, unknown>;
			const preserved: Record<string, unknown> = {};
			if (typeof r.rel_type === "string") preserved.rel_type = r.rel_type;
			if (typeof r.event_id === "string") preserved.event_id = r.event_id;
			if (Object.keys(preserved).length > 0) {
				newContent["m.relates_to"] = preserved;
			}
		}
	}

	const redacted: Record<string, unknown> = {};
	for (const key of allowedKeys) {
		if (key === "room_id" && stripRoomId) continue;
		if (key in src) redacted[key] = src[key];
	}
	redacted.content = newContent;

	return redacted as unknown as PDU;
};
/**
 * MSC4291: in room version 12+ the `m.room.create` event has no `room_id` of its
 * own — the room ID *is* the create event's reference hash, so including a
 * `room_id` field while hashing would be circular. Synapse handles this by never
 * putting a `room_id` on v12 create events. We allow the stored PDU to carry a
 * `room_id` (so CS-API responses can expose it), but strip it before computing
 * the content hash / reference hash so the create event's ID matches the room ID.
 *
 * Detection uses the event itself: a `m.room.create` whose `content.room_version`
 * is 12+. This keeps `computeContentHash`/`computeEventId` self-contained.
 */
export const isV12CreateEvent = (event: {
	type: string;
	content: unknown;
}): boolean =>
	event.type === "m.room.create" &&
	isRoomVersion12Plus(
		(event.content as Record<string, unknown> | undefined)?.room_version as
			| string
			| undefined,
	);

/**
 * MSC4291: prepare a stored event for transmission over federation. A v12+
 * `m.room.create` event MUST NOT carry a `room_id` of its own — the room ID *is*
 * its reference hash, and gomatrixserverlib (Complement's federation library)
 * keeps `room_id` during redaction, so a create event federated WITH a `room_id`
 * yields a different reference hash than the room ID, breaking the
 * MSC4291 "room_id == hash(create event)" invariant. We store a `room_id` on the
 * create PDU for CS-API convenience but must drop it on the wire. All other
 * events keep their `room_id` (it is part of their redacted/signed form).
 */
export const stripV12CreateRoomId = (event: PDU): PDU => {
	if (!isV12CreateEvent(event)) return event;
	if (!(event as unknown as Record<string, unknown>).room_id) return event;
	const copy = { ...event } as unknown as Record<string, unknown>;
	delete copy.room_id;
	return copy as unknown as PDU;
};

export const computeContentHash = (event: PDU): string => {
	const copy: Record<string, unknown> = { ...event };
	delete copy.unsigned;
	delete copy.signatures;
	delete copy.hashes;
	delete copy.event_id;
	if (isV12CreateEvent(event)) delete copy.room_id;
	// The content hash (hashes.sha256) is unpadded STANDARD base64 (+/), per the
	// Matrix spec "Adding hashes and signatures to events" — NOT url-safe base64.
	// (The reference hash / event ID below uses url-safe base64.) Using the wrong
	// alphabet here makes every inbound event from another server fail the content
	// hash check.
	return createHash("sha256")
		.update(canonicalJson(copy))
		.digest("base64")
		.replace(/=+$/, "");
};

export const computeEventId = (event: PDU, roomVersion?: string): EventId => {
	const withHash: PDU = {
		...event,
		hashes: { sha256: computeContentHash(event) },
	};

	// The event ID is the reference hash of the redacted event, so it MUST use
	// the room version's redaction rules. For v1–v10 rooms this means keeping
	// `prev_state`/`membership`/`origin` and version-specific content fields, so
	// our IDs match what remote servers compute.
	//
	// redactEvent already drops room_id for v12 create events (MSC4291), so the
	// create event's reference hash — and therefore its ID — equals the room ID.
	const redacted = redactEvent(withHash, roomVersion);
	const forRef: Record<string, unknown> = { ...redacted };
	delete forRef.unsigned;
	delete forRef.signatures;

	const hash = createHash("sha256")
		.update(canonicalJson(forRef))
		.digest("base64url");
	return `$${hash}`;
};
/**
 * Compute a room ID for room version 12+ from the create event.
 * The room ID is the event ID of the create event with `!` sigil instead of `$`.
 */
export const computeRoomIdV12 = (createEvent: PDU): RoomId => {
	const eventId = computeEventId(createEvent, "12");
	return `!${eventId.slice(1)}` as RoomId;
};

export const buildEvent = (params: {
	roomId: RoomId;
	sender: UserId;
	type: string;
	content: JsonObject;
	stateKey?: string;
	depth: number;
	prevEvents: EventId[];
	authEvents: EventId[];
	redacts?: EventId;
	unsigned?: UnsignedData;
	serverName: ServerName;
	signingKey?: SigningKey;
	roomVersion?: string;
	/**
	 * Explicit `origin_server_ts`. Defaults to `Date.now()`. Pass this when the
	 * same logical event must be built more than once and produce an identical
	 * event ID — most importantly for v12 create events, whose reference hash is
	 * the room ID. Building the create event twice with two `Date.now()` calls
	 * (e.g. once to derive the room ID and once to store it) can straddle a
	 * millisecond boundary and yield two different IDs, so the stored create
	 * event's ID would no longer equal the room ID. Supplying a fixed timestamp
	 * removes that nondeterminism.
	 */
	originServerTs?: number;
}): { event: PDU; eventId: EventId } => {
	const event: PDU = {
		auth_events: params.authEvents,
		content: params.content,
		depth: params.depth,
		hashes: { sha256: "" },
		origin_server_ts: params.originServerTs ?? Date.now(),
		prev_events: params.prevEvents,
		room_id: params.roomId,
		sender: params.sender,
		signatures: { [params.serverName]: {} },
		type: params.type,
	};

	if (params.stateKey !== undefined) {
		event.state_key = params.stateKey;
	}
	if (params.redacts) {
		event.redacts = params.redacts;
	}
	if (params.unsigned) {
		event.unsigned = params.unsigned;
	}

	event.hashes = { sha256: computeContentHash(event) };
	const eventId = computeEventId(event, params.roomVersion);

	if (params.signingKey) {
		return {
			event: signEvent(
				event,
				params.serverName,
				params.signingKey,
				params.roomVersion,
			),
			eventId,
		};
	}

	return { event, eventId };
};
const getStateEventId = (
	roomState: RoomState,
	type: string,
	stateKey: string,
): EventId | undefined => {
	const event = roomState.state_events.get(makeStateKey(type, stateKey));
	return event ? computeEventId(event, roomState.room_version) : undefined;
};

export const selectAuthEvents = (
	eventType: string,
	stateKey: string | undefined,
	roomState: RoomState,
	sender: UserId,
	/**
	 * The content of the event being authed. Only needed for restricted-room
	 * joins, where `join_authorised_via_users_server` selects an additional
	 * `m.room.member` auth event (the authorising user). Optional so existing
	 * callers that don't build restricted joins are unaffected.
	 */
	content?: JsonObject,
): EventId[] => {
	const authEvents: EventId[] = [];

	// In v12+, m.room.create is NOT included in auth_events
	if (!isRoomVersion12Plus(roomState.room_version)) {
		const createId = getStateEventId(roomState, "m.room.create", "");
		if (createId) authEvents.push(createId);
	}

	const plId = getStateEventId(roomState, "m.room.power_levels", "");
	if (plId) authEvents.push(plId);

	const senderMemberId = getStateEventId(roomState, "m.room.member", sender);
	if (senderMemberId) authEvents.push(senderMemberId);

	if (eventType === "m.room.member" && stateKey) {
		const joinRulesId = getStateEventId(roomState, "m.room.join_rules", "");
		if (joinRulesId) authEvents.push(joinRulesId);

		if (stateKey !== sender) {
			const targetMemberId = getStateEventId(
				roomState,
				"m.room.member",
				stateKey,
			);
			if (targetMemberId) authEvents.push(targetMemberId);
		}

		// MSC3083 restricted-room joins. When a join event carries
		// `join_authorised_via_users_server`, the m.room.member event of the
		// authorising user is also needed to auth the join (it proves that user
		// is joined and has invite power). Mirrors Synapse's
		// `auth_types_for_event`, which adds (m.room.member, authorising_user)
		// when the room version supports restricted join rules and the event is a
		// join carrying the authorising-user field. We key this off the member
		// content rather than the live join_rules so the auth chain is stable
		// regardless of later join-rule changes.
		if (content?.membership === "join") {
			const authorisingUser = content.join_authorised_via_users_server as
				| string
				| undefined;
			if (authorisingUser && authorisingUser !== stateKey) {
				const authUserMemberId = getStateEventId(
					roomState,
					"m.room.member",
					authorisingUser,
				);
				if (authUserMemberId) authEvents.push(authUserMemberId);
			}
		}
	}

	return authEvents;
};
export const getPowerLevels = (
	roomState: RoomState,
): RoomPowerLevelsContent => {
	const plEvent = roomState.state_events.get("m.room.power_levels\x1f");
	return plEvent
		? (plEvent.content as unknown as RoomPowerLevelsContent)
		: { users_default: 0, events_default: 0, state_default: 50 };
};

/** Check if a user is a room creator (sender of create event or in additional_creators) */
export const isRoomCreator = (
	userId: UserId,
	roomState: RoomState,
): boolean => {
	const createEvent = roomState.state_events.get("m.room.create\x1f");
	if (!createEvent) return false;
	if (createEvent.sender === userId) return true;
	const additionalCreators = (createEvent.content as Record<string, unknown>)
		.additional_creators as string[] | undefined;
	return additionalCreators?.includes(userId) ?? false;
};

export const getUserPowerLevel = (
	userId: UserId,
	roomState: RoomState,
): number => {
	// In room version 12+, room creators have infinite power level (MSC4289).
	if (
		isRoomVersion12Plus(roomState.room_version) &&
		isRoomCreator(userId, roomState)
	) {
		return CREATOR_POWER_LEVEL;
	}

	const plEvent = roomState.state_events.get("m.room.power_levels\x1f");
	if (!plEvent) {
		// Before power_levels is set, the room creator has implicit PL 100
		const createEvent = roomState.state_events.get("m.room.create\x1f");
		if (createEvent && createEvent.sender === userId) return 100;
		return 0;
	}
	const pl = plEvent.content as unknown as RoomPowerLevelsContent;
	return pl.users?.[userId] ?? pl.users_default ?? 0;
};

/**
 * Find the local user best able to authorise a restricted-room join (MSC3083):
 * a currently-joined user on `localServerName` whose power level meets the
 * room's invite threshold. Prefers the highest power level, breaking ties by the
 * lexicographically smallest user ID so the same authoriser is chosen on every
 * invocation regardless of Map iteration order. Returns undefined when no such
 * local user exists (the join must then be performed over federation).
 */
export const findAuthorisingLocalUser = (
	room: RoomState,
	localServerName: string,
): UserId | undefined => {
	const pl = getPowerLevels(room);
	const invitePl = pl.invite ?? 0;

	let best: UserId | undefined;
	let bestPl = -Infinity;

	for (const { userId: memberId, membership } of iterMembers(
		room.state_events,
	)) {
		if (membership !== "join") continue;
		if (domainOf(memberId) !== localServerName) continue;

		const memberPl = getUserPowerLevel(memberId, room);
		if (memberPl < invitePl) continue;

		if (
			memberPl > bestPl ||
			(memberPl === bestPl && (!best || memberId < best))
		) {
			best = memberId;
			bestPl = memberPl;
		}
	}
	return best;
};

const getEventPowerLevel = (
	eventType: string,
	isState: boolean,
	roomState: RoomState,
): number => {
	const pl = getPowerLevels(roomState);
	if (pl.events?.[eventType] !== undefined)
		return pl.events[eventType] as number;
	// In room version 12+, the default power level for m.room.tombstone is 150
	if (
		eventType === "m.room.tombstone" &&
		isRoomVersion12Plus(roomState.room_version)
	) {
		return 150;
	}
	return isState ? (pl.state_default ?? 50) : (pl.events_default ?? 0);
};
/** The `membership` field of an m.room.member event's content (or undefined). */
export const membershipOf = (event: {
	content?: unknown;
}): string | undefined =>
	(event.content as { membership?: string } | undefined)?.membership;

export const getMembership = (
	roomState: RoomState,
	userId: UserId,
): string | undefined => {
	const memberEvent = roomState.state_events.get(`m.room.member\x1f${userId}`);
	return membershipOf(memberEvent ?? {});
};

const checkMembershipAuth = (event: PDU, roomState: RoomState): void => {
	const targetUserId = event.state_key as string;
	const membership = (event.content as Record<string, unknown>)
		.membership as string;
	const senderMembership = getMembership(roomState, event.sender);
	const targetMembership = getMembership(roomState, targetUserId);
	const pl = getPowerLevels(roomState);
	const senderPl = getUserPowerLevel(event.sender, roomState);

	switch (membership) {
		case "join": {
			if (event.sender !== targetUserId) {
				throw forbidden("Cannot force another user to join");
			}
			if (senderMembership === "ban") {
				throw forbidden("User is banned from the room");
			}
			if (senderMembership === "join") return;
			if (senderMembership === "invite") return;

			const createEvent = roomState.state_events.get("m.room.create\x1f");
			if (
				createEvent &&
				createEvent.sender === event.sender &&
				!senderMembership
			) {
				return;
			}

			const joinRule = getJoinRule(roomState);

			if (joinRule === "public") return;

			if (joinRule === "restricted" || joinRule === "knock_restricted") {
				const joinAuth = (event.content as Record<string, unknown>)
					.join_authorised_via_users_server as string | undefined;
				if (joinAuth) {
					// Verify the authorizing user is actually joined to this room
					const authUserMembership = getMembership(roomState, joinAuth);
					if (authUserMembership !== "join") {
						throw forbidden("Authorizing user is not a member of the room");
					}
					return;
				}
				// Also allow if the user was previously knocked (accepted knock)
				if (senderMembership === "knock") return;
			}

			throw forbidden("Room is invite-only");
		}

		case "invite": {
			if (senderMembership !== "join") {
				throw forbidden("Sender is not in the room");
			}
			if (targetMembership === "join") {
				throw forbidden("Cannot invite user who is already in the room");
			}
			if (targetMembership === "ban") {
				throw forbidden("Cannot invite banned user");
			}
			if (event.sender === targetUserId) {
				throw forbidden("Cannot invite yourself");
			}
			const invitePl = pl.invite ?? 0;
			if (senderPl < invitePl) {
				throw forbidden(
					`Insufficient power level to invite: need ${invitePl}, have ${senderPl}`,
				);
			}
			return;
		}

		case "leave": {
			// Self-leave: a user can always leave a room they are joined to or
			// invited to (or have knocked on — accepting cancellation of a knock).
			if (event.sender === targetUserId) {
				if (
					senderMembership === "join" ||
					senderMembership === "invite" ||
					senderMembership === "knock"
				)
					return;
				throw forbidden("Cannot leave a room you are not in");
			}
			// Changing another user's membership to leave is either a kick (target
			// currently join/invite) or an unban (target currently banned). In both
			// cases the sender must themselves be joined.
			//
			// This mirrors synapse's _is_membership_change_allowed
			// (event_auth.py, `Membership.LEAVE` branch):
			//   - if the target is banned and the sender's power level is below the
			//     room ban level, reject (cannot unban);
			//   - otherwise, if sender != target (a kick), require the sender to have
			//     the kick power level AND a strictly higher power level than the
			//     target.
			// Notably, an unban (target_banned) is NOT subject to the kick-level /
			// higher-than-target checks — having the ban power level is sufficient.
			if (senderMembership !== "join") {
				throw forbidden("Sender is not in the room");
			}
			const targetPl = getUserPowerLevel(targetUserId, roomState);
			if (targetMembership === "ban") {
				// Unban: sender needs the ban power level.
				const banPl = pl.ban ?? 50;
				if (senderPl < banPl) {
					throw forbidden(`You cannot unban user ${targetUserId}.`);
				}
				return;
			}
			// Kick: authorized purely by power level — the spec's m.room.member
			// `leave` rule (and synapse's _is_membership_change_allowed) does NOT
			// require the target to currently be join/invite/knock. Kicking an
			// already-departed (or, under partial state, not-yet-known) target is
			// allowed as long as the PL checks below pass; it is simply idempotent
			// state-wise. This matters for partial-state joins, where a kick whose
			// auth_events legitimately omit the target's membership must pass the
			// claimed-auth check and only be rejected later if the SENDER turns out
			// to have already left (caught by the state-before / resync re-auth).
			const kickPl = pl.kick ?? 50;
			if (senderPl < kickPl || senderPl <= targetPl) {
				throw forbidden(`You cannot kick user ${targetUserId}.`);
			}
			return;
		}

		case "ban": {
			if (senderMembership !== "join") {
				throw forbidden("Sender is not in the room");
			}
			const banPl = pl.ban ?? 50;
			if (senderPl < banPl) {
				throw forbidden(
					`Insufficient power level to ban: need ${banPl}, have ${senderPl}`,
				);
			}
			if (targetUserId !== event.sender) {
				const targetPl = getUserPowerLevel(targetUserId, roomState);
				if (senderPl <= targetPl) {
					throw forbidden("Cannot ban user with equal or higher power level");
				}
			}
			return;
		}

		case "knock": {
			if (event.sender !== targetUserId) {
				throw forbidden("Cannot knock on behalf of another user");
			}
			if (senderMembership === "ban") {
				throw forbidden("User is banned from the room");
			}
			if (senderMembership === "join") {
				throw forbidden("User is already in the room");
			}
			// A re-knock (knock -> knock) is permitted by the spec.
			if (senderMembership === "invite") {
				throw forbidden("User is already invited");
			}

			const knockJoinRule = getJoinRule(roomState);

			if (knockJoinRule !== "knock" && knockJoinRule !== "knock_restricted") {
				throw forbidden("Room join rules do not allow knocking");
			}
			return;
		}

		default:
			throw forbidden(`Unknown membership: ${membership}`);
	}
};

/**
 * Validate a single power-level value: in room version 10+ it must be an
 * integer, and (matching Synapse's event validator / `CANONICALJSON_MAX_INT`)
 * it must fall within the range representable in canonical JSON, i.e.
 * `±(2**53 - 1)`. A value such as `2**53` is rejected. The error is `M_BAD_JSON`
 * so the CS API returns HTTP 400.
 */
const validatePowerLevelValue = (label: string, val: unknown): void => {
	if (typeof val !== "number") return;
	if (!Number.isInteger(val)) {
		throw badJson(
			`Power level value for ${label} must be an integer in room version 10+`,
		);
	}
	if (val > CANONICALJSON_MAX_INT || val < CANONICALJSON_MIN_INT) {
		throw badJson(
			`Power level value for ${label} is out of range for canonical JSON`,
		);
	}
};

const validateIntegerPowerLevels = (event: PDU): void => {
	const content = event.content as Record<string, unknown>;
	const intFields = [
		"ban",
		"events_default",
		"invite",
		"kick",
		"redact",
		"state_default",
		"users_default",
	];
	for (const field of intFields) {
		if (field in content) {
			validatePowerLevelValue(`'${field}'`, content[field]);
		}
	}
	for (const mapField of ["events", "users", "notifications"] as const) {
		const map = content[mapField] as Record<string, unknown> | undefined;
		if (map && typeof map === "object") {
			for (const [key, val] of Object.entries(map)) {
				validatePowerLevelValue(`${mapField} entry '${key}'`, val);
			}
		}
	}
};

export const checkEventAuth = (
	event: PDU,
	_eventId: EventId,
	roomState: RoomState,
): void => {
	const isV12Plus = isRoomVersion12Plus(roomState.room_version);

	if (event.type === "m.room.create") {
		if (roomState.state_events.size > 0) {
			// A second m.room.create can never be sent into an existing room
			// (MSC4291 / event auth rule 1). Clients receive HTTP 400.
			throw badJson("m.room.create can only be the first event in a room");
		}
		// In v12, the create event must NOT have a room_id in the event body
		// (it's derived from the hash). However, we still store room_id on the PDU
		// for internal use — this check validates that auth_events is empty for create.
		if (isV12Plus && event.auth_events.length > 0) {
			throw forbidden(
				"m.room.create must not have auth_events in room version 12+",
			);
		}
		// Validate additional_creators (MSC4289 check_valid_additional_creators).
		if (isV12Plus) {
			const additionalCreators = (event.content as Record<string, unknown>)
				.additional_creators;
			if (additionalCreators !== undefined) {
				validateAdditionalCreators(additionalCreators);
			}
		}
		return;
	}

	// In v12, m.room.create must NOT be in auth_events
	if (isV12Plus) {
		const createEvent = roomState.state_events.get("m.room.create\x1f");
		if (createEvent) {
			const createEventId = computeEventId(createEvent, roomState.room_version);
			if (event.auth_events.includes(createEventId)) {
				throw forbidden(
					"m.room.create must not be referenced in auth_events in room version 12+",
				);
			}
		}
	}

	if (event.type === "m.room.member") {
		checkMembershipAuth(event, roomState);
		return;
	}

	const senderMembership = getMembership(roomState, event.sender);
	if (senderMembership !== "join") {
		throw forbidden("Sender is not in the room");
	}

	// Room version 10+ requires integer power levels
	if (event.type === "m.room.power_levels") {
		const roomVersion = roomState.room_version ?? "1";
		const versionNum = parseInt(roomVersion, 10);
		if (!Number.isNaN(versionNum) && versionNum >= 10) {
			validateIntegerPowerLevels(event);
		}
		// MSC4289: in v12+ the room creator(s) hold an implicit infinite power
		// level and must NOT be listed in the power_levels `users` map. Synapse
		// rejects this with SynapseError(400, ...), so we use badJson (HTTP 400).
		if (isV12Plus) {
			const users = (event.content as Record<string, unknown>).users as
				| Record<string, number>
				| undefined;
			if (users) {
				const createEvent = roomState.state_events.get("m.room.create\x1f");
				if (createEvent) {
					const creator = createEvent.sender;
					const additionalCreators = (
						createEvent.content as Record<string, unknown>
					).additional_creators as string[] | undefined;
					if (creator in users) {
						throw badJson(
							`Creator user ${creator} must not appear in content.users`,
						);
					}
					if (additionalCreators) {
						for (const uid of additionalCreators) {
							if (uid in users) {
								throw badJson(
									"Additional creators users must not appear in content.users",
								);
							}
						}
					}
				}
			}
		}
	}

	const isState = event.state_key !== undefined;
	const requiredPl = getEventPowerLevel(event.type, isState, roomState);
	const senderPl = getUserPowerLevel(event.sender, roomState);
	if (senderPl < requiredPl) {
		throw forbidden(
			`Insufficient power level: need ${requiredPl}, have ${senderPl}`,
		);
	}

	// MSC3757 owned state events.
	//
	// A state event whose state_key starts with "@" and is NOT exactly the
	// sender's own user ID is normally only writable by anyone (subject to the
	// power-level check above). Both with and without MSC3757, a state_key that
	// looks like *another* user's ID is write-protected here; MSC3757 only
	// changes *who* may write it.
	//
	// Mirrors Synapse `_can_send_event` (event_auth.py): the owner of a state
	// key (whose state_key equals their user ID, or starts with their user ID
	// followed by "_") may set it, and so may anyone with strictly higher power
	// level than that owner. Without MSC3757 enabled, no one may set state keyed
	// by another user ID (normal power levels still apply, so this is a stricter
	// gate, never a looser one).
	const stateKey = event.state_key;
	if (stateKey?.startsWith("@") && stateKey !== event.sender) {
		if (isMsc3757Enabled(roomState.room_version)) {
			// Parse the owning user ID out of the state key: it is the state key
			// up to (but excluding) the first "_" that appears after the domain's
			// leading colon, or the whole state key if there is no such "_".
			const colonIdx = stateKey.indexOf(":", 1);
			if (colonIdx === -1) {
				throw badJson(
					"State key neither equals a valid user ID, nor starts with one plus an underscore",
				);
			}
			const suffixIdx = stateKey.indexOf("_", colonIdx + 1);
			const stateKeyUserId =
				suffixIdx === -1 ? stateKey : stateKey.slice(0, suffixIdx);
			if (!isValidUserId(stateKeyUserId)) {
				throw badJson(
					"State key neither equals a valid user ID, nor starts with one plus an underscore",
				);
			}
			// Allowed if the sender owns the state key, or has strictly higher
			// power level than the owner.
			if (
				stateKeyUserId === event.sender ||
				senderPl > getUserPowerLevel(stateKeyUserId as UserId, roomState)
			) {
				return;
			}
		}
		throw forbidden("You are not allowed to set others' state");
	}
};
export const pduToClientEvent = (pdu: PDU, eventId: EventId): ClientEvent => {
	const ce: ClientEvent = {
		content: pdu.content,
		event_id: eventId,
		origin_server_ts: pdu.origin_server_ts,
		room_id: pdu.room_id,
		sender: pdu.sender,
		type: pdu.type,
	};
	if (pdu.state_key !== undefined) ce.state_key = pdu.state_key;
	if (pdu.unsigned) ce.unsigned = pdu.unsigned;
	if (pdu.redacts) ce.redacts = pdu.redacts;
	return ce;
};

export const requireJoinedRoom = async (
	storage: Storage,
	roomId: string,
	userId: string,
): Promise<RoomState> => {
	const room = await storage.getRoom(roomId);
	if (!room) throw roomNotFound();
	if (getMembership(room, userId) !== "join") throw notJoined();
	return room;
};

export const isWorldReadable = (roomState: RoomState): boolean => {
	const hvEvent = roomState.state_events.get("m.room.history_visibility\x1f");
	if (!hvEvent) return false;
	return (
		(hvEvent.content as Record<string, unknown>).history_visibility ===
		"world_readable"
	);
};

export const requireJoinedOrWorldReadable = async (
	storage: Storage,
	roomId: string,
	userId: string | undefined,
): Promise<RoomState> => {
	const room = await storage.getRoom(roomId);
	if (!room) throw roomNotFound();
	if (userId) {
		const membership = getMembership(room, userId);
		if (membership === "join") return room;
		if (membership === "leave") {
			const hvEvent = room.state_events.get("m.room.history_visibility\x1f");
			const hv = hvEvent
				? (hvEvent.content as Record<string, unknown>).history_visibility
				: undefined;
			if (hv === "shared" || hv === "world_readable") return room;
		}
	}
	if (isWorldReadable(room)) return room;
	throw notJoined();
};

/** Read a single field from an event's content, tolerating a missing event. */
export const contentField = (event: PDU | undefined, field: string): unknown =>
	event ? (event.content as Record<string, unknown>)[field] : undefined;

export const countJoinedMembers = (
	stateEvents: Map<string, { content: unknown }>,
): number =>
	[...stateEvents.entries()].filter(
		([key, event]) =>
			key.startsWith("m.room.member\x1f") &&
			(event.content as Record<string, unknown>).membership === "join",
	).length;

export const getStateContent = (
	stateEvents: Map<string, { content: unknown }>,
	key: string,
	field: string,
): string | undefined => {
	const event = stateEvents.get(key);
	return event
		? ((event.content as Record<string, unknown>)[field] as string | undefined)
		: undefined;
};

export interface RoomSummaryFields {
	name?: string;
	topic?: string;
	avatar_url?: string;
	canonical_alias?: string;
	num_joined_members: number;
	world_readable: boolean;
	guest_can_join: boolean;
	join_rule?: string;
	room_type?: string;
}

/** The common room-summary projection shared by the space-hierarchy endpoints. */
export const roomSummaryFields = (room: RoomState): RoomSummaryFields => {
	const get = (type: string, field: string): string | undefined =>
		contentField(room.state_events.get(makeStateKey(type)), field) as
			| string
			| undefined;
	return {
		name: get("m.room.name", "name"),
		topic: get("m.room.topic", "topic"),
		avatar_url: get("m.room.avatar", "url"),
		canonical_alias: get("m.room.canonical_alias", "alias"),
		num_joined_members: countJoinedMembers(room.state_events),
		world_readable:
			get("m.room.history_visibility", "history_visibility") ===
			"world_readable",
		guest_can_join: get("m.room.guest_access", "guest_access") === "can_join",
		join_rule: get("m.room.join_rules", "join_rule"),
		room_type: get("m.room.create", "type"),
	};
};

/**
 * Separator for packing several identifiers into one composite string key
 * (state-event map keys, txn-idempotency keys, the various in-memory index
 * maps). The ASCII Unit Separator (U+001F) is a single byte, never appears in
 * Matrix identifiers (all printable ASCII), is compact, and — unlike the NUL
 * byte this replaced — is accepted by PostgreSQL/MySQL text columns and query
 * parameters. Keep pack and unpack symmetric: always split on this exact value.
 */
export const KEY_SEP = "\x1f";

export const makeStateKey = (type: string, stateKey = ""): string =>
	`${type}${KEY_SEP}${stateKey}`;

const MEMBER_KEY_PREFIX = `m.room.member${KEY_SEP}`;

/** Iterate the m.room.member entries of a room's state. */
export function* iterMembers(
	state: Map<string, PDU>,
): Generator<{ userId: UserId; membership: string | undefined; event: PDU }> {
	for (const [key, event] of state) {
		if (!key.startsWith(MEMBER_KEY_PREFIX)) continue;
		yield {
			userId: key.slice(MEMBER_KEY_PREFIX.length) as UserId,
			membership: membershipOf(event),
			event,
		};
	}
}

/** Whether `server` has at least one member of the given membership in `state`. */
export const serverHasMember = (
	state: Map<string, PDU>,
	server: string,
	membership: string,
): boolean => {
	for (const m of iterMembers(state)) {
		if (m.membership === membership && domainOf(m.userId) === server) {
			return true;
		}
	}
	return false;
};

/** A room's join rule, defaulting to "invite" when no join_rules event exists. */
export const getJoinRule = (room: RoomState): string => {
	const event = room.state_events.get(makeStateKey("m.room.join_rules"));
	return event
		? (((event.content as Record<string, unknown>).join_rule as string) ??
				"invite")
		: "invite";
};

/** Project an event down to the stripped-state shape used in invites/summaries. */
export const toStripped = (
	event: { content: unknown; sender: string; state_key?: string; type: string },
	fallbackStateKey = "",
): StrippedStateEvent => ({
	content: event.content as StrippedStateEvent["content"],
	sender: event.sender as StrippedStateEvent["sender"],
	state_key: event.state_key ?? fallbackStateKey,
	type: event.type,
});

/**
 * Whether `userId` satisfies a restricted room's allow conditions (MSC3083):
 * joined to one of the rooms listed under m.room.join_rules content.allow with
 * type "m.room_membership". When `requireServerInAllowRoom` is set, an allow room
 * only counts if that server currently has a joined member there — the rule a
 * server applies before vouching for a remote join (so it can fail over when its
 * view of the allow room is stale).
 */
export const userSatisfiesRestrictedAllow = async (
	storage: Storage,
	room: RoomState,
	userId: UserId,
	requireServerInAllowRoom?: string,
): Promise<boolean> => {
	const joinRulesEvent = room.state_events.get(
		makeStateKey("m.room.join_rules"),
	);
	if (!joinRulesEvent) return false;
	const allow = (joinRulesEvent.content as Record<string, unknown>).allow;
	if (!Array.isArray(allow)) return false;

	for (const entry of allow) {
		if (!entry || typeof entry !== "object") continue;
		const e = entry as Record<string, unknown>;
		if (e.type !== "m.room_membership") continue;
		const allowedRoomId = e.room_id;
		if (typeof allowedRoomId !== "string") continue;

		const allowedRoom = await storage.getRoom(allowedRoomId as RoomId);
		if (!allowedRoom) continue;
		if (
			requireServerInAllowRoom &&
			!serverHasMember(
				allowedRoom.state_events,
				requireServerInAllowRoom,
				"join",
			)
		) {
			continue;
		}
		if (getMembership(allowedRoom, userId) === "join") return true;
	}
	return false;
};

export interface EventContext {
	roomState: RoomState;
	depth: number;
	prevEvents: string[];
}

export const sendStateEvent = async (
	storage: Storage,
	serverName: string,
	ctx: EventContext,
	sender: string,
	type: string,
	stateKey: string,
	content: JsonObject,
	signingKey?: SigningKey,
	federationClient?: FederationClient,
	/**
	 * Explicit `origin_server_ts` for the built event. Forwarded to
	 * `buildEvent`. Pass this for v12 create events so the stored create event's
	 * ID matches the room ID that was derived from a separately-built create
	 * event (see the note on `buildEvent`'s `originServerTs`).
	 */
	originServerTs?: number,
): Promise<string> => {
	const authEvents = selectAuthEvents(
		type,
		stateKey,
		ctx.roomState,
		sender,
		content,
	);
	// Synapse `deduplicate_state_event`: sending a state event whose (type,
	// state_key) already holds an identical content from the same sender is a
	// no-op — return the existing event's ID rather than creating a new event.
	// This makes e.g. re-joining an already-joined room idempotent (the same
	// m.room.member event ID is returned), which clients/tests rely on.
	const existingState = ctx.roomState.state_events.get(
		makeStateKey(type, stateKey),
	);
	if (
		existingState &&
		existingState.sender === sender &&
		canonicalJson(existingState.content) === canonicalJson(content)
	) {
		return computeEventId(existingState, ctx.roomState.room_version);
	}

	// When a signing key is supplied the event is signed by our server. Signing
	// is additive: it injects `signatures` (and recomputes `hashes`) but does NOT
	// change the event ID, which is derived from the redacted form (signatures and
	// unsigned are stripped before hashing). This keeps event IDs stable whether
	// or not federation is active.
	const { event, eventId } = buildEvent({
		roomId: ctx.roomState.room_id,
		sender,
		type,
		content,
		stateKey,
		depth: ctx.depth,
		prevEvents: ctx.prevEvents,
		authEvents,
		serverName,
		signingKey,
		roomVersion: ctx.roomState.room_version,
		originServerTs,
	});

	checkEventAuth(event, eventId, ctx.roomState);
	await storage.setStateEvent(ctx.roomState.room_id, event, eventId);

	ctx.depth++;
	ctx.prevEvents = [eventId];
	ctx.roomState.depth = ctx.depth;
	ctx.roomState.forward_extremities = [eventId];

	// Fan the (signed) event out to remote servers in the room. Best-effort and
	// fire-and-forget; only happens when both a signing key and federation client
	// are available (i.e. federation is enabled and the event is signed).
	if (signingKey && federationClient) {
		await fanoutEvent(
			storage,
			serverName,
			signingKey,
			federationClient,
			ctx.roomState.room_id as RoomId,
			event,
			eventId,
		);
	}

	return eventId;
};
