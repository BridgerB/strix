import { notFound } from "../errors.ts";
import {
	countJoinedMembers,
	getMembership,
	getStateContent,
} from "../events.ts";
import type { Handler } from "../router.ts";
import type { Storage } from "../storage/interface.ts";
import type { RoomAlias, RoomId } from "../types/index.ts";
import { getAllowedRoomIds } from "./federation/spaces.ts";

export const getRoomSummary =
	(storage: Storage): Handler =>
	async (req) => {
		const roomIdOrAlias = req.params.roomIdOrAlias as string;

		let roomId: RoomId;
		if (roomIdOrAlias.startsWith("#")) {
			const result = await storage.getRoomByAlias(roomIdOrAlias as RoomAlias);
			if (!result) throw notFound("Room alias not found");
			roomId = result.room_id;
		} else {
			roomId = roomIdOrAlias as RoomId;
		}

		const room = await storage.getRoom(roomId);
		if (!room) throw notFound("Room not found");

		const numJoined = countJoinedMembers(room.state_events);

		const name = getStateContent(room.state_events, "m.room.name\x1f", "name");
		const topic = getStateContent(
			room.state_events,
			"m.room.topic\x1f",
			"topic",
		);
		const avatarUrl = getStateContent(
			room.state_events,
			"m.room.avatar\x1f",
			"url",
		);
		const joinRule = getStateContent(
			room.state_events,
			"m.room.join_rules\x1f",
			"join_rule",
		);
		const historyVisibility = getStateContent(
			room.state_events,
			"m.room.history_visibility\x1f",
			"history_visibility",
		);
		const guestAccess = getStateContent(
			room.state_events,
			"m.room.guest_access\x1f",
			"guest_access",
		);
		const roomType = getStateContent(
			room.state_events,
			"m.room.create\x1f",
			"type",
		);

		const userId = req.userId as string;
		const membership = getMembership(room, userId);

		const body: Record<string, unknown> = {
			room_id: roomId,
			num_joined_members: numJoined,
			world_readable: historyVisibility === "world_readable",
			guest_can_join: guestAccess === "can_join",
		};

		if (name) body.name = name;
		if (topic) body.topic = topic;
		if (avatarUrl) body.avatar_url = avatarUrl;
		if (joinRule) body.join_rule = joinRule;
		if (roomType) body.room_type = roomType;
		if (membership) body.membership = membership;

		// Restricted (and knock_restricted) rooms advertise the rooms whose
		// membership grants access (MSC3266 / room_summary_test.go).
		const allowedRoomIds = getAllowedRoomIds(room);
		if (allowedRoomIds.length > 0) body.allowed_room_ids = allowedRoomIds;

		return { status: 200, body };
	};
