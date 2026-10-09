import type { PresenceState } from "./ephemeral.ts";
import type {
	ClientEvent,
	StrippedStateEvent,
	ToDeviceEvent,
} from "./events.ts";
import type { EventId, RoomId, UserId } from "./identifiers.ts";

export interface SyncRequest {
	filter?: string | import("./filters.ts").SyncFilter;
	since?: string;
	full_state?: boolean;
	set_presence?: PresenceState;
	timeout?: number;
}

export interface SyncResponse {
	next_batch: string;
	account_data?: { events: ClientEvent[] };
	presence?: { events: ClientEvent[] };
	rooms?: SyncRooms;
	to_device?: { events: ToDeviceEvent[] };
	device_lists?: DeviceLists;
	device_one_time_keys_count?: Record<string, number>;
	device_unused_fallback_key_types?: string[];
	// MSC4429: per-user profile field updates for users sharing a room with the
	// syncer. `profile_updates` is null when the user left the last shared room.
	"org.matrix.msc4429.users"?: Record<
		string,
		{ profile_updates: Record<string, unknown> | null }
	>;
}

export interface SyncRooms {
	join?: Record<RoomId, JoinedRoom>;
	invite?: Record<RoomId, InvitedRoom>;
	leave?: Record<RoomId, LeftRoom>;
	knock?: Record<RoomId, KnockedRoom>;
}

export interface JoinedRoom {
	summary?: RoomSummary;
	state?: { events: ClientEvent[] };
	timeline?: Timeline;
	ephemeral?: { events: ClientEvent[] };
	account_data?: { events: ClientEvent[] };
	unread_notifications?: UnreadNotificationCounts;
	unread_thread_notifications?: Record<EventId, UnreadNotificationCounts>;
}

export interface InvitedRoom {
	invite_state: { events: StrippedStateEvent[] };
}

export interface LeftRoom {
	state?: { events: ClientEvent[] };
	timeline?: Timeline;
	account_data?: { events: ClientEvent[] };
}

export interface KnockedRoom {
	knock_state: { events: StrippedStateEvent[] };
}

export interface RoomSummary {
	"m.heroes"?: UserId[];
	"m.joined_member_count"?: number;
	"m.invited_member_count"?: number;
}

export interface Timeline {
	events: ClientEvent[];
	limited?: boolean;
	prev_batch?: string;
}

export interface UnreadNotificationCounts {
	highlight_count?: number;
	notification_count?: number;
}

export interface DeviceLists {
	changed?: UserId[];
	left?: UserId[];
}
