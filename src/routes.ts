import { parseRegistrations } from "./appservice/registration.ts";
import { createFederationClient } from "./federation/client.ts";
import { flushAllPendingEdus } from "./federation/outbound.ts";
import {
	getWhoAmI,
	postChangePassword,
	postDeactivate,
} from "./handlers/account.ts";
import {
	deleteGlobalAccountData,
	deleteRoomAccountData,
	deleteTag,
	getGlobalAccountData,
	getRoomAccountData,
	getTags,
	putGlobalAccountData,
	putRoomAccountData,
	putTag,
} from "./handlers/account-data.ts";
import {
	getAdminLock,
	getAdminSuspend,
	putAdminLock,
	putAdminSuspend,
} from "./handlers/admin.ts";
import {
	postAppservicePing,
	putAppserviceDirectoryListRoom,
} from "./handlers/appservice.ts";
import {
	postDeviceSigningUpload,
	postSignaturesUpload,
} from "./handlers/cross-signing.ts";
import {
	getDelayedEvents,
	postDelayedEventAction,
	putDelayedEvent,
	putDelayedStateEvent,
} from "./handlers/delayed-events.ts";
import {
	deleteDevice,
	deleteDevices,
	getDevice,
	getDevices,
	putDevice,
} from "./handlers/devices.ts";
import {
	deleteDirectoryRoom,
	getDirectoryListRoom,
	getDirectoryRoom,
	getPublicRooms,
	getRoomAliases,
	postPublicRooms,
	putDirectoryListRoom,
	putDirectoryRoom,
} from "./handlers/directory.ts";
import {
	getAuthMetadata,
	getCapabilities,
	versionsHandler,
	wellKnownClientHandler,
	wellKnownPolicyServerHandler,
	wellKnownServerHandler,
	wellKnownSupportHandler,
} from "./handlers/discovery.ts";
import {
	getKeysChanges,
	postKeysClaim,
	postKeysQuery,
	postKeysUpload,
	putSendToDevice,
} from "./handlers/e2ee.ts";
import {
	postFederationKeysClaim,
	postFederationKeysQuery,
	postFederationUserDevices,
} from "./handlers/federation/devices.ts";
import {
	getFederationEvent,
	getFederationEventAuth,
	getFederationRoomState,
	getFederationRoomStateIds,
	getFederationTimestampToEvent,
	postFederationBackfill,
	postFederationMissingEvents,
} from "./handlers/federation/events.ts";
import { getKeyQuery, postKeyQuery } from "./handlers/federation/key-notary.ts";
import { getServerKeys } from "./handlers/federation/keys.ts";
import {
	getFederationMediaDownload,
	getFederationMediaThumbnail,
} from "./handlers/federation/media.ts";
import {
	getMakeJoin,
	getMakeKnock,
	getMakeLeave,
	postExchangeThirdPartyInvite,
	postThreePidOnBind,
	putFederationInvite,
	putSendJoin,
	putSendKnock,
	putSendLeave,
} from "./handlers/federation/membership.ts";
import {
	getFederationOpenIdUserinfo,
	getFederationPublicRooms,
	getFederationVersion,
	getQueryDirectory,
	getQueryGeneric,
	getQueryProfile,
	postFederationPublicRooms,
} from "./handlers/federation/query.ts";
import { postFederationHierarchy } from "./handlers/federation/spaces.ts";
import { putFederationSend } from "./handlers/federation/transactions.ts";
import { getFilterById, postCreateFilter } from "./handlers/filters.ts";
import {
	deleteKeyBackupAll,
	deleteKeyBackupRoom,
	deleteKeyBackupSession,
	deleteKeyBackupVersion,
	getKeyBackupAll,
	getKeyBackupRoom,
	getKeyBackupSession,
	getKeyBackupVersion,
	postKeyBackupVersion,
	putKeyBackupAll,
	putKeyBackupRoom,
	putKeyBackupSession,
	putKeyBackupVersion,
} from "./handlers/key-backup.ts";
import { getLoginFlows, postLogin } from "./handlers/login.ts";
import { postLogout, postLogoutAll } from "./handlers/logout.ts";
import {
	getConfig,
	getDownload,
	getThumbnail,
	postCreateMedia,
	postUpload,
	putAsyncUpload,
} from "./handlers/media.ts";
import { getNotifications } from "./handlers/notifications.ts";
import { postOpenIdToken } from "./handlers/openid.ts";
import { getPresence, putPresence } from "./handlers/presence.ts";
import {
	getAvatarUrl,
	getDisplayName,
	getProfile,
	deleteProfileField,
	getProfileField,
	putAvatarUrl,
	putDisplayName,
	putProfileField,
} from "./handlers/profile.ts";
import {
	deletePushRule,
	getAllPushRules,
	getGlobalPushRules,
	getPushRule,
	getPushRuleActions,
	getPushRuleEnabled,
	getPushRulesByKind,
	putPushRule,
	putPushRuleActions,
	putPushRuleEnabled,
} from "./handlers/push-rules.ts";
import { getPushers, postPushersSet } from "./handlers/pushers.ts";
import { postReadMarkers } from "./handlers/read-markers.ts";
import { postReceipt } from "./handlers/receipts.ts";
import { postRefresh } from "./handlers/refresh.ts";
import { postRegister } from "./handlers/register.ts";
import {
	getRelations,
	postEventRelationships,
	postFederationEventRelationships,
} from "./handlers/relations.ts";
import {
	postReportEvent,
	postReportRoom,
	postReportUser,
} from "./handlers/report.ts";
import {
	getAllState,
	getContext,
	getEvent,
	getJoinedMembers,
	getMembers,
	getMessages,
	getStateEvent,
	getTimestampToEvent,
	postRedact,
	putSendEvent,
	putStateEvent,
} from "./handlers/room-events.ts";
import { getRoomInitialSync } from "./handlers/room-initial-sync.ts";
import { getRoomSummary } from "./handlers/room-summary.ts";
import { postRoomUpgrade } from "./handlers/room-upgrade.ts";
import {
	getJoinedRooms,
	postBan,
	postCreateRoom,
	postForget,
	postInvite,
	postJoin,
	postKick,
	postKnock,
	postLeave,
	postUnban,
	resumePartialStateResyncs,
} from "./handlers/rooms.ts";
import { postSearch } from "./handlers/search.ts";
import { slidingSync } from "./handlers/sliding-sync.ts";
import { getSpaceHierarchy } from "./handlers/spaces.ts";
import {
	getSsoCallback,
	getSsoConfig,
	getSsoFallback,
	getSsoRedirect,
} from "./handlers/sso.ts";
import { getSync } from "./handlers/sync.ts";
import {
	getProtocol,
	getProtocols,
	getThirdpartyLocation,
	getThirdpartyLocationByProtocol,
	getThirdpartyUser,
	getThirdpartyUserByProtocol,
} from "./handlers/thirdparty.ts";
import {
	deleteThreadSubscription,
	getThreadSubscription,
	putThreadSubscription,
} from "./handlers/thread-subscriptions.ts";
import { getThreads } from "./handlers/threads.ts";
import {
	getThreePids,
	postAddThreePid,
	postDeleteThreePid,
} from "./handlers/threepid.ts";
import {
	getAdminWhois,
	getRegisterAvailable,
	getRegistrationTokenValidity,
	postAccount3pidEmailRequestToken,
	postAccount3pidMsisdnRequestToken,
	postLoginGetToken,
	postPasswordEmailRequestToken,
	postPasswordMsisdnRequestToken,
	postRegisterEmailRequestToken,
	postRegisterMsisdnRequestToken,
	postThreePidBind,
	postThreePidUnbind,
} from "./handlers/threepid-verify.ts";
import { putTyping } from "./handlers/typing.ts";
import { getUrlPreview } from "./handlers/url-preview.ts";
import { postUserDirectorySearch } from "./handlers/user-directory.ts";
import { getTurnServer } from "./handlers/voip.ts";
import { requireAppserviceAuth } from "./middleware/appservice-auth.ts";
import { requireAuth } from "./middleware/auth.ts";
import { requireFederationAuth } from "./middleware/federation-auth.ts";
import { rateLimit } from "./middleware/rate-limit.ts";
import type { Handler, Router } from "./router.ts";
import type { SigningKey } from "./signing.ts";
import type { Storage } from "./storage/interface.ts";
import type { ServerName } from "./types/index.ts";

export const registerRoutes = (
	router: Router,
	storage: Storage,
	serverName: string,
	signingKey?: SigningKey,
): void => {
	const registrations = parseRegistrations();
	const auth = requireAuth(storage, registrations, serverName);
	const asAuth = requireAppserviceAuth(registrations, serverName);
	const loginRL = rateLimit("login");
	const registerRL = rateLimit("register");
	const defaultRL = rateLimit("default");

	// Create federation client early so client-server handlers can use it for federation joins
	const federationClient = signingKey
		? createFederationClient(serverName as ServerName, signingKey)
		: undefined;

	// Durable outbound EDU retry: replay any EDUs queued for destinations that
	// were unreachable, both once on startup (so a sender that restarted while a
	// peer was down still recovers — the "stopped server" Complement case) and
	// on a periodic timer (so a peer that comes back up is caught up even with no
	// new outbound traffic). Mirrors Synapse's per-destination catch-up.
	if (federationClient) {
		const fc = federationClient;
		const sweep = (): void => {
			void flushAllPendingEdus(storage, serverName, fc).catch(() => {});
		};
		// Initial sweep shortly after startup (let listeners bind first).
		setTimeout(sweep, 1000).unref();
		// Periodic catch-up sweep.
		setInterval(sweep, 5000).unref();
	}

	router.get("/_matrix/client/versions", versionsHandler(serverName));
	router.get("/.well-known/matrix/server", wellKnownServerHandler(serverName));
	router.get("/.well-known/matrix/client", wellKnownClientHandler(serverName));
	router.get("/.well-known/matrix/support", wellKnownSupportHandler());
	router.get(
		"/.well-known/matrix/policy_server",
		wellKnownPolicyServerHandler(),
	);
	router.get("/_matrix/client/v1/auth_metadata", getAuthMetadata());
	router.get("/_matrix/client/v3/capabilities", getCapabilities(), auth);

	router.get("/_matrix/client/v3/login", getLoginFlows(registrations));
	router.post(
		"/_matrix/client/v3/login",
		postLogin(storage, serverName, registrations),
		loginRL,
	);
	router.post(
		"/_matrix/client/v3/register",
		postRegister(storage, serverName),
		registerRL,
	);
	router.get(
		"/_matrix/client/v3/register/available",
		getRegisterAvailable(storage),
	);
	router.post(
		"/_matrix/client/v3/register/email/requestToken",
		postRegisterEmailRequestToken(storage, serverName),
	);
	router.post(
		"/_matrix/client/v3/register/msisdn/requestToken",
		postRegisterMsisdnRequestToken(),
	);
	router.get(
		"/_matrix/client/v3/register/m.login.registration_token/validity",
		getRegistrationTokenValidity(),
	);
	router.get(
		"/_matrix/client/v1/register/m.login.registration_token/validity",
		getRegistrationTokenValidity(),
	);
	router.post("/_matrix/client/v3/refresh", postRefresh(storage));
	router.post(
		"/_matrix/client/v1/login/get_token",
		postLoginGetToken(storage),
		auth,
	);

	// SSO routes (only registered when SSO is configured)
	const ssoConfig = getSsoConfig();
	if (ssoConfig) {
		router.get(
			"/_matrix/client/v3/login/sso/redirect/:idpId",
			getSsoRedirect(ssoConfig),
		);
		router.get(
			"/_matrix/client/v3/login/sso/redirect",
			getSsoRedirect(ssoConfig),
		);
		router.get(
			"/_matrix/client/v3/login/sso/callback",
			getSsoCallback(storage, serverName, ssoConfig),
		);
		router.get(
			"/_matrix/client/v3/auth/m.login.sso/fallback/web",
			getSsoFallback(ssoConfig),
		);
	}

	router.post("/_matrix/client/v3/logout", postLogout(storage), auth);
	router.post("/_matrix/client/v3/logout/all", postLogoutAll(storage), auth);
	router.get("/_matrix/client/v3/account/whoami", getWhoAmI(), auth);

	router.post(
		"/_matrix/client/v3/account/password",
		postChangePassword(storage),
		auth,
		defaultRL,
	);
	router.post(
		"/_matrix/client/v3/account/password/email/requestToken",
		postPasswordEmailRequestToken(storage, serverName),
	);
	router.post(
		"/_matrix/client/v3/account/password/msisdn/requestToken",
		postPasswordMsisdnRequestToken(),
	);
	router.post(
		"/_matrix/client/v3/account/deactivate",
		postDeactivate(storage),
		auth,
		defaultRL,
	);

	router.get(
		"/_matrix/client/v3/admin/whois/:userId",
		getAdminWhois(storage),
		auth,
	);

	router.put(
		"/_matrix/client/v1/admin/lock/:userId",
		putAdminLock(storage),
		auth,
	);
	router.get(
		"/_matrix/client/v1/admin/lock/:userId",
		getAdminLock(storage),
		auth,
	);
	router.put(
		"/_matrix/client/v1/admin/suspend/:userId",
		putAdminSuspend(storage),
		auth,
	);
	router.get(
		"/_matrix/client/v1/admin/suspend/:userId",
		getAdminSuspend(storage),
		auth,
	);

	router.get(
		"/_matrix/client/v3/profile/:userId",
		getProfile(storage, serverName, federationClient),
	);
	router.get(
		"/_matrix/client/v3/profile/:userId/displayname",
		getDisplayName(storage, serverName, federationClient),
	);
	router.get(
		"/_matrix/client/v3/profile/:userId/avatar_url",
		getAvatarUrl(storage, serverName, federationClient),
	);
	router.put(
		"/_matrix/client/v3/profile/:userId/displayname",
		putDisplayName(storage, serverName, signingKey, federationClient),
		auth,
	);
	router.put(
		"/_matrix/client/v3/profile/:userId/avatar_url",
		putAvatarUrl(storage, serverName, signingKey, federationClient),
		auth,
	);
	router.get(
		"/_matrix/client/v3/profile/:userId/:keyName",
		getProfileField(storage),
	);
	router.put(
		"/_matrix/client/v3/profile/:userId/:keyName",
		putProfileField(storage, serverName),
		auth,
	);
	router.delete(
		"/_matrix/client/v3/profile/:userId/:keyName",
		deleteProfileField(storage, serverName),
		auth,
	);

	router.get("/_matrix/client/v3/devices", getDevices(storage), auth);
	router.get("/_matrix/client/v3/devices/:deviceId", getDevice(storage), auth);
	router.put(
		"/_matrix/client/v3/devices/:deviceId",
		putDevice(storage, serverName as ServerName, signingKey, federationClient),
		auth,
	);
	router.delete(
		"/_matrix/client/v3/devices/:deviceId",
		deleteDevice(storage),
		auth,
	);
	router.post(
		"/_matrix/client/v3/delete_devices",
		deleteDevices(storage),
		auth,
	);

	router.get(
		"/_matrix/client/v3/directory/room/:roomAlias",
		getDirectoryRoom(storage, serverName, federationClient),
	);
	router.put(
		"/_matrix/client/v3/directory/room/:roomAlias",
		putDirectoryRoom(storage, serverName),
		auth,
	);
	router.delete(
		"/_matrix/client/v3/directory/room/:roomAlias",
		deleteDirectoryRoom(storage, serverName),
		auth,
	);
	router.get(
		"/_matrix/client/v3/directory/list/room/:roomId",
		getDirectoryListRoom(storage),
	);
	router.put(
		"/_matrix/client/v3/directory/list/room/:roomId",
		putDirectoryListRoom(storage),
		auth,
	);
	router.get("/_matrix/client/v3/publicRooms", getPublicRooms(storage));
	router.post("/_matrix/client/v3/publicRooms", postPublicRooms(storage), auth);

	router.post(
		"/_matrix/client/v3/createRoom",
		postCreateRoom(storage, serverName, signingKey, federationClient),
		auth,
	);
	router.get("/_matrix/client/v3/joined_rooms", getJoinedRooms(storage), auth);

	router.post(
		"/_matrix/client/v3/join/:roomIdOrAlias",
		postJoin(storage, serverName, signingKey, federationClient),
		auth,
	);
	router.post(
		"/_matrix/client/v3/rooms/:roomId/join",
		postJoin(storage, serverName, signingKey, federationClient),
		auth,
	);
	router.post(
		"/_matrix/client/v3/rooms/:roomId/leave",
		postLeave(storage, serverName, signingKey, federationClient),
		auth,
	);
	router.post(
		"/_matrix/client/v3/rooms/:roomId/invite",
		postInvite(storage, serverName, signingKey, federationClient),
		auth,
	);
	router.post(
		"/_matrix/client/v3/rooms/:roomId/knock",
		postKnock(storage, serverName, signingKey, federationClient),
		auth,
	);
	router.post(
		"/_matrix/client/v3/knock/:roomIdOrAlias",
		postKnock(storage, serverName, signingKey, federationClient),
		auth,
	);
	router.post(
		"/_matrix/client/v3/rooms/:roomId/kick",
		postKick(storage, serverName, signingKey, federationClient),
		auth,
	);
	router.post(
		"/_matrix/client/v3/rooms/:roomId/ban",
		postBan(storage, serverName, signingKey, federationClient),
		auth,
	);
	router.post(
		"/_matrix/client/v3/rooms/:roomId/unban",
		postUnban(storage, serverName, signingKey, federationClient),
		auth,
	);
	router.post(
		"/_matrix/client/v3/rooms/:roomId/forget",
		postForget(storage),
		auth,
	);

	// MSC4140: when `org.matrix.msc4140.delay` is present, the send/state PUT
	// schedules a delayed event instead of sending immediately.
	const sendDispatch: Handler = (req) =>
		req.query.get("org.matrix.msc4140.delay") !== null
			? putDelayedEvent(storage, serverName)(req)
			: putSendEvent(storage, serverName, signingKey, federationClient)(req);
	const stateDispatch: Handler = (req) =>
		req.query.get("org.matrix.msc4140.delay") !== null
			? putDelayedStateEvent(storage, serverName)(req)
			: putStateEvent(storage, serverName, signingKey, federationClient)(req);

	router.put(
		"/_matrix/client/v3/rooms/:roomId/send/:eventType/:txnId",
		sendDispatch,
		auth,
	);
	router.put(
		"/_matrix/client/v3/rooms/:roomId/state/:eventType/:stateKey",
		stateDispatch,
		auth,
	);
	router.put(
		"/_matrix/client/v3/rooms/:roomId/state/:eventType",
		stateDispatch,
		auth,
	);
	router.get(
		"/_matrix/client/unstable/org.matrix.msc4140/delayed_events",
		getDelayedEvents(storage, serverName),
		auth,
	);
	router.post(
		"/_matrix/client/unstable/org.matrix.msc4140/delayed_events/:delayId/:action",
		postDelayedEventAction(),
	);
	router.post(
		"/_matrix/client/unstable/event_relationships",
		postEventRelationships(storage, serverName as ServerName, federationClient),
		auth,
	);

	router.get(
		"/_matrix/client/v3/rooms/:roomId/state",
		getAllState(storage),
		auth,
	);
	router.get(
		"/_matrix/client/v3/rooms/:roomId/state/:eventType/:stateKey",
		getStateEvent(storage),
		auth,
	);
	router.get(
		"/_matrix/client/v3/rooms/:roomId/state/:eventType",
		getStateEvent(storage),
		auth,
	);
	router.get(
		"/_matrix/client/v3/rooms/:roomId/messages",
		getMessages(storage, serverName, signingKey, federationClient),
		auth,
	);
	router.get(
		"/_matrix/client/v3/rooms/:roomId/members",
		getMembers(storage),
		auth,
	);
	router.get(
		"/_matrix/client/v3/rooms/:roomId/joined_members",
		getJoinedMembers(storage),
		auth,
	);
	router.get(
		"/_matrix/client/v3/rooms/:roomId/aliases",
		getRoomAliases(storage),
		auth,
	);
	router.get(
		"/_matrix/client/v3/rooms/:roomId/timestamp_to_event",
		getTimestampToEvent(storage, serverName, signingKey, federationClient),
		auth,
	);
	router.get(
		"/_matrix/client/v3/rooms/:roomId/event/:eventId",
		getEvent(storage),
		auth,
	);
	router.get(
		"/_matrix/client/v3/rooms/:roomId/context/:eventId",
		getContext(storage),
		auth,
	);

	router.put(
		"/_matrix/client/v3/rooms/:roomId/redact/:eventId/:txnId",
		postRedact(storage, serverName, signingKey, federationClient),
		auth,
	);

	router.get(
		"/_matrix/client/v3/rooms/:roomId/relations/:eventId/:relType/:eventType",
		getRelations(storage),
		auth,
	);
	router.get(
		"/_matrix/client/v3/rooms/:roomId/relations/:eventId/:relType",
		getRelations(storage),
		auth,
	);
	router.get(
		"/_matrix/client/v3/rooms/:roomId/relations/:eventId",
		getRelations(storage),
		auth,
	);

	router.post(
		"/_matrix/client/v3/user/:userId/filter",
		postCreateFilter(storage),
		auth,
	);
	router.get(
		"/_matrix/client/v3/user/:userId/filter/:filterId",
		getFilterById(storage),
		auth,
	);

	router.get(
		"/_matrix/client/v3/user/:userId/account_data/:type",
		getGlobalAccountData(storage),
		auth,
	);
	router.put(
		"/_matrix/client/v3/user/:userId/account_data/:type",
		putGlobalAccountData(storage),
		auth,
	);
	router.get(
		"/_matrix/client/v3/user/:userId/rooms/:roomId/account_data/:type",
		getRoomAccountData(storage),
		auth,
	);
	router.put(
		"/_matrix/client/v3/user/:userId/rooms/:roomId/account_data/:type",
		putRoomAccountData(storage),
		auth,
	);
	// MSC3391: account-data deletion (unstable prefix)
	router.delete(
		"/_matrix/client/unstable/org.matrix.msc3391/user/:userId/account_data/:type",
		deleteGlobalAccountData(storage),
		auth,
	);
	router.delete(
		"/_matrix/client/unstable/org.matrix.msc3391/user/:userId/rooms/:roomId/account_data/:type",
		deleteRoomAccountData(storage),
		auth,
	);

	router.get(
		"/_matrix/client/v3/user/:userId/rooms/:roomId/tags",
		getTags(storage),
		auth,
	);
	router.put(
		"/_matrix/client/v3/user/:userId/rooms/:roomId/tags/:tag",
		putTag(storage),
		auth,
	);
	router.delete(
		"/_matrix/client/v3/user/:userId/rooms/:roomId/tags/:tag",
		deleteTag(storage),
		auth,
	);

	router.put(
		"/_matrix/client/v3/rooms/:roomId/typing/:userId",
		putTyping(storage, serverName as ServerName, signingKey, federationClient),
		auth,
	);

	router.post(
		"/_matrix/client/v3/rooms/:roomId/receipt/:receiptType/:eventId",
		postReceipt(storage, serverName as ServerName, federationClient),
		auth,
	);

	router.post(
		"/_matrix/client/v3/rooms/:roomId/read_markers",
		postReadMarkers(storage, serverName as ServerName, federationClient),
		auth,
	);

	router.get(
		"/_matrix/client/v3/presence/:userId/status",
		getPresence(storage),
		auth,
	);
	router.put(
		"/_matrix/client/v3/presence/:userId/status",
		putPresence(
			storage,
			serverName as ServerName,
			signingKey,
			federationClient,
		),
		auth,
	);

	router.post(
		"/_matrix/media/v1/create",
		postCreateMedia(storage, serverName),
		auth,
	);
	router.put(
		"/_matrix/media/v3/upload/:serverName/:mediaId",
		putAsyncUpload(storage, serverName),
		auth,
	);
	router.post(
		"/_matrix/media/v3/upload",
		postUpload(storage, serverName),
		auth,
	);
	router.get(
		"/_matrix/media/v3/download/:serverName/:mediaId",
		getDownload(storage, serverName, signingKey),
	);
	router.get(
		"/_matrix/media/v3/download/:serverName/:mediaId/:fileName",
		getDownload(storage, serverName, signingKey),
	);
	router.get(
		"/_matrix/media/v3/thumbnail/:serverName/:mediaId",
		getThumbnail(storage, serverName, signingKey),
	);
	router.get("/_matrix/media/v3/config", getConfig(), auth);

	// Authenticated media endpoints (spec v1.11+)
	router.get(
		"/_matrix/client/v1/media/download/:serverName/:mediaId/:fileName",
		getDownload(storage, serverName, signingKey),
		auth,
	);
	router.get(
		"/_matrix/client/v1/media/download/:serverName/:mediaId",
		getDownload(storage, serverName, signingKey),
		auth,
	);
	router.get(
		"/_matrix/client/v1/media/thumbnail/:serverName/:mediaId",
		getThumbnail(storage, serverName, signingKey),
		auth,
	);
	router.get("/_matrix/client/v1/media/config", getConfig(), auth);

	router.get(
		"/_matrix/client/v1/media/preview_url",
		getUrlPreview(storage, serverName),
		auth,
	);
	router.get(
		"/_matrix/media/v3/preview_url",
		getUrlPreview(storage, serverName),
		auth,
	);

	router.get(
		"/_matrix/client/v3/pushrules/global/:kind/:ruleId/enabled",
		getPushRuleEnabled(storage),
		auth,
	);
	router.put(
		"/_matrix/client/v3/pushrules/global/:kind/:ruleId/enabled",
		putPushRuleEnabled(storage),
		auth,
	);
	router.get(
		"/_matrix/client/v3/pushrules/global/:kind/:ruleId/actions",
		getPushRuleActions(storage),
		auth,
	);
	router.put(
		"/_matrix/client/v3/pushrules/global/:kind/:ruleId/actions",
		putPushRuleActions(storage),
		auth,
	);
	router.get(
		"/_matrix/client/v3/pushrules/global/:kind/:ruleId",
		getPushRule(storage),
		auth,
	);
	router.put(
		"/_matrix/client/v3/pushrules/global/:kind/:ruleId",
		putPushRule(storage),
		auth,
	);
	router.delete(
		"/_matrix/client/v3/pushrules/global/:kind/:ruleId",
		deletePushRule(storage),
		auth,
	);
	router.get(
		"/_matrix/client/v3/pushrules/global/:kind",
		getPushRulesByKind(storage),
		auth,
	);
	router.get(
		"/_matrix/client/v3/pushrules/global",
		getGlobalPushRules(storage),
		auth,
	);
	router.get("/_matrix/client/v3/pushrules", getAllPushRules(storage), auth);

	router.get("/_matrix/client/v3/pushers", getPushers(storage), auth);
	router.post("/_matrix/client/v3/pushers/set", postPushersSet(storage), auth);

	router.post(
		"/_matrix/client/v3/keys/upload",
		postKeysUpload(
			storage,
			serverName as ServerName,
			signingKey,
			federationClient,
		),
		auth,
	);
	router.post(
		"/_matrix/client/v3/keys/query",
		postKeysQuery(storage, serverName as ServerName, federationClient),
		auth,
	);
	router.post(
		"/_matrix/client/v3/keys/claim",
		postKeysClaim(storage, serverName as ServerName, federationClient),
		auth,
	);
	router.get("/_matrix/client/v3/keys/changes", getKeysChanges(storage), auth);

	router.post(
		"/_matrix/client/v3/keys/device_signing/upload",
		postDeviceSigningUpload(storage),
		auth,
	);
	router.post(
		"/_matrix/client/v3/keys/signatures/upload",
		postSignaturesUpload(storage),
		auth,
	);

	// Key backup version management
	router.post(
		"/_matrix/client/v3/room_keys/version",
		postKeyBackupVersion(storage),
		auth,
	);
	router.get(
		"/_matrix/client/v3/room_keys/version/:version",
		getKeyBackupVersion(storage),
		auth,
	);
	router.put(
		"/_matrix/client/v3/room_keys/version/:version",
		putKeyBackupVersion(storage),
		auth,
	);
	router.delete(
		"/_matrix/client/v3/room_keys/version/:version",
		deleteKeyBackupVersion(storage),
		auth,
	);
	router.get(
		"/_matrix/client/v3/room_keys/version",
		getKeyBackupVersion(storage),
		auth,
	);

	// Key backup data — specific routes first
	router.put(
		"/_matrix/client/v3/room_keys/keys/:roomId/:sessionId",
		putKeyBackupSession(storage),
		auth,
	);
	router.get(
		"/_matrix/client/v3/room_keys/keys/:roomId/:sessionId",
		getKeyBackupSession(storage),
		auth,
	);
	router.delete(
		"/_matrix/client/v3/room_keys/keys/:roomId/:sessionId",
		deleteKeyBackupSession(storage),
		auth,
	);
	router.put(
		"/_matrix/client/v3/room_keys/keys/:roomId",
		putKeyBackupRoom(storage),
		auth,
	);
	router.get(
		"/_matrix/client/v3/room_keys/keys/:roomId",
		getKeyBackupRoom(storage),
		auth,
	);
	router.delete(
		"/_matrix/client/v3/room_keys/keys/:roomId",
		deleteKeyBackupRoom(storage),
		auth,
	);
	router.put(
		"/_matrix/client/v3/room_keys/keys",
		putKeyBackupAll(storage),
		auth,
	);
	router.get(
		"/_matrix/client/v3/room_keys/keys",
		getKeyBackupAll(storage),
		auth,
	);
	router.delete(
		"/_matrix/client/v3/room_keys/keys",
		deleteKeyBackupAll(storage),
		auth,
	);

	router.put(
		"/_matrix/client/v3/sendToDevice/:eventType/:txnId",
		putSendToDevice(
			storage,
			serverName as ServerName,
			signingKey,
			federationClient,
		),
		auth,
	);

	router.get("/_matrix/client/v3/voip/turnServer", getTurnServer(), auth);

	router.post(
		"/_matrix/client/v3/rooms/:roomId/report/:eventId",
		postReportEvent(storage),
		auth,
	);

	router.post(
		"/_matrix/client/v3/users/:userId/report",
		postReportUser(storage),
		auth,
	);

	router.post(
		"/_matrix/client/v3/user/:userId/openid/request_token",
		postOpenIdToken(storage, serverName),
		auth,
	);

	router.get("/_matrix/client/v3/account/3pid", getThreePids(storage), auth);
	router.post(
		"/_matrix/client/v3/account/3pid/add",
		postAddThreePid(storage),
		auth,
	);
	router.post(
		"/_matrix/client/v3/account/3pid/delete",
		postDeleteThreePid(storage),
		auth,
	);
	router.post(
		"/_matrix/client/v3/account/3pid/email/requestToken",
		postAccount3pidEmailRequestToken(storage, serverName),
	);
	router.post(
		"/_matrix/client/v3/account/3pid/msisdn/requestToken",
		postAccount3pidMsisdnRequestToken(),
	);
	router.post("/_matrix/client/v3/account/3pid/bind", postThreePidBind(), auth);
	router.post(
		"/_matrix/client/v3/account/3pid/unbind",
		postThreePidUnbind(),
		auth,
	);

	router.post(
		"/_matrix/client/v3/user_directory/search",
		postUserDirectorySearch(storage),
		auth,
	);

	router.get(
		"/_matrix/client/v3/rooms/:roomId/threads",
		getThreads(storage),
		auth,
	);

	// MSC4306 thread subscriptions
	router.put(
		"/_matrix/client/unstable/io.element.msc4306/rooms/:roomId/thread/:threadRootId/subscription",
		putThreadSubscription(storage),
		auth,
	);
	router.get(
		"/_matrix/client/unstable/io.element.msc4306/rooms/:roomId/thread/:threadRootId/subscription",
		getThreadSubscription(storage),
		auth,
	);
	router.delete(
		"/_matrix/client/unstable/io.element.msc4306/rooms/:roomId/thread/:threadRootId/subscription",
		deleteThreadSubscription(storage),
		auth,
	);

	router.get(
		"/_matrix/client/v3/notifications",
		getNotifications(storage),
		auth,
	);

	router.post("/_matrix/client/v3/search", postSearch(storage), auth);

	router.get(
		"/_matrix/client/v1/room_summary/:roomIdOrAlias",
		getRoomSummary(storage),
		auth,
	);

	router.get(
		"/_matrix/client/v3/rooms/:roomId/initialSync",
		getRoomInitialSync(storage),
		auth,
	);

	router.get(
		"/_matrix/client/v3/rooms/:roomId/hierarchy",
		getSpaceHierarchy(storage, serverName as ServerName, federationClient),
		auth,
	);

	router.post(
		"/_matrix/client/v3/rooms/:roomId/upgrade",
		postRoomUpgrade(storage, serverName, signingKey, federationClient),
		auth,
	);

	router.get(
		"/_matrix/client/v3/thirdparty/protocol/:protocol",
		getProtocol(),
		auth,
	);
	router.get("/_matrix/client/v3/thirdparty/protocols", getProtocols(), auth);
	router.get(
		"/_matrix/client/v3/thirdparty/location/:protocol",
		getThirdpartyLocationByProtocol(),
		auth,
	);
	router.get(
		"/_matrix/client/v3/thirdparty/location",
		getThirdpartyLocation(),
		auth,
	);
	router.get(
		"/_matrix/client/v3/thirdparty/user/:protocol",
		getThirdpartyUserByProtocol(),
		auth,
	);
	router.get("/_matrix/client/v3/thirdparty/user", getThirdpartyUser(), auth);

	// v1 path aliases for endpoints Element Web uses
	router.get(
		"/_matrix/client/v1/rooms/:roomId/hierarchy",
		getSpaceHierarchy(storage, serverName as ServerName, federationClient),
		auth,
	);
	router.get(
		"/_matrix/client/v1/rooms/:roomId/relations/:eventId/:relType/:eventType",
		getRelations(storage),
		auth,
	);
	router.get(
		"/_matrix/client/v1/rooms/:roomId/relations/:eventId/:relType",
		getRelations(storage),
		auth,
	);
	router.get(
		"/_matrix/client/v1/rooms/:roomId/relations/:eventId",
		getRelations(storage),
		auth,
	);
	router.get(
		"/_matrix/client/v1/rooms/:roomId/threads",
		getThreads(storage),
		auth,
	);
	router.get(
		"/_matrix/client/v1/rooms/:roomId/timestamp_to_event",
		getTimestampToEvent(storage, serverName, signingKey, federationClient),
		auth,
	);

	// Trailing-slash pushrules variants
	router.get("/_matrix/client/v3/pushrules/", getAllPushRules(storage), auth);
	router.get(
		"/_matrix/client/v3/pushrules/global/",
		getGlobalPushRules(storage),
		auth,
	);

	// Deprecated events endpoint
	router.get(
		"/_matrix/client/v3/events",
		(_req) => ({
			status: 200,
			body: { chunk: [], start: "", end: "" },
		}),
		auth,
	);

	// Room report without eventId
	router.post(
		"/_matrix/client/v3/rooms/:roomId/report",
		postReportRoom(storage),
		auth,
	);

	router.get("/_matrix/client/v3/sync", getSync(storage, serverName), auth);

	// Sliding sync (MSC3575 / v4)
	router.post(
		"/_matrix/client/unstable/org.matrix.simplified_msc3575/sync",
		slidingSync(storage, serverName),
		auth,
	);
	router.post(
		"/_matrix/client/v4/sync",
		slidingSync(storage, serverName),
		auth,
	);

	// Appservice endpoints
	router.post(
		"/_matrix/client/v1/appservice/:appserviceId/ping",
		postAppservicePing(registrations),
	);
	router.put(
		"/_matrix/client/v3/directory/list/appservice/:networkId/:roomId",
		putAppserviceDirectoryListRoom(storage, registrations),
		asAuth,
	);

	if (signingKey && federationClient) {
		const fedAuth = requireFederationAuth(
			serverName,
			storage,
			federationClient,
		);

		router.get("/_matrix/key/v2/server", getServerKeys(serverName, signingKey));
		router.get(
			"/_matrix/key/v2/server/:keyId",
			getServerKeys(serverName, signingKey),
		);

		router.post("/_matrix/key/v2/query", postKeyQuery(storage), fedAuth);
		router.get(
			"/_matrix/key/v2/query/:serverName",
			getKeyQuery(storage),
			fedAuth,
		);

		router.get("/_matrix/federation/v1/version", getFederationVersion());

		router.get(
			"/_matrix/federation/v1/query/profile",
			getQueryProfile(storage),
			fedAuth,
		);
		router.get(
			"/_matrix/federation/v1/query/directory",
			getQueryDirectory(storage),
			fedAuth,
		);
		router.get(
			"/_matrix/federation/v1/query/:queryType",
			getQueryGeneric(),
			fedAuth,
		);
		router.get(
			"/_matrix/federation/v1/publicRooms",
			getFederationPublicRooms(storage),
			fedAuth,
		);
		router.post(
			"/_matrix/federation/v1/publicRooms",
			postFederationPublicRooms(storage),
			fedAuth,
		);

		router.get(
			"/_matrix/federation/v1/openid/userinfo",
			getFederationOpenIdUserinfo(storage),
		);

		router.get(
			"/_matrix/federation/v1/event/:eventId",
			getFederationEvent(storage, serverName),
			fedAuth,
		);
		router.get(
			"/_matrix/federation/v1/state/:roomId",
			getFederationRoomState(storage),
			fedAuth,
		);
		router.get(
			"/_matrix/federation/v1/state_ids/:roomId",
			getFederationRoomStateIds(storage),
			fedAuth,
		);
		router.get(
			"/_matrix/federation/v1/event_auth/:roomId/:eventId",
			getFederationEventAuth(storage),
			fedAuth,
		);
		// Federation backfill is a GET per the spec (server-server-api); the handler
		// reads `v`/`limit` from the query string. Registering it as POST made our
		// own outbound backfill — and any spec-compliant peer — get 405, breaking
		// jump-to-date's remote event fetch.
		router.get(
			"/_matrix/federation/v1/backfill/:roomId",
			postFederationBackfill(storage, serverName),
			fedAuth,
		);
		router.post(
			"/_matrix/federation/v1/get_missing_events/:roomId",
			postFederationMissingEvents(storage),
			fedAuth,
		);

		router.get(
			"/_matrix/federation/v1/timestamp_to_event/:roomId",
			getFederationTimestampToEvent(storage),
			fedAuth,
		);

		// Spec endpoint is GET; keep POST registered too for any non-conforming
		// caller (the handler reads only the path param, never a body).
		router.get(
			"/_matrix/federation/v1/user/devices/:userId",
			postFederationUserDevices(storage),
			fedAuth,
		);
		router.post(
			"/_matrix/federation/v1/user/devices/:userId",
			postFederationUserDevices(storage),
			fedAuth,
		);
		router.post(
			"/_matrix/federation/v1/user/keys/query",
			postFederationKeysQuery(storage),
			fedAuth,
		);
		router.post(
			"/_matrix/federation/v1/user/keys/claim",
			postFederationKeysClaim(storage),
			fedAuth,
		);

		router.put(
			"/_matrix/federation/v1/send/:txnId",
			putFederationSend(storage, serverName, signingKey, federationClient),
			fedAuth,
		);

		router.get(
			"/_matrix/federation/v1/make_join/:roomId/:userId",
			getMakeJoin(storage, serverName),
			fedAuth,
		);
		router.put(
			"/_matrix/federation/v2/send_join/:roomId/:eventId",
			putSendJoin(storage, serverName, signingKey, federationClient),
			fedAuth,
		);
		router.put(
			"/_matrix/federation/v1/send_join/:roomId/:eventId",
			putSendJoin(storage, serverName, signingKey, federationClient),
			fedAuth,
		);
		router.get(
			"/_matrix/federation/v1/make_leave/:roomId/:userId",
			getMakeLeave(storage, serverName),
			fedAuth,
		);
		router.put(
			"/_matrix/federation/v2/send_leave/:roomId/:eventId",
			putSendLeave(storage, serverName, signingKey, federationClient),
			fedAuth,
		);
		router.put(
			"/_matrix/federation/v1/send_leave/:roomId/:eventId",
			putSendLeave(storage, serverName, signingKey, federationClient),
			fedAuth,
		);
		router.put(
			"/_matrix/federation/v2/invite/:roomId/:eventId",
			putFederationInvite(storage, serverName, signingKey, federationClient),
			fedAuth,
		);

		router.get(
			"/_matrix/federation/v1/make_knock/:roomId/:userId",
			getMakeKnock(storage, serverName),
			fedAuth,
		);
		router.put(
			"/_matrix/federation/v1/send_knock/:roomId/:eventId",
			putSendKnock(storage, serverName, signingKey, federationClient),
			fedAuth,
		);

		router.get(
			"/_matrix/federation/v1/hierarchy/:roomId",
			postFederationHierarchy(storage),
			fedAuth,
		);
		router.post(
			"/_matrix/federation/unstable/event_relationships",
			postFederationEventRelationships(
				storage,
				serverName as ServerName,
				federationClient,
			),
			fedAuth,
		);

		router.get(
			"/_matrix/federation/v1/media/download/:mediaId",
			getFederationMediaDownload(storage, serverName),
			fedAuth,
		);
		router.get(
			"/_matrix/federation/v1/media/thumbnail/:mediaId",
			getFederationMediaThumbnail(storage, serverName),
			fedAuth,
		);

		router.put(
			"/_matrix/federation/v1/invite/:roomId/:eventId",
			putFederationInvite(storage, serverName, signingKey, federationClient),
			fedAuth,
		);
		router.post(
			"/_matrix/federation/v1/exchange_third_party_invite/:roomId",
			postExchangeThirdPartyInvite(),
			fedAuth,
		);
		router.post(
			"/_matrix/federation/v1/3pid/onbind",
			postThreePidOnBind(),
			fedAuth,
		);
	}

	// r0 route aliases for older clients / Complement
	router.post(
		"/_matrix/client/r0/register",
		postRegister(storage, serverName),
		registerRL,
	);
	router.get("/_matrix/client/r0/login", getLoginFlows(registrations));
	router.post(
		"/_matrix/client/r0/login",
		postLogin(storage, serverName, registrations),
		loginRL,
	);
	router.post(
		"/_matrix/client/r0/createRoom",
		postCreateRoom(storage, serverName, signingKey, federationClient),
		auth,
	);
	router.get("/_matrix/client/r0/sync", getSync(storage, serverName), auth);
	router.post(
		"/_matrix/client/r0/join/:roomIdOrAlias",
		postJoin(storage, serverName, signingKey, federationClient),
		auth,
	);
	router.get("/_matrix/client/r0/joined_rooms", getJoinedRooms(storage), auth);
	router.put(
		"/_matrix/client/r0/rooms/:roomId/send/:eventType/:txnId",
		putSendEvent(storage, serverName, signingKey, federationClient),
		auth,
	);
	router.get(
		"/_matrix/client/r0/rooms/:roomId/messages",
		getMessages(storage, serverName, signingKey, federationClient),
		auth,
	);
	router.get(
		"/_matrix/client/r0/rooms/:roomId/state",
		getAllState(storage),
		auth,
	);
	router.put(
		"/_matrix/client/r0/rooms/:roomId/state/:eventType/:stateKey",
		putStateEvent(storage, serverName, signingKey, federationClient),
		auth,
	);
	router.put(
		"/_matrix/client/r0/rooms/:roomId/state/:eventType",
		putStateEvent(storage, serverName, signingKey, federationClient),
		auth,
	);
	router.get(
		"/_matrix/client/r0/profile/:userId",
		getProfile(storage, serverName, federationClient),
	);
	router.get("/_matrix/client/r0/account/whoami", getWhoAmI(), auth);
	router.post(
		"/_matrix/client/r0/rooms/:roomId/leave",
		postLeave(storage, serverName, signingKey, federationClient),
		auth,
	);
	router.post(
		"/_matrix/client/r0/rooms/:roomId/invite",
		postInvite(storage, serverName, signingKey, federationClient),
		auth,
	);
	router.post(
		"/_matrix/client/r0/rooms/:roomId/join",
		postJoin(storage, serverName, signingKey, federationClient),
		auth,
	);
	router.get(
		"/_matrix/client/r0/rooms/:roomId/state/:eventType/:stateKey",
		getStateEvent(storage),
		auth,
	);
	router.get(
		"/_matrix/client/r0/rooms/:roomId/state/:eventType",
		getStateEvent(storage),
		auth,
	);
	router.get(
		"/_matrix/client/r0/rooms/:roomId/members",
		getMembers(storage),
		auth,
	);
	router.get(
		"/_matrix/client/r0/rooms/:roomId/event/:eventId",
		getEvent(storage),
		auth,
	);
	router.get("/_matrix/client/r0/capabilities", getCapabilities(), auth);
	router.post("/_matrix/client/r0/logout", postLogout(storage), auth);
	router.post("/_matrix/client/r0/logout/all", postLogoutAll(storage), auth);
	router.post(
		"/_matrix/client/r0/keys/upload",
		postKeysUpload(
			storage,
			serverName as ServerName,
			signingKey,
			federationClient,
		),
		auth,
	);
	router.post(
		"/_matrix/client/r0/keys/query",
		postKeysQuery(storage, serverName as ServerName, federationClient),
		auth,
	);
	router.post(
		"/_matrix/client/r0/keys/claim",
		postKeysClaim(storage, serverName as ServerName, federationClient),
		auth,
	);
	router.put(
		"/_matrix/client/r0/sendToDevice/:eventType/:txnId",
		putSendToDevice(
			storage,
			serverName as ServerName,
			signingKey,
			federationClient,
		),
		auth,
	);
	router.put(
		"/_matrix/client/r0/rooms/:roomId/redact/:eventId/:txnId",
		postRedact(storage, serverName, signingKey, federationClient),
		auth,
	);
	router.get("/_matrix/client/r0/pushrules", getAllPushRules(storage), auth);
	router.get(
		"/_matrix/client/r0/user/:userId/account_data/:type",
		getGlobalAccountData(storage),
		auth,
	);
	router.put(
		"/_matrix/client/r0/user/:userId/account_data/:type",
		putGlobalAccountData(storage),
		auth,
	);
	router.put(
		"/_matrix/client/r0/rooms/:roomId/typing/:userId",
		putTyping(storage, serverName as ServerName, signingKey, federationClient),
		auth,
	);
	router.post(
		"/_matrix/client/r0/rooms/:roomId/receipt/:receiptType/:eventId",
		postReceipt(storage, serverName as ServerName, federationClient),
		auth,
	);
	router.get("/_matrix/client/r0/voip/turnServer", getTurnServer(), auth);
	router.get("/_matrix/client/r0/devices", getDevices(storage), auth);
	router.post(
		"/_matrix/client/r0/user/:userId/filter",
		postCreateFilter(storage),
		auth,
	);
	router.get(
		"/_matrix/client/r0/user/:userId/filter/:filterId",
		getFilterById(storage),
		auth,
	);
	router.get(
		"/_matrix/client/r0/rooms/:roomId/context/:eventId",
		getContext(storage),
		auth,
	);
	router.get("/_matrix/client/r0/publicRooms", getPublicRooms(storage));
	router.post("/_matrix/client/r0/publicRooms", postPublicRooms(storage), auth);
	router.get(
		"/_matrix/client/r0/directory/room/:roomAlias",
		getDirectoryRoom(storage, serverName, federationClient),
	);
	router.put(
		"/_matrix/client/r0/directory/room/:roomAlias",
		putDirectoryRoom(storage, serverName),
		auth,
	);
	router.get(
		"/_matrix/client/r0/presence/:userId/status",
		getPresence(storage),
		auth,
	);
	router.put(
		"/_matrix/client/r0/presence/:userId/status",
		putPresence(
			storage,
			serverName as ServerName,
			signingKey,
			federationClient,
		),
		auth,
	);
	router.post(
		"/_matrix/client/r0/account/password",
		postChangePassword(storage),
		auth,
		defaultRL,
	);
	router.get(
		"/_matrix/client/r0/register/available",
		getRegisterAvailable(storage),
	);
	router.get("/_matrix/client/r0/account/3pid", getThreePids(storage), auth);
	router.get(
		"/_matrix/client/r0/rooms/:roomId/joined_members",
		getJoinedMembers(storage),
		auth,
	);
	router.get(
		"/_matrix/client/r0/rooms/:roomId/aliases",
		getRoomAliases(storage),
		auth,
	);
	router.post(
		"/_matrix/client/r0/rooms/:roomId/kick",
		postKick(storage, serverName, signingKey, federationClient),
		auth,
	);
	router.post(
		"/_matrix/client/r0/rooms/:roomId/ban",
		postBan(storage, serverName, signingKey, federationClient),
		auth,
	);
	router.post(
		"/_matrix/client/r0/rooms/:roomId/unban",
		postUnban(storage, serverName, signingKey, federationClient),
		auth,
	);
	router.post(
		"/_matrix/client/r0/rooms/:roomId/forget",
		postForget(storage),
		auth,
	);

	// Policy server endpoint — we are not a policy server, return 404
	router.post("/_matrix/policy/v1/sign", (_req) => ({
		status: 404,
		body: {
			errcode: "M_NOT_FOUND",
			error: "This server is not a policy server",
		},
	}));

	// Resume background resyncs for any rooms left partial-state by a restart.
	// The sqlite backend persists the flag; in-memory backends start empty.
	// Fire-and-forget once all routes are wired up.
	if (federationClient) {
		void resumePartialStateResyncs(
			storage,
			serverName as ServerName,
			federationClient,
		);
	}
};
