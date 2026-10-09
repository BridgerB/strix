import { randomBytes } from "node:crypto";
import { generateSessionId } from "../crypto.ts";
import { hashPassword } from "../crypto-utils.ts";
import {
	badJson,
	invalidParam,
	invalidUsername,
	userInUse,
	weakPassword,
} from "../errors.ts";
import { getOrInitRules } from "../push-rules.ts";
import type { Handler } from "../router.ts";
import type { Storage } from "../storage/interface.ts";
import type {
	AuthType,
	LoginResponse,
	RegisterRequest,
	UIAAResponse,
} from "../types/index.ts";
import { createSessionAndRespond } from "./auth-shared.ts";

const REGISTRATION_FLOWS: { stages: AuthType[] }[] = [
	{ stages: ["m.login.dummy"] },
];

// Minimum password length. The Matrix spec does not mandate a server-side
// minimum, and Complement tests legitimately register with short passwords
// (e.g. "hunter2", "secret"); an overly strict minimum (was 8) rejected those
// with M_WEAK_PASSWORD. Keep it at 1 so only an empty password is rejected
// (empty is also caught earlier by the missing-field check).
const MIN_PASSWORD_LENGTH = 1;
export const USERNAME_RE = /^[a-z0-9._=\-/]+$/;

export const postRegister =
	(storage: Storage, serverName: string): Handler =>
	async (req) => {
		const kind = req.query.get("kind") ?? "user";

		if (kind === "guest") {
			return registerGuest(storage, serverName, req);
		}

		const body = req.body as RegisterRequest;

		// Validate the requested username up front — format, then availability — so
		// an invalid or already-taken username is rejected with 400 *before* the
		// UIAA dance (Synapse behaviour; TestRegistration). The initial UIAA probe
		// may legitimately omit the username, so only check when one is present.
		if (body.username != null && body.username !== "") {
			const lp = String(body.username).toLowerCase();
			if (!USERNAME_RE.test(lp))
				throw invalidUsername(
					"Username can only contain lowercase letters, digits, and ._=-/",
				);
			if (await storage.getUserByLocalpart(lp)) throw userInUse();
		}

		if (!body.auth) {
			const sessionId = generateSessionId();
			await storage.createUIAASession(sessionId);
			const uiaa: UIAAResponse = {
				flows: REGISTRATION_FLOWS,
				params: {},
				session: sessionId,
			};
			return { status: 401, body: uiaa };
		}

		// A UIAA session is required: auth provided without a session (or with an
		// unknown one) must be answered with a fresh 401 challenge, not silently
		// completed — otherwise registration "succeeds" with no real auth step
		// (TestRegistration "without a session fails").
		const sessionId = body.auth.session;
		const uiaaSession = sessionId
			? await storage.getUIAASession(sessionId)
			: undefined;
		if (!sessionId || !uiaaSession) {
			const newSession = generateSessionId();
			await storage.createUIAASession(newSession);
			return {
				status: 401,
				body: {
					flows: REGISTRATION_FLOWS,
					params: {},
					session: newSession,
				},
			};
		}

		if (body.auth.type === "m.login.dummy") {
			await storage.addUIAACompleted(sessionId, "m.login.dummy");
		} else {
			throw invalidParam(`Unsupported auth type: ${body.auth.type}`);
		}

		const updated = await storage.getUIAASession(sessionId);
		const allCompleted = REGISTRATION_FLOWS.some((flow) =>
			flow.stages.every((stage) => updated?.completed.includes(stage)),
		);

		if (!allCompleted) {
			const uiaa: UIAAResponse = {
				flows: REGISTRATION_FLOWS,
				params: {},
				session: sessionId,
				completed: updated?.completed as AuthType[] | undefined,
			};
			return { status: 401, body: uiaa };
		}

		if (!body.username) throw badJson("Missing 'username' field");
		const localpart = body.username.toLowerCase();
		if (!USERNAME_RE.test(localpart))
			throw invalidUsername(
				"Username can only contain lowercase letters, digits, and ._=-/",
			);

		const existing = await storage.getUserByLocalpart(localpart);
		if (existing) throw userInUse();

		if (!body.password) throw badJson("Missing 'password' field");
		if (body.password.length < MIN_PASSWORD_LENGTH)
			throw weakPassword(
				`Password must be at least ${MIN_PASSWORD_LENGTH} characters`,
			);

		const userId = `@${localpart}:${serverName}`;
		const now = Date.now();

		const passwordHash = await hashPassword(body.password);

		await storage.createUser({
			user_id: userId,
			localpart,
			server_name: serverName,
			password_hash: passwordHash,
			account_type: "user",
			is_deactivated: false,
			created_at: now,
		});

		// Materialise the default push rules now, at registration, rather than
		// lazily on first push-rule/sync access. A lazy init during /sync would
		// write account data mid-sync and bump the stream, making an otherwise
		// idle long-poll return immediately with a spurious m.push_rules change.
		await getOrInitRules(storage, userId);

		await storage.deleteUIAASession(sessionId);

		if (body.inhibit_login) {
			return { status: 200, body: { user_id: userId } };
		}

		const { accessToken, deviceId, refreshToken } =
			await createSessionAndRespond(storage, req, userId, body);

		const response: LoginResponse = {
			user_id: userId,
			access_token: accessToken,
			device_id: deviceId,
		};

		if (refreshToken) {
			response.refresh_token = refreshToken;
			response.expires_in_ms = 300_000;
		}

		return { status: 200, body: response };
	};

async function registerGuest(
	storage: Storage,
	serverName: string,
	req: import("../router.ts").RouterRequest,
): Promise<import("../router.ts").RouterResponse> {
	const guestId = randomBytes(12).toString("base64url");
	const localpart = `_guest_${guestId}`;
	const userId = `@${localpart}:${serverName}`;
	const now = Date.now();

	await storage.createUser({
		user_id: userId,
		localpart,
		server_name: serverName,
		password_hash: randomBytes(32).toString("base64url"),
		account_type: "guest",
		is_deactivated: false,
		created_at: now,
	});

	// See postRegister: materialise default push rules eagerly.
	await getOrInitRules(storage, userId);

	const body = (req.body ?? {}) as {
		device_id?: string;
		initial_device_display_name?: string;
	};

	const { accessToken, deviceId } = await createSessionAndRespond(
		storage,
		req,
		userId,
		body,
	);

	const response: LoginResponse = {
		user_id: userId,
		access_token: accessToken,
		device_id: deviceId,
	};

	return { status: 200, body: response };
}
