/**
 * The four endpoints of the wire contract, as plain functions.
 *
 * **No HTTP framework is imported here and none ever will be.** These are
 * `(input) => Promise<{ status, body }>`; the consumer adapts them to Express,
 * Hono, Fastify, or `node:http` in three lines. The moment this file imports
 * Express it stops working for the Hono user, and the PHP twin — which mounts
 * the identical contract on a Laravel route group — stops having anything to
 * mirror.
 *
 * Nothing here decides *anything* about the ceremony. It parses a body, calls
 * `PasskeyServer`, and turns a `PasskeyError` into a status and a body. Every
 * security decision lives in `server.ts`.
 *
 * @module
 */

import type { PublicKeyCredentialCreationOptionsJSON, PublicKeyCredentialRequestOptionsJSON, RegistrationResponseJSON, AuthenticationResponseJSON } from "@simplewebauthn/server";

import { PasskeyError } from "./errors.js";
import type { PasskeyServer } from "./server.js";
import type { PasskeyErrorCode, PasskeySummary, PasskeyUser, StoredCredential } from "./types.js";

/**
 * The application-specific half: who is logged in, who owns an email, and what
 * "log in" means.
 *
 * `Ctx` is whatever the consumer's framework calls a request — this package
 * never inspects it, it only hands it back.
 */
export interface PasskeyHooks<Ctx = unknown> {
  /**
   * The already-authenticated user enrolling a passkey, or `null`.
   *
   * Enrollment happens on a signed-in user: v1 has no passkey-only signup, on
   * purpose (it needs an account-provisioning policy and an anti-abuse story
   * that belong to the app).
   */
  currentUser(ctx: Ctx): Promise<PasskeyUser | null>;

  /**
   * Look a user up for the **username-first** login flow.
   *
   * Return `null` for an unknown address. `loginOptions` then answers 200 with
   * a well-formed payload and an empty `allowCredentials` — never a 404, which
   * would be a user-enumeration oracle. Omit the hook entirely if the app only
   * uses the discoverable flow.
   */
  resolveUserByEmail?(email: string, ctx: Ctx): Promise<PasskeyUser | null>;

  /**
   * Establish the session. Called only after the assertion has verified.
   *
   * Whatever it resolves to becomes the `user` field of the login response, so
   * return the app's public user payload (and `undefined` if there isn't one).
   */
  onAuthenticated(userHandle: string, credential: StoredCredential, ctx: Ctx): Promise<unknown>;
}

/** What a handler is given: the parsed JSON body, and the framework's request. */
export interface PasskeyRequest<Ctx = unknown> {
  /** The already-parsed JSON body. Absent is treated as `{}`. */
  body?: unknown;
  /** Passed through to the hooks untouched. */
  ctx: Ctx;
}

/** What a handler returns. Serialise `body` as JSON and send `status`. */
export interface PasskeyResponse<Body = unknown> {
  status: number;
  body: Body;
}

/** The error body every failure answers with. */
export interface PasskeyErrorBody {
  error: { code: PasskeyErrorCode; message: string };
}

/** `POST {prefix}/register/options` → 200. */
export interface RegisterOptionsBody {
  state: string;
  publicKey: PublicKeyCredentialCreationOptionsJSON;
}

/** `POST {prefix}/register` → 201. */
export interface RegisterBody {
  credential: PasskeySummary;
}

/** `POST {prefix}/login/options` → 200. */
export interface LoginOptionsBody {
  state: string;
  publicKey: PublicKeyCredentialRequestOptionsJSON;
}

/** `POST {prefix}/login` → 200. */
export interface LoginBody {
  /** Whatever {@link PasskeyHooks.onAuthenticated} returned, or `null`. */
  user: unknown;
  credential: PasskeySummary;
}

/** The four handlers. All are POST; all should be sent `Cache-Control: no-store`. */
export interface PasskeyHandlers<Ctx = unknown> {
  registerOptions(input: PasskeyRequest<Ctx>): Promise<PasskeyResponse<RegisterOptionsBody | PasskeyErrorBody>>;
  register(input: PasskeyRequest<Ctx>): Promise<PasskeyResponse<RegisterBody | PasskeyErrorBody>>;
  loginOptions(input: PasskeyRequest<Ctx>): Promise<PasskeyResponse<LoginOptionsBody | PasskeyErrorBody>>;
  login(input: PasskeyRequest<Ctx>): Promise<PasskeyResponse<LoginBody | PasskeyErrorBody>>;
}

/**
 * `PasskeyErrorCode` is a closed set shared with the PHP twin and has no
 * `unauthenticated` member — over there the route group sits behind `auth`
 * middleware, so the controller is never reached. Node has no such middleware
 * by construction, so an unauthenticated enrollment call answers 401 with the
 * nearest honest code rather than inventing a fourteenth one and breaking
 * parity.
 *
 * Put real authentication middleware in front of these routes; this is the
 * backstop, not the mechanism.
 */
const UNAUTHENTICATED: PasskeyResponse<PasskeyErrorBody> = Object.freeze({
  status: 401,
  body: Object.freeze({
    error: Object.freeze({
      code: "not_supported" as PasskeyErrorCode,
      message: "Passkey enrollment requires an authenticated user.",
    }),
  }),
});

/**
 * Build the four handlers.
 *
 * @example Express
 * ```ts
 * const handlers = createPasskeyHandlers<express.Request>(server, hooks);
 * app.post("/passkeys/login", express.json(), async (req, res) => {
 *   const { status, body } = await handlers.login({ body: req.body, ctx: req });
 *   res.status(status).set("Cache-Control", "no-store").json(body);
 * });
 * ```
 */
export function createPasskeyHandlers<Ctx = unknown>(
  server: PasskeyServer,
  hooks: PasskeyHooks<Ctx>,
): PasskeyHandlers<Ctx> {
  return {
    async registerOptions(input) {
      return guard<RegisterOptionsBody | PasskeyErrorBody>(async () => {
        const user = await hooks.currentUser(input.ctx);
        if (!user) {
          return UNAUTHENTICATED;
        }
        const { state, publicKey } = await server.startRegistration(user);
        return { status: 200, body: { state, publicKey } };
      });
    },

    async register(input) {
      return guard<RegisterBody | PasskeyErrorBody>(async () => {
        const user = await hooks.currentUser(input.ctx);
        if (!user) {
          return UNAUTHENTICATED;
        }

        const body = asRecord(input.body);
        const state = requiredString(body, "state");
        const response = requiredCeremonyResponse<RegistrationResponseJSON>(body);
        const name = optionalString(body, "name");

        const { summary } = await server.finishRegistration({ state, response, name });
        return { status: 201, body: { credential: summary } };
      });
    },

    async loginOptions(input) {
      return guard<LoginOptionsBody | PasskeyErrorBody>(async () => {
        const body = asRecord(input.body);
        const email = optionalString(body, "email");

        // An unknown address must be indistinguishable from a known one with no
        // passkeys: both produce a well-formed payload with an empty
        // `allowCredentials`. Answering 404 here would turn the login form into
        // a user-enumeration oracle. (The timing difference of the lookup is
        // not closed in v1 — the README says so plainly.)
        const user =
          email && hooks.resolveUserByEmail ? await hooks.resolveUserByEmail(email, input.ctx) : null;

        const { state, publicKey } = await server.startAuthentication(
          user ? { userHandle: user.handle } : {},
        );
        return { status: 200, body: { state, publicKey } };
      });
    },

    async login(input) {
      return guard<LoginBody | PasskeyErrorBody>(async () => {
        const body = asRecord(input.body);
        const state = requiredString(body, "state");
        const response = requiredCeremonyResponse<AuthenticationResponseJSON>(body);

        const result = await server.finishAuthentication({ state, response });
        const user = await hooks.onAuthenticated(result.userHandle, result.credential, input.ctx);

        return { status: 200, body: { user: user ?? null, credential: result.summary } };
      });
    },
  };
}

/**
 * Turn a `PasskeyError` into a response; let everything else through.
 *
 * Deliberately narrow: a `TypeError` from a misconfigured relying party, or a
 * dropped database connection, is not something to hand a client a tidy 4xx
 * for. Those are the app's 500s and they should be logged and alerted on.
 */
async function guard<Body>(
  run: () => Promise<PasskeyResponse<Body>>,
): Promise<PasskeyResponse<Body | PasskeyErrorBody>> {
  try {
    return await run();
  } catch (err) {
    if (err instanceof PasskeyError) {
      return { status: err.httpStatus, body: err.toJSON() };
    }
    throw err;
  }
}

function asRecord(body: unknown): Record<string, unknown> {
  if (body === undefined || body === null) {
    return {};
  }
  if (typeof body !== "object" || Array.isArray(body)) {
    throw PasskeyError.invalidResponse();
  }
  return body as Record<string, unknown>;
}

function requiredString(body: Record<string, unknown>, key: string): string {
  const value = body[key];
  if (typeof value !== "string" || value.length === 0) {
    throw PasskeyError.invalidResponse();
  }
  return value;
}

function optionalString(body: Record<string, unknown>, key: string): string | undefined {
  const value = body[key];
  if (value === undefined || value === null) {
    return undefined;
  }
  if (typeof value !== "string") {
    throw PasskeyError.invalidResponse();
  }
  return value;
}

/**
 * Pull `response` out of the body with the one structural check the server
 * relies on: `id` must be a string, because both finish paths look a credential
 * up by it. Everything past that is the library's job — validating a WebAuthn
 * response is precisely the work we refuse to duplicate.
 */
function requiredCeremonyResponse<T>(body: Record<string, unknown>): T {
  const response = body["response"];
  if (typeof response !== "object" || response === null || Array.isArray(response)) {
    throw PasskeyError.invalidResponse();
  }
  if (typeof (response as { id?: unknown }).id !== "string") {
    throw PasskeyError.invalidResponse();
  }
  return response as T;
}
