import { describe, expect, it, vi } from "vitest";

import { createPasskeyHandlers } from "../src/http.js";
import type { PasskeyHandlers, PasskeyHooks } from "../src/http.js";
import { PasskeyServer } from "../src/server.js";
import { InMemoryChallengeStore, InMemoryCredentialStore } from "../src/stores.js";
import type { PasskeyUser } from "../src/types.js";

import {
  ADA_HANDLE,
  FakeVerifier,
  ada,
  authenticationResponse,
  makeRelyingParty,
  registrationResponse,
  sequentialBytes,
} from "./helpers.js";

interface Ctx {
  label: string;
}

const CTX: Ctx = { label: "request" };
const NOW = Date.parse("2026-01-01T00:00:00.000Z");

function setup(
  hookOverrides: Partial<PasskeyHooks<Ctx>> = {},
  currentUser: PasskeyUser | null = ada(),
): {
  handlers: PasskeyHandlers<Ctx>;
  server: PasskeyServer;
  verifier: FakeVerifier;
  onAuthenticated: ReturnType<typeof vi.fn>;
} {
  const verifier = new FakeVerifier();
  const server = new PasskeyServer({
    relyingParty: makeRelyingParty(),
    challenges: new InMemoryChallengeStore({ now: () => NOW }),
    credentials: new InMemoryCredentialStore(),
    verifier,
    now: () => NOW,
    randomBytes: sequentialBytes(),
  });

  const onAuthenticated = vi.fn(async () => ({ id: 1, email: "ada@example.com" }));

  const handlers = createPasskeyHandlers<Ctx>(server, {
    currentUser: async () => currentUser,
    onAuthenticated,
    ...hookOverrides,
  });

  return { handlers, server, verifier, onAuthenticated };
}

describe("registerOptions", () => {
  it("answers 200 with a state and an options payload", async () => {
    const { handlers } = setup();
    const result = await handlers.registerOptions({ ctx: CTX });

    expect(result.status).toBe(200);
    expect(result.body).toMatchObject({ state: expect.any(String) });
  });

  it("answers 401 when nobody is signed in", async () => {
    // Enrollment happens on an authenticated user: v1 has no passkey-only
    // signup. Real auth middleware belongs in front of these routes; this is
    // the backstop.
    const { handlers } = setup({}, null);
    const result = await handlers.registerOptions({ ctx: CTX });

    expect(result.status).toBe(401);
  });
});

describe("register", () => {
  it("answers 201 with the credential summary and never the public key", async () => {
    const { handlers } = setup();
    const options = await handlers.registerOptions({ ctx: CTX });
    const state = (options.body as { state: string }).state;

    const result = await handlers.register({
      ctx: CTX,
      body: { state, name: "MacBook", response: registrationResponse("cred-1") },
    });

    expect(result.status).toBe(201);
    expect(result.body).toMatchObject({ credential: { id: "cred-1", name: "MacBook" } });
    expect(JSON.stringify(result.body)).not.toContain("publicKey");
  });

  it("turns a PasskeyError into its status and wire body", async () => {
    const { handlers } = setup();
    const result = await handlers.register({
      ctx: CTX,
      body: { state: "never-issued", response: registrationResponse("cred-1") },
    });

    expect(result).toEqual({
      status: 400,
      body: {
        error: {
          code: "challenge_not_found",
          message: "No passkey challenge is in flight for this request.",
        },
      },
    });
  });

  it("rejects a malformed body as invalid_response", async () => {
    const { handlers } = setup();

    for (const body of [undefined, {}, { state: "x" }, { state: "x", response: "nope" }, []]) {
      const result = await handlers.register({ ctx: CTX, body });
      expect(result.status).toBe(400);
      expect(result.body).toMatchObject({ error: { code: "invalid_response" } });
    }
  });
});

describe("loginOptions", () => {
  it("answers 200 with an empty allowCredentials for an unknown email", async () => {
    // NOT a 404. A 404 here turns the login form into a user-enumeration
    // oracle: an attacker learns which addresses have accounts by typing them
    // in. (The timing difference of the lookup itself is not closed in v1 —
    // the README says so plainly rather than implying a guarantee.)
    const resolveUserByEmail = vi.fn(async () => null);
    const { handlers } = setup({ resolveUserByEmail });

    const result = await handlers.loginOptions({ ctx: CTX, body: { email: "nobody@example.com" } });

    expect(result.status).toBe(200);
    expect(result.body).toMatchObject({
      state: expect.any(String),
      publicKey: { allowCredentials: [], rpId: "example.com" },
    });
    expect(resolveUserByEmail).toHaveBeenCalledWith("nobody@example.com", CTX);
  });

  it("answers identically when no email is supplied at all", async () => {
    const { handlers } = setup();
    const result = await handlers.loginOptions({ ctx: CTX, body: {} });

    expect(result.status).toBe(200);
    expect(result.body).toMatchObject({ publicKey: { allowCredentials: [] } });
  });

  it("fills allowCredentials for a known user", async () => {
    const { handlers } = setup({ resolveUserByEmail: async () => ada() });

    const options = await handlers.registerOptions({ ctx: CTX });
    await handlers.register({
      ctx: CTX,
      body: {
        state: (options.body as { state: string }).state,
        response: registrationResponse("cred-1"),
      },
    });

    const result = await handlers.loginOptions({ ctx: CTX, body: { email: "ada@example.com" } });
    expect(result.body).toMatchObject({
      publicKey: { allowCredentials: [{ id: "cred-1", type: "public-key" }] },
    });
  });
});

describe("login", () => {
  it("answers 200 with whatever onAuthenticated returned", async () => {
    const { handlers, verifier, onAuthenticated } = setup({
      resolveUserByEmail: async () => ada(),
    });

    const registerOptions = await handlers.registerOptions({ ctx: CTX });
    await handlers.register({
      ctx: CTX,
      body: {
        state: (registerOptions.body as { state: string }).state,
        response: registrationResponse("cred-1"),
      },
    });

    const loginOptions = await handlers.loginOptions({ ctx: CTX, body: {} });
    verifier.newCounter = 9;

    const result = await handlers.login({
      ctx: CTX,
      body: {
        state: (loginOptions.body as { state: string }).state,
        response: authenticationResponse("cred-1", ADA_HANDLE),
      },
    });

    expect(result.status).toBe(200);
    expect(result.body).toMatchObject({
      user: { id: 1, email: "ada@example.com" },
      credential: { id: "cred-1" },
    });
    expect(onAuthenticated).toHaveBeenCalledWith(
      ADA_HANDLE,
      expect.objectContaining({ id: "cred-1" }),
      CTX,
    );
  });

  it("answers 401 for an unknown credential, indistinguishably from a bad signature", async () => {
    const { handlers, verifier } = setup();

    const unknown = await handlers.loginOptions({ ctx: CTX, body: {} });
    const unknownResult = await handlers.login({
      ctx: CTX,
      body: {
        state: (unknown.body as { state: string }).state,
        response: authenticationResponse("never-enrolled"),
      },
    });

    // Now the same client-visible answer, produced by a genuinely failed
    // signature check on a credential that DOES exist.
    const registerOptions = await handlers.registerOptions({ ctx: CTX });
    await handlers.register({
      ctx: CTX,
      body: {
        state: (registerOptions.body as { state: string }).state,
        response: registrationResponse("cred-1"),
      },
    });
    verifier.newCounter = 9;
    verifier.authenticationVerified = false;

    const bad = await handlers.loginOptions({ ctx: CTX, body: {} });
    const badResult = await handlers.login({
      ctx: CTX,
      body: {
        state: (bad.body as { state: string }).state,
        response: authenticationResponse("cred-1"),
      },
    });

    expect(unknownResult.status).toBe(badResult.status);
    expect((unknownResult.body as { error: { message: string } }).error.message).toBe(
      (badResult.body as { error: { message: string } }).error.message,
    );
  });

  it("does not call onAuthenticated when verification fails", async () => {
    const { handlers, onAuthenticated } = setup();

    const options = await handlers.loginOptions({ ctx: CTX, body: {} });
    await handlers.login({
      ctx: CTX,
      body: {
        state: (options.body as { state: string }).state,
        response: authenticationResponse("never-enrolled"),
      },
    });

    expect(onAuthenticated).not.toHaveBeenCalled();
  });

  it("lets a non-PasskeyError through rather than dressing it as a 4xx", async () => {
    // A dropped database connection is the app's 500 and should be logged and
    // alerted on, not quietly rendered as "your passkey did not work".
    const { handlers, verifier } = setup();

    const registerOptions = await handlers.registerOptions({ ctx: CTX });
    await handlers.register({
      ctx: CTX,
      body: {
        state: (registerOptions.body as { state: string }).state,
        response: registrationResponse("cred-1"),
      },
    });

    verifier.authenticationError = new RangeError("the database fell over");
    const options = await handlers.loginOptions({ ctx: CTX, body: {} });

    // RangeError's message matches no probe, so it maps to verification_failed
    // — mapVerificationError never lets anything escape from the ceremony. The
    // genuinely-out-of-band failure is the hook throwing.
    const mapped = await handlers.login({
      ctx: CTX,
      body: {
        state: (options.body as { state: string }).state,
        response: authenticationResponse("cred-1"),
      },
    });
    expect(mapped.status).toBe(401);

    const throwing = createPasskeyHandlers<Ctx>(
      new PasskeyServer({
        relyingParty: makeRelyingParty(),
        challenges: new InMemoryChallengeStore(),
        credentials: new InMemoryCredentialStore(),
      }),
      {
        currentUser: () => {
          throw new RangeError("the database fell over");
        },
        onAuthenticated: async () => null,
      },
    );

    await expect(throwing.registerOptions({ ctx: CTX })).rejects.toBeInstanceOf(RangeError);
  });
});
