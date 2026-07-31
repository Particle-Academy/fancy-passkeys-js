import { describe, expect, it, vi } from "vitest";

import { toBase64Url } from "../src/encoding.js";
import type { PasskeyPolicy } from "../src/policy.js";
import { PasskeyServer } from "../src/server.js";
import { InMemoryChallengeStore, InMemoryCredentialStore } from "../src/stores.js";
import type { ChallengeStore } from "../src/stores.js";
import type { ChallengeRecord } from "../src/types.js";

import {
  ADA_HANDLE,
  FakeVerifier,
  GRACE_HANDLE,
  ORIGIN,
  RP_ID,
  ada,
  authenticationResponse,
  grace,
  makeRelyingParty,
  registrationResponse,
  sequentialBytes,
} from "./helpers.js";

const START = Date.parse("2026-01-01T00:00:00.000Z");

/**
 * A challenge store with no expiry semantics of its own.
 *
 * Entirely realistic — a `challenges` table with no cleanup job is the first
 * thing most consumers write — and it is why `PasskeyServer` re-checks
 * `expiresAt` instead of trusting `pull()` to have pruned. A store's clock is
 * not the server's clock.
 */
class NoTtlChallengeStore implements ChallengeStore {
  readonly records = new Map<string, ChallengeRecord>();

  put(handle: string, record: ChallengeRecord): Promise<void> {
    this.records.set(handle, { ...record });
    return Promise.resolve();
  }

  pull(handle: string): Promise<ChallengeRecord | null> {
    const record = this.records.get(handle) ?? null;
    this.records.delete(handle);
    return Promise.resolve(record);
  }
}

function setup(
  options: { policy?: Partial<PasskeyPolicy>; challenges?: ChallengeStore } = {},
): {
  server: PasskeyServer;
  verifier: FakeVerifier;
  credentials: InMemoryCredentialStore;
  advance(ms: number): void;
} {
  let clock = START;
  const now = (): number => clock;

  const verifier = new FakeVerifier();
  const credentials = new InMemoryCredentialStore();
  const challenges = options.challenges ?? new InMemoryChallengeStore({ now });

  const server = new PasskeyServer({
    relyingParty: makeRelyingParty(),
    challenges,
    credentials,
    verifier,
    now,
    randomBytes: sequentialBytes(),
    ...(options.policy ? { policy: options.policy } : {}),
  });

  return {
    server,
    verifier,
    credentials,
    advance: (ms: number) => {
      clock += ms;
    },
  };
}

describe("registration", () => {
  it("issues options and persists the credential", async () => {
    const { server, verifier, credentials } = setup();

    const started = await server.startRegistration(ada());
    expect(started.state).toMatch(/^[A-Za-z0-9_-]+$/);
    expect(started.publicKey.rp).toEqual({ id: RP_ID, name: "Example App" });
    expect(started.publicKey.user.id).toBe(ADA_HANDLE);
    expect(started.publicKey.excludeCredentials).toEqual([]);

    const { credential, summary } = await server.finishRegistration({
      state: started.state,
      response: registrationResponse("cred-1", ["internal", "hybrid"]),
      name: "MacBook Touch ID",
    });

    expect(credential).toMatchObject({
      id: "cred-1",
      userHandle: ADA_HANDLE,
      name: "MacBook Touch ID",
      publicKey: toBase64Url(new Uint8Array([9, 8, 7, 6])),
      transports: ["internal", "hybrid"],
      backedUp: true,
      backupEligible: true,
      attestationFormat: "none",
      createdAt: "2026-01-01T00:00:00.000Z",
      lastUsedAt: null,
      clonedAt: null,
    });

    // The summary is what reaches a browser, and it must never carry key material.
    expect(summary).not.toHaveProperty("publicKey");
    expect(summary).not.toHaveProperty("userHandle");

    await expect(credentials.findById("cred-1")).resolves.not.toBeNull();

    // The expectations handed to the verifier come from config, never from the
    // request: an allow-list of origins and an explicit RP ID.
    expect(verifier.lastRegistrationOpts).toMatchObject({
      expectedChallenge: started.publicKey.challenge,
      expectedOrigin: [ORIGIN],
      expectedRPID: RP_ID,
    });
  });

  it("populates excludeCredentials from the user's existing passkeys", async () => {
    const { server } = setup();

    const first = await server.startRegistration(ada());
    await server.finishRegistration({
      state: first.state,
      response: registrationResponse("cred-1", ["internal"]),
    });

    const second = await server.startRegistration(ada());
    expect(second.publicKey.excludeCredentials).toEqual([
      { id: "cred-1", type: "public-key", transports: ["internal"] },
    ]);
  });

  it("rejects a replayed finish with challenge_not_found", async () => {
    // The challenge is pulled BEFORE anything is verified, so the second
    // attempt dies at "no such challenge" no matter how valid it looks.
    const { server } = setup();

    const started = await server.startRegistration(ada());
    const response = registrationResponse("cred-1");
    await server.finishRegistration({ state: started.state, response });

    await expect(
      server.finishRegistration({ state: started.state, response }),
    ).rejects.toMatchObject({ code: "challenge_not_found" });
  });

  it("rejects an expired challenge even when the store did not prune it", async () => {
    const challenges = new NoTtlChallengeStore();
    const { server, advance } = setup({ challenges, policy: { challengeTtlSeconds: 300 } });

    const started = await server.startRegistration(ada());
    advance(300_001);

    await expect(
      server.finishRegistration({ state: started.state, response: registrationResponse("cred-1") }),
    ).rejects.toMatchObject({ code: "challenge_expired" });
  });

  it("refuses an authentication challenge", async () => {
    const { server } = setup();
    const started = await server.startAuthentication();

    await expect(
      server.finishRegistration({ state: started.state, response: registrationResponse("cred-1") }),
    ).rejects.toMatchObject({ code: "challenge_type_mismatch" });
  });

  it("refuses a credential id already registered to another account", async () => {
    // Cross-user reuse. Re-pointing an existing credential id at a new account
    // is account takeover, so the uniqueness check spans every user.
    const { server } = setup();

    const adaStart = await server.startRegistration(ada());
    await server.finishRegistration({
      state: adaStart.state,
      response: registrationResponse("shared-cred"),
    });

    const graceStart = await server.startRegistration(grace());
    await expect(
      server.finishRegistration({
        state: graceStart.state,
        response: registrationResponse("shared-cred"),
      }),
    ).rejects.toMatchObject({ code: "credential_already_registered" });
  });

  it("maps a thrown library error instead of letting it escape as a 500", async () => {
    const { server, verifier } = setup();
    verifier.registrationError = new Error(
      'Unexpected registration response origin "https://evil.example", expected "https://example.com"',
    );

    const started = await server.startRegistration(ada());
    await expect(
      server.finishRegistration({ state: started.state, response: registrationResponse("cred-1") }),
    ).rejects.toMatchObject({ code: "origin_not_allowed", httpStatus: 400 });
  });

  it("treats verified:false as a verification failure", async () => {
    const { server, verifier } = setup();
    verifier.registrationVerified = false;

    const started = await server.startRegistration(ada());
    await expect(
      server.finishRegistration({ state: started.state, response: registrationResponse("cred-1") }),
    ).rejects.toMatchObject({ code: "verification_failed" });
  });
});

describe("authentication", () => {
  async function enroll(
    server: PasskeyServer,
    verifier: FakeVerifier,
    credentialId: string,
    user = ada(),
    counter = 1,
  ): Promise<void> {
    verifier.newCounter = counter;
    const started = await server.startRegistration(user);
    await server.finishRegistration({
      state: started.state,
      response: registrationResponse(credentialId),
    });
  }

  it("verifies an assertion and reports the account", async () => {
    const { server, verifier } = setup();
    await enroll(server, verifier, "cred-1");

    const started = await server.startAuthentication();
    // Discoverable flow: no username was supplied, so the browser picks.
    expect(started.publicKey.allowCredentials).toEqual([]);

    verifier.newCounter = 5;
    const result = await server.finishAuthentication({
      state: started.state,
      response: authenticationResponse("cred-1", ADA_HANDLE),
    });

    expect(result.userHandle).toBe(ADA_HANDLE);
    expect(result.credential.signCount).toBe(5);
    expect(result.credential.lastUsedAt).toBe("2026-01-01T00:00:00.000Z");
    expect(result.summary.id).toBe("cred-1");
  });

  it("fills allowCredentials for the username-first flow", async () => {
    const { server, verifier } = setup();
    await enroll(server, verifier, "cred-1");

    const started = await server.startAuthentication({ userHandle: ADA_HANDLE });
    expect(started.publicKey.allowCredentials).toEqual([
      { id: "cred-1", type: "public-key", transports: ["internal"] },
    ]);
  });

  it("emits an empty allowCredentials for a user with no passkeys", async () => {
    // Indistinguishable from the discoverable flow on purpose: this is what
    // stops the username-first endpoint being a user-enumeration oracle.
    const { server } = setup();

    const started = await server.startAuthentication({ userHandle: GRACE_HANDLE });
    expect(started.publicKey.allowCredentials).toEqual([]);
  });

  it("rejects a replayed finish with challenge_not_found", async () => {
    const { server, verifier } = setup();
    await enroll(server, verifier, "cred-1");

    const started = await server.startAuthentication();
    verifier.newCounter = 5;
    const response = authenticationResponse("cred-1");
    await server.finishAuthentication({ state: started.state, response });

    verifier.newCounter = 6;
    await expect(
      server.finishAuthentication({ state: started.state, response }),
    ).rejects.toMatchObject({ code: "challenge_not_found" });
  });

  it("rejects an expired challenge even when the store did not prune it", async () => {
    const challenges = new NoTtlChallengeStore();
    const { server, verifier, advance } = setup({ challenges });
    await enroll(server, verifier, "cred-1");

    const started = await server.startAuthentication();
    advance(300_001);

    await expect(
      server.finishAuthentication({
        state: started.state,
        response: authenticationResponse("cred-1"),
      }),
    ).rejects.toMatchObject({ code: "challenge_expired" });
  });

  it("refuses a registration challenge", async () => {
    const { server } = setup();
    const started = await server.startRegistration(ada());

    await expect(
      server.finishAuthentication({
        state: started.state,
        response: authenticationResponse("cred-1"),
      }),
    ).rejects.toMatchObject({ code: "challenge_type_mismatch" });
  });

  it("rejects an unknown credential", async () => {
    const { server } = setup();
    const started = await server.startAuthentication();

    await expect(
      server.finishAuthentication({
        state: started.state,
        response: authenticationResponse("never-enrolled"),
      }),
    ).rejects.toMatchObject({ code: "unknown_credential" });
  });

  it("rejects a credential that does not belong to the challenged account", async () => {
    const { server, verifier } = setup();
    await enroll(server, verifier, "ada-cred", ada());

    // Username-first: we issued the challenge for Grace, Ada's key answered.
    const started = await server.startAuthentication({ userHandle: GRACE_HANDLE });
    await expect(
      server.finishAuthentication({
        state: started.state,
        response: authenticationResponse("ada-cred"),
      }),
    ).rejects.toMatchObject({ code: "user_handle_mismatch" });
  });

  it("rejects an asserted user handle that is not the stored one", async () => {
    const { server, verifier } = setup();
    await enroll(server, verifier, "ada-cred", ada());

    // Discoverable: the authenticator reported a handle, and it is not ours.
    const started = await server.startAuthentication();
    await expect(
      server.finishAuthentication({
        state: started.state,
        response: authenticationResponse("ada-cred", GRACE_HANDLE),
      }),
    ).rejects.toMatchObject({ code: "user_handle_mismatch" });
  });

  it("persists the counter on success — including when it is 0", async () => {
    // The most common silent defeat of clone detection: skip the zero case and
    // the stored value never advances, so every comparison is against 0 and the
    // check can never fire. Most synced passkeys report 0 forever.
    const { server, verifier, credentials } = setup();
    await enroll(server, verifier, "cred-1", ada(), 0);

    const spy = vi.spyOn(credentials, "updateAfterAuthentication");

    const started = await server.startAuthentication();
    verifier.newCounter = 0;
    await server.finishAuthentication({
      state: started.state,
      response: authenticationResponse("cred-1"),
    });

    expect(spy).toHaveBeenCalledWith("cred-1", 0, "2026-01-01T00:00:00.000Z");
    await expect(credentials.findById("cred-1")).resolves.toMatchObject({
      signCount: 0,
      lastUsedAt: "2026-01-01T00:00:00.000Z",
    });
  });

  it("persists an advancing counter", async () => {
    const { server, verifier, credentials } = setup();
    await enroll(server, verifier, "cred-1", ada(), 3);

    const started = await server.startAuthentication();
    verifier.newCounter = 11;
    await server.finishAuthentication({
      state: started.state,
      response: authenticationResponse("cred-1"),
    });

    await expect(credentials.findById("cred-1")).resolves.toMatchObject({ signCount: 11 });
  });

  it("treats verified:false as a verification failure", async () => {
    const { server, verifier } = setup();
    await enroll(server, verifier, "cred-1");

    const started = await server.startAuthentication();
    verifier.newCounter = 5;
    verifier.authenticationVerified = false;

    await expect(
      server.finishAuthentication({
        state: started.state,
        response: authenticationResponse("cred-1"),
      }),
    ).rejects.toMatchObject({ code: "verification_failed" });
  });
});

describe("listPasskeys", () => {
  it("returns client-safe summaries for one account only", async () => {
    const { server, verifier } = setup();

    const adaStart = await server.startRegistration(ada());
    await server.finishRegistration({
      state: adaStart.state,
      response: registrationResponse("ada-cred"),
      name: "Ada's laptop",
    });

    verifier.newCounter = 1;
    const graceStart = await server.startRegistration(grace());
    await server.finishRegistration({
      state: graceStart.state,
      response: registrationResponse("grace-cred"),
    });

    const summaries = await server.listPasskeys(ADA_HANDLE);
    expect(summaries).toEqual([
      {
        id: "ada-cred",
        name: "Ada's laptop",
        createdAt: "2026-01-01T00:00:00.000Z",
        lastUsedAt: null,
        transports: ["internal"],
        backedUp: true,
        aaguid: "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
        clonedAt: null,
      },
    ]);
  });
});

describe("input validation", () => {
  it("refuses a user handle that is not base64url", async () => {
    // A programmer error in the host app, not an authentication failure — the
    // app mints handles, a request never does.
    const { server } = setup();

    await expect(
      server.startRegistration({ handle: "not base64url!", name: "x", displayName: "x" }),
    ).rejects.toBeInstanceOf(TypeError);
  });

  it("refuses an empty state handle", async () => {
    const { server } = setup();

    await expect(
      server.finishAuthentication({ state: "", response: authenticationResponse("cred-1") }),
    ).rejects.toMatchObject({ code: "invalid_response" });
  });
});
