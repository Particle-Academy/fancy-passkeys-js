import { describe, expect, it, vi } from "vitest";

import { PasskeyError } from "../src/errors.js";
import type { CounterPolicy } from "../src/policy.js";
import { PasskeyServer } from "../src/server.js";
import { InMemoryChallengeStore, InMemoryCredentialStore } from "../src/stores.js";

import {
  ADA_HANDLE,
  FakeVerifier,
  ada,
  authenticationResponse,
  makeRelyingParty,
  makeStoredCredential,
  realisticAssertion,
  registrationResponse,
  sequentialBytes,
} from "./helpers.js";

const NOW = Date.parse("2026-01-01T00:00:00.000Z");
const NOW_ISO = "2026-01-01T00:00:00.000Z";

function setup(counterPolicy: CounterPolicy, storedCount: number): {
  server: PasskeyServer;
  verifier: FakeVerifier;
  credentials: InMemoryCredentialStore;
} {
  const verifier = new FakeVerifier();
  const credentials = new InMemoryCredentialStore([
    makeStoredCredential({ id: "cred-1", signCount: storedCount }),
  ]);

  const server = new PasskeyServer({
    relyingParty: makeRelyingParty(),
    policy: { counterPolicy },
    challenges: new InMemoryChallengeStore({ now: () => NOW }),
    credentials,
    verifier,
    now: () => NOW,
    randomBytes: sequentialBytes(),
  });

  return { server, verifier, credentials };
}

async function authenticate(
  server: PasskeyServer,
  verifier: FakeVerifier,
  reportedCounter: number,
): Promise<unknown> {
  const started = await server.startAuthentication();
  verifier.newCounter = reportedCounter;
  return server.finishAuthentication({
    state: started.state,
    response: authenticationResponse("cred-1", ADA_HANDLE),
  });
}

describe("counterPolicy: reject (the default)", () => {
  it("is the default", () => {
    const { server } = setup("reject", 0);
    expect(server.policy.counterPolicy).toBe("reject");
  });

  it("fails the login AND flags the credential when the counter goes backwards", async () => {
    // Both halves matter. The counter is a one-shot detector: fail the login
    // without recording it and the real device's next attempt succeeds, leaving
    // no trace that anything was ever wrong.
    const { server, verifier, credentials } = setup("reject", 7);
    const flagged = vi.spyOn(credentials, "flagCloned");

    await expect(authenticate(server, verifier, 3)).rejects.toMatchObject({
      code: "counter_regressed",
      httpStatus: 401,
    });

    expect(flagged).toHaveBeenCalledWith("cred-1", NOW_ISO);
    await expect(credentials.findById("cred-1")).resolves.toMatchObject({ clonedAt: NOW_ISO });
  });

  it("treats an equal counter as a regression", async () => {
    const { server, verifier } = setup("reject", 7);
    await expect(authenticate(server, verifier, 7)).rejects.toMatchObject({
      code: "counter_regressed",
    });
  });

  it("does not advance the stored counter on a rejected login", async () => {
    const { server, verifier, credentials } = setup("reject", 7);
    await expect(authenticate(server, verifier, 3)).rejects.toThrow();

    await expect(credentials.findById("cred-1")).resolves.toMatchObject({ signCount: 7 });
  });

  it("accepts both counters at zero", async () => {
    // Most synced passkey providers — iCloud Keychain, Google Password Manager —
    // do not implement counters and always report 0. A strict `new > stored`
    // rule would reject the majority of real passkeys in the world.
    const { server, verifier, credentials } = setup("reject", 0);
    const flagged = vi.spyOn(credentials, "flagCloned");

    await expect(authenticate(server, verifier, 0)).resolves.toMatchObject({
      userHandle: ADA_HANDLE,
    });
    expect(flagged).not.toHaveBeenCalled();
  });

  it("accepts an advancing counter", async () => {
    const { server, verifier, credentials } = setup("reject", 7);
    await expect(authenticate(server, verifier, 8)).resolves.toBeTruthy();
    await expect(credentials.findById("cred-1")).resolves.toMatchObject({
      signCount: 8,
      clonedAt: null,
    });
  });
});

describe("counterPolicy: ignore", () => {
  it("lets the login through and records nothing", async () => {
    // "Ignore" means clone detection is off. Nothing is flagged, so there is no
    // signal left anywhere — which is exactly why the option's documentation
    // says "this disables clone detection" in those words.
    const { server, verifier, credentials } = setup("ignore", 7);
    const flagged = vi.spyOn(credentials, "flagCloned");

    await expect(authenticate(server, verifier, 3)).resolves.toMatchObject({
      userHandle: ADA_HANDLE,
    });

    expect(flagged).not.toHaveBeenCalled();
    await expect(credentials.findById("cred-1")).resolves.toMatchObject({
      clonedAt: null,
      // Persisted regardless: the wrapper's job is to record what the
      // authenticator said, and the policy only decides whether to object.
      signCount: 3,
    });
  });
});

describe("counterPolicy: log-only", () => {
  it("lets the login through but still flags the credential", async () => {
    const { server, verifier, credentials } = setup("log-only", 7);
    const flagged = vi.spyOn(credentials, "flagCloned");

    const result = await authenticate(server, verifier, 3);
    expect(result).toMatchObject({ userHandle: ADA_HANDLE });

    expect(flagged).toHaveBeenCalledWith("cred-1", NOW_ISO);
    await expect(credentials.findById("cred-1")).resolves.toMatchObject({ clonedAt: NOW_ISO });
  });

  it("does not flag a healthy counter", async () => {
    const { server, verifier, credentials } = setup("log-only", 7);
    const flagged = vi.spyOn(credentials, "flagCloned");

    await authenticate(server, verifier, 9);
    expect(flagged).not.toHaveBeenCalled();
  });
});

describe("the real library's counter check", () => {
  /**
   * `counterPolicy: 'reject'` deliberately lets `@simplewebauthn/server` do the
   * counter check and maps the `Error` it throws. That mapping is a string
   * match, so this test drives the **real** library — not the fake — far enough
   * to throw it, using a hand-assembled assertion. If v13 ever rewords the
   * message, `mapVerificationError` would quietly downgrade a clone detection
   * to a generic failure and stop flagging; this fails instead.
   */
  it("still throws the message the clone flag depends on", async () => {
    const credentials = new InMemoryCredentialStore([
      makeStoredCredential({ id: "cred-1", signCount: 7 }),
    ]);
    const server = new PasskeyServer({
      relyingParty: makeRelyingParty(),
      challenges: new InMemoryChallengeStore({ now: () => NOW }),
      credentials,
      now: () => NOW,
      randomBytes: sequentialBytes(),
      // No `verifier` — the real @simplewebauthn/server.
    });

    const started = await server.startAuthentication();

    const error = (await server
      .finishAuthentication({
        state: started.state,
        response: realisticAssertion({
          credentialId: "cred-1",
          challenge: started.publicKey.challenge,
          counter: 3,
        }),
      })
      .catch((err: unknown) => err)) as PasskeyError;

    expect(error).toBeInstanceOf(PasskeyError);
    expect(error.code).toBe("counter_regressed");
    // The exact upstream wording, straight off the real library. This is the
    // string `mapVerificationError` matches on, and it is preserved on `cause`
    // (never on `message`, which reaches the client).
    expect((error.cause as Error).message).toBe(
      "Response counter value 3 was lower than expected 7",
    );
    expect(error.message).not.toContain("counter value");

    await expect(credentials.findById("cred-1")).resolves.toMatchObject({ clonedAt: NOW_ISO });
  });
});

describe("registration seeds the counter", () => {
  it("stores whatever the authenticator reported at enrollment", async () => {
    const verifier = new FakeVerifier();
    verifier.newCounter = 42;
    const credentials = new InMemoryCredentialStore();
    const server = new PasskeyServer({
      relyingParty: makeRelyingParty(),
      challenges: new InMemoryChallengeStore({ now: () => NOW }),
      credentials,
      verifier,
      now: () => NOW,
      randomBytes: sequentialBytes(),
    });

    const started = await server.startRegistration(ada());
    await server.finishRegistration({
      state: started.state,
      response: registrationResponse("fresh-cred"),
    });

    await expect(credentials.findById("fresh-cred")).resolves.toMatchObject({ signCount: 42 });
  });
});
