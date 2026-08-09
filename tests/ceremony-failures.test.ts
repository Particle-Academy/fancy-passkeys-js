import { describe, expect, it } from "vitest";

import { PasskeyError } from "../src/errors.js";
import { PasskeyServer } from "../src/server.js";
import { InMemoryChallengeStore, InMemoryCredentialStore } from "../src/stores.js";
import {
  ADA_HANDLE,
  FakeVerifier,
  ada,
  authenticationResponse,
  makeRelyingParty,
  makeStoredCredential,
  registrationResponse,
  sequentialBytes,
} from "./helpers.js";

const NOW = Date.parse("2026-01-01T00:00:00.000Z");

function setup() {
  const verifier = new FakeVerifier();
  const credentials = new InMemoryCredentialStore([makeStoredCredential({ id: "cred-1" })]);

  const server = new PasskeyServer({
    relyingParty: makeRelyingParty(),
    challenges: new InMemoryChallengeStore({ now: () => NOW }),
    credentials,
    verifier,
    now: () => NOW,
    randomBytes: sequentialBytes(),
  });

  return { server, verifier, credentials };
}

async function codeOf(fn: () => Promise<unknown>): Promise<string> {
  try {
    await fn();
  } catch (e) {
    if (e instanceof PasskeyError) return e.code;
    throw e;
  }
  throw new Error("expected the ceremony to be rejected, but it succeeded");
}

/**
 * Ceremony-type mismatch and wrong origin.
 *
 * The PHP twin has covered both since it shipped (`CeremonyFailureTest`,
 * `OriginValidationTest`); this side had the error CODES and the enforcing
 * branches but nothing exercising them. That asymmetry is the thing story #167
 * calls out — a failure path is only tested if it is tested on BOTH backends,
 * because a passkey implementation is judged on exactly these.
 */
describe("ceremony-type mismatch", () => {
  it("refuses a REGISTRATION challenge redeemed at the authentication endpoint", async () => {
    // The attack this blocks: a challenge minted for one ceremony being spent
    // on the other, which would let a registration flow mint an authenticated
    // session.
    const { server } = setup();
    const started = await server.startRegistration(ada());

    const code = await codeOf(() =>
      server.finishAuthentication({
        state: started.state,
        response: authenticationResponse("cred-1", ADA_HANDLE),
      }),
    );

    expect(code).toBe("challenge_type_mismatch");
  });

  it("refuses an AUTHENTICATION challenge redeemed at the registration endpoint", async () => {
    const { server } = setup();
    const started = await server.startAuthentication();

    const code = await codeOf(() =>
      server.finishRegistration({
        state: started.state,
        response: registrationResponse("cred-new"),
      }),
    );

    expect(code).toBe("challenge_type_mismatch");
  });

  it("consumes the challenge even when the type is wrong", async () => {
    // A rejected challenge must still be spent. Leaving it redeemable turns a
    // type mismatch into an oracle an attacker can retry against.
    const { server } = setup();
    const started = await server.startRegistration(ada());

    await codeOf(() =>
      server.finishAuthentication({
        state: started.state,
        response: authenticationResponse("cred-1", ADA_HANDLE),
      }),
    );

    // The correct endpoint now also fails — the challenge is gone, not merely
    // misrouted.
    const second = await codeOf(() =>
      server.finishRegistration({ state: started.state, response: registrationResponse("cred-new") }),
    );

    expect(second).toBe("challenge_not_found");
  });
});

describe("wrong origin", () => {
  it("rejects a response from an origin the relying party does not list", async () => {
    // The phishing defence. A credential is bound to an origin, so a response
    // arriving from evil.example must not verify however well-formed it is.
    const { server, verifier } = setup();
    const started = await server.startAuthentication();

    verifier.authenticationError = new Error('Unexpected authentication response origin "https://evil.example", expected "https://example.com"');

    const code = await codeOf(() =>
      server.finishAuthentication({
        state: started.state,
        response: authenticationResponse("cred-1", ADA_HANDLE),
      }),
    );

    expect(code).toBe("origin_not_allowed");
  });

  it("rejects a mismatched RP ID distinctly from a mismatched origin", async () => {
    // Different codes because they are different misconfigurations: one is a
    // wrong site, the other a wrong relying-party identifier on the right site.
    const { server, verifier } = setup();
    const started = await server.startAuthentication();

    verifier.authenticationError = new Error("Unexpected RP ID hash");

    const code = await codeOf(() =>
      server.finishAuthentication({
        state: started.state,
        response: authenticationResponse("cred-1", ADA_HANDLE),
      }),
    );

    expect(code).toBe("rp_id_mismatch");
  });
});
