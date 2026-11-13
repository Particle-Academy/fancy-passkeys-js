import { readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import type { RegistrationResponseJSON } from "@simplewebauthn/server";
import { describe, expect, it } from "vitest";

import { toBase64Url } from "../src/encoding.js";
import { PasskeyError } from "../src/errors.js";
import { PasskeyServer } from "../src/server.js";
import { InMemoryChallengeStore, InMemoryCredentialStore } from "../src/stores.js";
import type { PasskeyErrorCode } from "../src/types.js";

import { ADA_HANDLE, ada, makeRelyingParty, makeStoredCredential, realisticAssertion } from "./helpers.js";

/**
 * The error contract shared with the PHP twin, from
 * `tests/fixtures/errors/codes.json` (byte-identical in both repos).
 *
 * The fixture exists because the two backends had drifted on a named failure:
 * the `passkeys` lab benchmark (2026-11-13) saw a wrong-origin assertion answer
 * `origin_not_allowed` 400 from Node and `verification_failed` 401 from PHP.
 * One React surface sits in front of either backend, so the answer is part of
 * the wire contract, not an implementation detail.
 *
 * The ceremonies run against the REAL `@simplewebauthn/server`: a wrong origin
 * is exactly the kind of check a fake verifier would answer however the test
 * told it to.
 */
interface Fixture {
  codes: Record<PasskeyErrorCode, { status: number; wire: PasskeyErrorCode }>;
  ceremonies: Array<{
    name: string;
    ceremony: "authentication" | "registration";
    credential: "registered" | "unknown" | "new";
    clientDataOrigin: string;
    code: PasskeyErrorCode;
    status: number;
  }>;
}

const fixture = JSON.parse(
  readFileSync(resolve(dirname(fileURLToPath(import.meta.url)), "fixtures", "errors", "codes.json"), "utf8"),
) as Fixture;

const CREDENTIAL_ID = "Y3JlZC1vbmU";

function realServer(): PasskeyServer {
  return new PasskeyServer({
    relyingParty: makeRelyingParty(),
    challenges: new InMemoryChallengeStore(),
    credentials: new InMemoryCredentialStore([makeStoredCredential({ id: CREDENTIAL_ID, userHandle: ADA_HANDLE })]),
  });
}

/** A registration response whose client data parses; the attestation never gets read. */
function registrationAt(origin: string, challenge: string): RegistrationResponseJSON {
  const clientData = JSON.stringify({ type: "webauthn.create", challenge, origin, crossOrigin: false });
  return {
    id: "bmV3LWNyZWQ",
    rawId: "bmV3LWNyZWQ",
    type: "public-key",
    clientExtensionResults: {},
    response: {
      clientDataJSON: toBase64Url(new TextEncoder().encode(clientData)),
      attestationObject: toBase64Url(new Uint8Array([0xa0])),
      transports: ["internal"],
    },
  };
}

async function wireOf(fn: () => Promise<unknown>): Promise<{ code: string; status: number }> {
  try {
    await fn();
  } catch (e) {
    if (e instanceof PasskeyError) {
      return { code: e.toJSON().error.code, status: e.httpStatus };
    }
    throw e;
  }
  throw new Error("expected the ceremony to be refused, but it succeeded");
}

describe("the shared error fixture", () => {
  it.each(Object.entries(fixture.codes))("%s answers the fixture's status and wire code", (code, expected) => {
    const error = new PasskeyError(code as PasskeyErrorCode);
    expect(error.httpStatus).toBe(expected.status);
    expect(error.toJSON().error.code).toBe(expected.wire);
  });

  it.each(fixture.ceremonies.map((row) => [row.name, row] as const))("%s", async (_name, row) => {
    const server = realServer();

    const answer =
      row.ceremony === "registration"
        ? await (async () => {
            const started = await server.startRegistration(ada());
            return wireOf(() =>
              server.finishRegistration({
                state: started.state,
                response: registrationAt(row.clientDataOrigin, started.publicKey.challenge),
              }),
            );
          })()
        : await (async () => {
            const started = await server.startAuthentication();
            const credentialId = row.credential === "unknown" ? "bmV2ZXItc2Vlbg" : CREDENTIAL_ID;
            return wireOf(() =>
              server.finishAuthentication({
                state: started.state,
                response: realisticAssertion({
                  credentialId,
                  challenge: started.publicKey.challenge,
                  counter: 1,
                  origin: row.clientDataOrigin,
                }),
              }),
            );
          })();

    expect(answer).toEqual({ code: row.code, status: row.status });
  });
});
