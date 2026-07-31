import { describe, expect, it } from "vitest";

import { PasskeyError, mapVerificationError } from "../src/errors.js";
import type { PasskeyErrorCode } from "../src/types.js";

const ALL_CODES: PasskeyErrorCode[] = [
  "challenge_expired",
  "challenge_not_found",
  "challenge_type_mismatch",
  "origin_not_allowed",
  "rp_id_mismatch",
  "unknown_credential",
  "credential_already_registered",
  "counter_regressed",
  "user_verification_required",
  "user_handle_mismatch",
  "verification_failed",
  "invalid_response",
  "not_supported",
];

/**
 * The exact strings `@simplewebauthn/server` v13.3.2 throws.
 *
 * Copied from the library source rather than paraphrased: these ARE the
 * discriminant — v13 throws bare `Error`s with nothing else to switch on — so a
 * paraphrase here would test the paraphrase.
 */
const UPSTREAM_MESSAGES: [message: string, code: PasskeyErrorCode][] = [
  ["Response counter value 3 was lower than expected 7", "counter_regressed"],
  [
    'Unexpected authentication response origin "https://evil.example", expected "https://example.com"',
    "origin_not_allowed",
  ],
  [
    'Unexpected registration response origin "https://evil.example", expected one of: https://example.com',
    "origin_not_allowed",
  ],
  ["Unexpected RP ID hash", "rp_id_mismatch"],
  [
    'Unexpected authentication response challenge "abc", expected "def"',
    "verification_failed",
  ],
  ['Unexpected registration response challenge "abc", expected "def"', "verification_failed"],
  [
    'Custom challenge verifier returned false for registration response challenge "abc"',
    "verification_failed",
  ],
  ["User verification required, but user could not be verified", "user_verification_required"],
  ["User verification was required, but user could not be verified", "user_verification_required"],
];

describe("PasskeyError", () => {
  it("maps every code to a 4xx", () => {
    // A 5xx for "that login is not valid" is both a lie and, because the stack
    // differs per failure mode, an oracle.
    for (const code of ALL_CODES) {
      const error = new PasskeyError(code);
      expect(error.httpStatus, code).toBeGreaterThanOrEqual(400);
      expect(error.httpStatus, code).toBeLessThan(500);
    }
  });

  it("uses 401 for authentication failures and 409 for the one conflict", () => {
    expect(new PasskeyError("credential_already_registered").httpStatus).toBe(409);
    expect(new PasskeyError("verification_failed").httpStatus).toBe(401);
    expect(new PasskeyError("unknown_credential").httpStatus).toBe(401);
    expect(new PasskeyError("counter_regressed").httpStatus).toBe(401);
    expect(new PasskeyError("challenge_expired").httpStatus).toBe(400);
  });

  it("gives unknown_credential and verification_failed identical client-visible answers", () => {
    // A distinct "we have never seen that credential" reply is a
    // credential-existence oracle: it sorts a stolen list into "registered
    // here" and "not". The two must be indistinguishable on the wire.
    const unknown = new PasskeyError("unknown_credential");
    const failed = new PasskeyError("verification_failed");

    expect(unknown.message).toBe(failed.message);
    expect(unknown.httpStatus).toBe(failed.httpStatus);
    expect(unknown.toJSON().error.message).toBe(failed.toJSON().error.message);
  });

  it("serialises to the wire error body and nothing else", () => {
    const error = new PasskeyError("challenge_expired", { cause: new Error("secret internals") });

    expect(error.toJSON()).toEqual({
      error: {
        code: "challenge_expired",
        message: "The passkey challenge has expired. Start again.",
      },
    });
    expect(JSON.parse(JSON.stringify(error))).toEqual(error.toJSON());
  });

  it("keeps the cause non-enumerable so a logger cannot leak it by accident", () => {
    const cause = new Error("Unexpected RP ID hash");
    const error = new PasskeyError("rp_id_mismatch", { cause });

    expect(error.cause).toBe(cause);
    expect(Object.keys(error)).not.toContain("cause");
    expect(Object.prototype.propertyIsEnumerable.call(error, "cause")).toBe(false);
  });

  it("has no cause property at all when there was no upstream error", () => {
    expect("cause" in new PasskeyError("not_supported")).toBe(false);
  });

  it("exposes a factory for every code", () => {
    const factories = [
      PasskeyError.challengeExpired(),
      PasskeyError.challengeNotFound(),
      PasskeyError.challengeTypeMismatch(),
      PasskeyError.originNotAllowed(),
      PasskeyError.rpIdMismatch(),
      PasskeyError.unknownCredential(),
      PasskeyError.credentialAlreadyRegistered(),
      PasskeyError.counterRegressed(),
      PasskeyError.userVerificationRequired(),
      PasskeyError.userHandleMismatch(),
      PasskeyError.verificationFailed(),
      PasskeyError.invalidResponse(),
      PasskeyError.notSupported(),
    ];

    expect(factories.map((error) => error.code).sort()).toEqual([...ALL_CODES].sort());
    for (const error of factories) {
      expect(error).toBeInstanceOf(PasskeyError);
      expect(error.name).toBe("PasskeyError");
    }
  });
});

describe("mapVerificationError", () => {
  it.each(UPSTREAM_MESSAGES)("maps %j", (message, code) => {
    expect(mapVerificationError(new Error(message)).code).toBe(code);
  });

  it("falls back to verification_failed rather than letting anything escape", () => {
    // Including messages a FUTURE version of the library might invent. An
    // unrecognised error must never become an uncaught throw a framework
    // renders as 500.
    for (const value of [
      new Error("User not present during authentication"),
      new Error("Some entirely new v14 wording"),
      new TypeError("boom"),
      "a bare string",
      null,
      undefined,
      { not: "an error" },
    ]) {
      const mapped = mapVerificationError(value);
      expect(mapped).toBeInstanceOf(PasskeyError);
      expect(mapped.httpStatus).toBeLessThan(500);
    }

    expect(mapVerificationError(new Error("who knows")).code).toBe("verification_failed");
  });

  it("never puts the upstream message in the client-visible message", () => {
    // The upstream text embeds the actual challenge, the actual origin, and the
    // expected RP ID, and it differs per failure mode.
    const raw = 'Unexpected authentication response challenge "SECRET-CHALLENGE", expected "OTHER"';
    const mapped = mapVerificationError(new Error(raw));

    expect(mapped.message).not.toContain("SECRET-CHALLENGE");
    expect(mapped.message).not.toContain("OTHER");
    expect(mapped.message).toBe(new PasskeyError("verification_failed").message);
    expect(JSON.stringify(mapped.toJSON())).not.toContain("SECRET-CHALLENGE");
  });

  it("preserves the upstream error on cause for server-side logging", () => {
    const upstream = new Error("Response counter value 3 was lower than expected 7");
    expect(mapVerificationError(upstream).cause).toBe(upstream);
  });

  it("passes our own errors through unchanged", () => {
    const ours = PasskeyError.challengeExpired();
    expect(mapVerificationError(ours)).toBe(ours);
  });
});
