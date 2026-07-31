import type { PasskeyErrorCode } from "./types.js";

/**
 * The HTTP status each code answers with.
 *
 * Every code maps to a **4xx**. That is the point of this table: v13 of
 * `@simplewebauthn/server` throws a bare `Error` for nearly every mismatch —
 * wrong challenge, wrong origin, wrong RP ID, no user presence, no user
 * verification, counter regression — so a wrapper that does not catch reports
 * "500 Internal Server Error" for "that login is not valid". A 500 is both a
 * lie and, because the stack differs per failure mode, an oracle.
 *
 * `401` is used for anything that means "this authentication attempt failed",
 * `409` for the one genuine conflict, `400` for a malformed or stale request.
 */
const HTTP_STATUS: Record<PasskeyErrorCode, number> = {
  challenge_expired: 400,
  challenge_not_found: 400,
  challenge_type_mismatch: 400,
  origin_not_allowed: 400,
  rp_id_mismatch: 400,
  unknown_credential: 401,
  credential_already_registered: 409,
  counter_regressed: 401,
  user_verification_required: 401,
  user_handle_mismatch: 401,
  verification_failed: 401,
  invalid_response: 400,
  not_supported: 400,
};

/**
 * The client-visible message for each code.
 *
 * Two rules govern this table and both are load-bearing:
 *
 * 1. **`unknown_credential` and `verification_failed` are byte-identical.** A
 *    distinct "we have never seen that credential" message is a
 *    credential-existence oracle: an attacker holding a list of credential ids
 *    could sort it into "registered here" and "not". `errors.test.ts` asserts
 *    the two strings are equal, and the two codes share an HTTP status too.
 * 2. **No message is derived from an upstream error.** The underlying library's
 *    messages embed the actual challenge, the actual origin, and the expected
 *    RP ID, and they differ per failure mode. The raw error is preserved on the
 *    non-enumerable `cause` for server-side logging and never reaches the wire.
 */
const MESSAGES: Record<PasskeyErrorCode, string> = {
  challenge_expired: "The passkey challenge has expired. Start again.",
  challenge_not_found: "No passkey challenge is in flight for this request.",
  challenge_type_mismatch: "That challenge was issued for a different ceremony.",
  origin_not_allowed: "The request origin is not allowed for this application.",
  rp_id_mismatch: "The relying party id did not match.",
  unknown_credential: "The passkey could not be verified.",
  credential_already_registered: "That passkey is already registered.",
  counter_regressed: "The passkey's signature counter went backwards; it may have been cloned.",
  user_verification_required: "This passkey must verify the user with a biometric or PIN.",
  user_handle_mismatch: "That passkey does not belong to this account.",
  verification_failed: "The passkey could not be verified.",
  invalid_response: "The passkey response was malformed.",
  not_supported: "That passkey operation is not supported.",
};

/** Optional extras when constructing a {@link PasskeyError}. */
export interface PasskeyErrorOptions {
  /**
   * The underlying error, kept for server-side logging.
   *
   * Installed **non-enumerably** by the `Error` constructor, so
   * `JSON.stringify(err)` and structured loggers that walk own enumerable keys
   * will not accidentally ship it to a client.
   */
  cause?: unknown;
  /** Overrides the message table. Must not embed anything request-derived. */
  message?: string;
}

/**
 * A failure a client is allowed to be told about.
 *
 * Every path out of this package that is not a programmer error throws one of
 * these, which is what lets `./http` answer with a stable `{ error: { code,
 * message } }` body and a 4xx instead of leaking a stack trace.
 */
export class PasskeyError extends Error {
  readonly name = "PasskeyError";

  /** The wire code. Part of the contract shared with the PHP twin. */
  readonly code: PasskeyErrorCode;

  /** Always 4xx. See {@link HTTP_STATUS}. */
  readonly httpStatus: number;

  constructor(code: PasskeyErrorCode, options: PasskeyErrorOptions = {}) {
    const message = options.message ?? MESSAGES[code];
    // Only pass `cause` when there is one: `new Error(m, { cause: undefined })`
    // still installs the property, which makes "was there an upstream error?"
    // impossible to answer.
    super(message, "cause" in options ? { cause: options.cause } : undefined);
    this.code = code;
    this.httpStatus = HTTP_STATUS[code];
  }

  /** The wire body. This is the ONLY shape an error leaves the server as. */
  toJSON(): { error: { code: PasskeyErrorCode; message: string } } {
    return { error: { code: this.code, message: this.message } };
  }

  static challengeExpired(options?: PasskeyErrorOptions): PasskeyError {
    return new PasskeyError("challenge_expired", options);
  }

  static challengeNotFound(options?: PasskeyErrorOptions): PasskeyError {
    return new PasskeyError("challenge_not_found", options);
  }

  static challengeTypeMismatch(options?: PasskeyErrorOptions): PasskeyError {
    return new PasskeyError("challenge_type_mismatch", options);
  }

  static originNotAllowed(options?: PasskeyErrorOptions): PasskeyError {
    return new PasskeyError("origin_not_allowed", options);
  }

  static rpIdMismatch(options?: PasskeyErrorOptions): PasskeyError {
    return new PasskeyError("rp_id_mismatch", options);
  }

  static unknownCredential(options?: PasskeyErrorOptions): PasskeyError {
    return new PasskeyError("unknown_credential", options);
  }

  static credentialAlreadyRegistered(options?: PasskeyErrorOptions): PasskeyError {
    return new PasskeyError("credential_already_registered", options);
  }

  static counterRegressed(options?: PasskeyErrorOptions): PasskeyError {
    return new PasskeyError("counter_regressed", options);
  }

  static userVerificationRequired(options?: PasskeyErrorOptions): PasskeyError {
    return new PasskeyError("user_verification_required", options);
  }

  static userHandleMismatch(options?: PasskeyErrorOptions): PasskeyError {
    return new PasskeyError("user_handle_mismatch", options);
  }

  static verificationFailed(options?: PasskeyErrorOptions): PasskeyError {
    return new PasskeyError("verification_failed", options);
  }

  static invalidResponse(options?: PasskeyErrorOptions): PasskeyError {
    return new PasskeyError("invalid_response", options);
  }

  static notSupported(options?: PasskeyErrorOptions): PasskeyError {
    return new PasskeyError("not_supported", options);
  }
}

/**
 * Ordered probes against the upstream error message.
 *
 * String matching on an error message is not a technique anyone enjoys, but v13
 * throws plain `Error`s with no discriminant, so there is nothing else to look
 * at. Each needle is a **multi-word, human-authored phrase** from the library's
 * message, never a single word: the messages interpolate base64url values
 * (challenges, origins, credential ids), and a one-word needle like `"origin"`
 * can in principle be matched by the interpolated blob rather than the prose.
 * The phrases below contain spaces, which base64url cannot:
 *
 * - `Response counter value 3 was lower than expected 7`
 * - `Unexpected authentication response origin "…", expected "…"`
 * - `Unexpected RP ID hash`
 * - `Unexpected registration response challenge "…", expected "…"`
 * - `User verification required, but user could not be verified`
 *
 * `errors.test.ts` asserts these exact strings, so an upstream reword fails CI
 * rather than silently degrading — which matters most for the counter probe,
 * because `finishAuthentication` keys the clone flag off it.
 */
const VERIFICATION_ERROR_PROBES: ReadonlyArray<{ needle: string; code: PasskeyErrorCode }> = [
  { needle: "response counter value", code: "counter_regressed" },
  { needle: "response origin", code: "origin_not_allowed" },
  { needle: "unexpected rp id hash", code: "rp_id_mismatch" },
  { needle: "user verification", code: "user_verification_required" },
  { needle: "response challenge", code: "verification_failed" },
];

/**
 * Turn anything `@simplewebauthn/server` threw into a typed
 * {@link PasskeyError}.
 *
 * This is the ONLY place an upstream error is allowed to be interpreted, and it
 * has two absolute obligations:
 *
 * - **Nothing escapes untyped.** An unrecognised message maps to
 *   `verification_failed` (401), never to an uncaught throw that a framework
 *   would render as 500. "Unrecognised" includes future messages from a future
 *   version of the library, which is exactly why the fallback is a real code
 *   and not a rethrow.
 * - **The raw message never reaches the client.** It embeds request-derived
 *   values and differs per failure mode. It goes on `cause`, which is
 *   non-enumerable, so it survives for logging and dies at the JSON boundary.
 */
export function mapVerificationError(err: unknown): PasskeyError {
  // Our own errors pass through: `finishAuthentication` funnels the counter
  // policy through here too, and re-wrapping would lose the code.
  if (err instanceof PasskeyError) {
    return err;
  }

  const raw = err instanceof Error ? err.message : typeof err === "string" ? err : "";
  const haystack = raw.toLowerCase();

  for (const { needle, code } of VERIFICATION_ERROR_PROBES) {
    if (haystack.includes(needle)) {
      return new PasskeyError(code, { cause: err });
    }
  }

  return new PasskeyError("verification_failed", { cause: err });
}
