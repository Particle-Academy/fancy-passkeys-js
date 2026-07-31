/**
 * Base64URL encoding helpers.
 *
 * This is the only "binary" code in the package and it is deliberately trivial:
 * encoding, not cryptography. Everything WebAuthn-shaped — CBOR, COSE, ASN.1,
 * signature verification — belongs to `@simplewebauthn/server` and never comes
 * here. See AGENTS.md.
 *
 * Everything this package persists or puts on the wire is base64url **text**
 * (credential ids, public keys, user handles, challenges), because mirroring a
 * store across two runtimes and three databases with binary columns is exactly
 * where encoding bugs live.
 */

/** Matches an unpadded base64url string. Padding (`=`) is not accepted. */
const BASE64URL = /^[A-Za-z0-9_-]*$/;

/** Encode bytes as an unpadded base64url string. */
export function toBase64Url(bytes: Uint8Array): string {
  return Buffer.from(bytes).toString("base64url");
}

/**
 * Decode an unpadded base64url string to bytes.
 *
 * `Buffer.from(value, "base64url")` silently ignores characters it does not
 * understand, so a malformed handle would decode to *something* rather than
 * fail. Callers that accept a value from outside should run
 * {@link assertBase64Url} first.
 */
export function fromBase64Url(value: string): Uint8Array<ArrayBuffer> {
  return new Uint8Array(Buffer.from(value, "base64url"));
}

/** True when `value` is a non-empty, unpadded base64url string. */
export function isBase64Url(value: unknown): value is string {
  return typeof value === "string" && value.length > 0 && BASE64URL.test(value);
}

/**
 * Copy bytes into a plain `Uint8Array` backed by its own `ArrayBuffer`.
 *
 * `@simplewebauthn/server` types its byte parameters as `Uint8Array<ArrayBuffer>`
 * (never `SharedArrayBuffer`), while an injected `randomBytes` is typed as the
 * looser `Uint8Array`. 32 bytes is not a copy worth avoiding, and the copy also
 * detaches the value from whatever buffer the caller handed us.
 */
export function copyBytes(bytes: Uint8Array): Uint8Array<ArrayBuffer> {
  return new Uint8Array(bytes);
}

/**
 * Throw a `TypeError` unless `value` is a non-empty base64url string.
 *
 * A bad user handle is a programmer error in the host application (handles are
 * minted by the app, never by a request), so it fails loudly at the call site
 * rather than arriving later as an unexplained verification failure.
 */
export function assertBase64Url(value: unknown, label: string): asserts value is string {
  if (!isBase64Url(value)) {
    throw new TypeError(`${label} must be a non-empty base64url string.`);
  }
}
