/**
 * Login certificates — an OPTIONAL, canonical record of a successful passkey
 * ceremony, and a token that is the SHA-256 of that record.
 *
 * What it is for: tracing. The app logs the token beside a request, a support
 * ticket quotes it, an audit row stores the certificate; any of them can later
 * be checked against the others with {@link verifyLoginCertificate}.
 *
 * What it is NOT:
 *
 * - **Not a signature, and not a credential.** Anyone holding a certificate can
 *   compute its token — that is the point of a hash. It proves that a record
 *   and a token belong together, not who wrote them. Keep certificates where an
 *   attacker cannot write if you need tamper-evidence, or sign them yourself.
 *   Never accept a token as proof of a session.
 * - **Not our cryptography.** SHA-256 comes from the platform's WebCrypto. No
 *   WebAuthn work happens here; the ceremony was verified before this runs.
 *
 * The certificate carries a 16-byte random `nonce`, so a token cannot be
 * reversed by enumerating plausible IPs and timestamps, and two identical
 * sign-ins never share a token.
 *
 * **Byte-identical with the PHP twin** (`FancyPasskeys\LoginCertificate`). The
 * canonical form is change-council's (`canonical-json.ts`); the shared fixture
 * `tests/fixtures/login-certificate/vectors.json` pins certificate, canonical
 * bytes and token for both runtimes. That forces a few rules on claims that a
 * single-runtime design would not need — each is noted where it is enforced.
 *
 * @module
 */

import { canonicalJson } from "./canonical-json.js";
import { isBase64Url } from "./encoding.js";
import type { CeremonyType } from "./types.js";

/** The `type` field of every v1 certificate. */
export const LOGIN_CERTIFICATE_TYPE = "fancy-passkeys.login-certificate";
/** The `version` field of every v1 certificate. */
export const LOGIN_CERTIFICATE_VERSION = 1;
/**
 * Every v1 token starts with this. `fplc` = fancy-passkeys login certificate;
 * `v1` binds the certificate schema, the canonical form and SHA-256 together,
 * so changing any of the three is a new prefix, never a silent reinterpretation.
 */
export const LOGIN_CERTIFICATE_TOKEN_PREFIX = "fplc_v1_";

const TOKEN_PATTERN = /^fplc_v1_[0-9a-f]{64}$/;
const CEREMONIES: readonly CeremonyType[] = ["registration", "authentication"];

/** A claim value that has one canonical form in both runtimes. */
export type CertificateClaimValue =
  | null
  | boolean
  | number
  | string
  | CertificateClaimValue[]
  | { [key: string]: CertificateClaimValue };

/** The app's claims: an object of {@link CertificateClaimValue}s. */
export type CertificateClaims = { [key: string]: CertificateClaimValue };

/** The facts about the ceremony that the package itself contributes. */
export interface LoginCertificateSubject {
  ceremony: CeremonyType;
  rpId: string;
  credentialId: string;
  /** The account's WebAuthn user handle — the "who", without a primary key. */
  userHandle: string;
}

/** A v1 login certificate. */
export interface LoginCertificate extends LoginCertificateSubject {
  type: typeof LOGIN_CERTIFICATE_TYPE;
  version: typeof LOGIN_CERTIFICATE_VERSION;
  /** ISO-8601 UTC with milliseconds, from the server's clock. */
  issuedAt: string;
  /** 16 random bytes, base64url. */
  nonce: string;
  /** The app's claims, with known-sensitive keys stripped. */
  claims: CertificateClaims;
}

/** What issuing a certificate produces. */
export interface IssuedLoginCertificate {
  certificate: LoginCertificate;
  /** The exact bytes that were hashed. Store THIS if you store the certificate. */
  canonical: string;
  /** `fplc_v1_` + 64 lowercase hex characters. */
  token: string;
  /**
   * Paths of claims removed as known-sensitive (`claims.device.token`), sorted.
   * Not part of the certificate; reported so a host can notice it is passing
   * something it should not.
   */
  stripped: string[];
}

/** Input to {@link issueLoginCertificate}. */
export interface LoginCertificateInput extends LoginCertificateSubject {
  issuedAt: string;
  nonce: string;
  claims?: Record<string, unknown>;
}

/**
 * Normalised key fragments that mark a claim as sensitive anywhere in its name
 * (`db_password`, `csrf-token`, `X-Api-Key`). Lowercased, with every character
 * that is not a-z or 0-9 removed, before matching.
 */
const SENSITIVE_FRAGMENTS: readonly string[] = [
  "password",
  "passwd",
  "secret",
  "token",
  "apikey",
  "authorization",
  "cookie",
  "privatekey",
  "sessionid",
  "recoverycode",
];

/**
 * Short names that are sensitive only as the WHOLE key. As fragments they would
 * strip harmless keys (`otp` is inside `footprint`, `pin` inside `spin`).
 */
const SENSITIVE_NAMES: readonly string[] = ["otp", "totp", "pin", "pwd", "cvv", "ssn", "session", "auth"];

/**
 * Whether a claim key names something that must never be in a certificate.
 *
 * This is a backstop, not a guarantee: it catches the obvious names, and it is
 * deliberately biased toward stripping (`tokenizer` goes too). An app must not
 * put credentials in a certificate under ANY name. Identical in the PHP twin.
 */
export function isSensitiveClaimKey(key: string): boolean {
  const normalised = key.toLowerCase().replace(/[^a-z0-9]/g, "");
  return (
    SENSITIVE_NAMES.includes(normalised) ||
    SENSITIVE_FRAGMENTS.some((fragment) => normalised.includes(fragment))
  );
}

/**
 * Build a certificate, canonicalise it and hash it.
 *
 * Throws `TypeError` for a claim that has no single canonical form across PHP
 * and Node (floats, integers beyond 2^53-1, non-ASCII or all-digit keys,
 * `undefined`, class instances, lone surrogates) — a programmer error in the
 * host, surfaced loudly rather than as a token one runtime cannot reproduce.
 */
export async function issueLoginCertificate(input: LoginCertificateInput): Promise<IssuedLoginCertificate> {
  if (!CEREMONIES.includes(input.ceremony)) {
    throw new TypeError(`Login certificate ceremony must be "registration" or "authentication".`);
  }
  for (const field of ["rpId", "credentialId", "userHandle", "issuedAt"] as const) {
    if (typeof input[field] !== "string" || input[field].length === 0) {
      throw new TypeError(`Login certificate \`${field}\` must be a non-empty string.`);
    }
  }
  if (!isBase64Url(input.nonce)) {
    throw new TypeError("Login certificate `nonce` must be a non-empty base64url string.");
  }

  const stripped: string[] = [];
  const claims = cleanObject(input.claims ?? {}, "claims", stripped, true);

  const certificate: LoginCertificate = {
    type: LOGIN_CERTIFICATE_TYPE,
    version: LOGIN_CERTIFICATE_VERSION,
    ceremony: input.ceremony,
    issuedAt: input.issuedAt,
    nonce: input.nonce,
    rpId: input.rpId,
    credentialId: input.credentialId,
    userHandle: input.userHandle,
    claims: claims as CertificateClaims,
  };

  const canonical = canonicalJson(certificate);
  return { certificate, canonical, token: await tokenFor(canonical), stripped: stripped.sort() };
}

/**
 * The token for a certificate, which may be the object or its stored JSON.
 *
 * Nothing is stripped here: the certificate is hashed exactly as given. Throws
 * `TypeError` for a value with no canonical form.
 */
export async function loginCertificateToken(certificate: unknown): Promise<string> {
  const value = typeof certificate === "string" ? (JSON.parse(certificate) as unknown) : certificate;
  cleanValue(value, "certificate", [], false);
  return tokenFor(canonicalJson(value));
}

/**
 * Whether `token` is the token of `certificate` (the object, or its stored
 * JSON). Never throws: anything malformed is simply `false`.
 *
 * It checks that the two belong together, which is all a hash can say — see the
 * module notes before treating a match as proof of anything else.
 */
export async function verifyLoginCertificate(certificate: unknown, token: unknown): Promise<boolean> {
  if (typeof token !== "string" || !TOKEN_PATTERN.test(token)) {
    return false;
  }
  let value: unknown;
  try {
    value = typeof certificate === "string" ? JSON.parse(certificate) : certificate;
  } catch {
    return false;
  }
  if (!isPlainObject(value)) {
    return false;
  }
  if (value["type"] !== LOGIN_CERTIFICATE_TYPE || value["version"] !== LOGIN_CERTIFICATE_VERSION) {
    return false;
  }
  let expected: string;
  try {
    expected = await loginCertificateToken(value);
  } catch {
    return false;
  }
  return constantTimeEqual(expected, token);
}

async function tokenFor(canonical: string): Promise<string> {
  const digest = await globalThis.crypto.subtle.digest("SHA-256", new TextEncoder().encode(canonical));
  let hex = "";
  for (const byte of new Uint8Array(digest)) {
    hex += byte.toString(16).padStart(2, "0");
  }
  return LOGIN_CERTIFICATE_TOKEN_PREFIX + hex;
}

/** Equal-length strings compared without an early exit. Not secret, but cheap to do right. */
function constantTimeEqual(a: string, b: string): boolean {
  if (a.length !== b.length) {
    return false;
  }
  let diff = 0;
  for (let i = 0; i < a.length; i += 1) {
    diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  }
  return diff === 0;
}

function isPlainObject(value: unknown): value is Record<string, unknown> {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    return false;
  }
  const proto = Object.getPrototypeOf(value) as unknown;
  return proto === Object.prototype || proto === null;
}

/**
 * Printable ASCII only, so code-unit order (JavaScript's sort) and byte order
 * (PHP's `ksort`) agree. Checked by code, not by a regex literal, so no escape
 * sequence can be mangled on the way into this file.
 */
function isPrintableAscii(key: string): boolean {
  for (let i = 0; i < key.length; i += 1) {
    const code = key.charCodeAt(i);
    if (code < 0x20 || code > 0x7e) {
      return false;
    }
  }
  return true;
}

/** No unpaired UTF-16 surrogate: PHP's json_encode would refuse the UTF-8 for it. */
function isWellFormed(value: string): boolean {
  for (let i = 0; i < value.length; i += 1) {
    const code = value.charCodeAt(i);
    if (code >= 0xd800 && code <= 0xdbff) {
      const next = value.charCodeAt(i + 1);
      if (!(next >= 0xdc00 && next <= 0xdfff)) {
        return false;
      }
      i += 1;
    } else if (code >= 0xdc00 && code <= 0xdfff) {
      return false;
    }
  }
  return true;
}

function cleanObject(value: unknown, path: string, stripped: string[], strip: boolean): Record<string, unknown> {
  if (!isPlainObject(value)) {
    throw new TypeError(`Login certificate ${path} must be a plain object.`);
  }
  const out: Record<string, unknown> = {};
  for (const key of Object.keys(value)) {
    // PHP turns an all-digit key ("0", "-1") into an integer array key, and a
    // run of them from 0 into a LIST, so the same claims would hash
    // differently in the two runtimes. Refused in both.
    if (!isPrintableAscii(key) || /^-?[0-9]+$/.test(key)) {
      throw new TypeError(
        `Login certificate claim key "${key}" at ${path} must be printable ASCII and not all digits.`,
      );
    }
    const childPath = `${path}.${key}`;
    if (strip && isSensitiveClaimKey(key)) {
      stripped.push(childPath);
      continue;
    }
    out[key] = cleanValue(value[key], childPath, stripped, strip);
  }
  return out;
}

function cleanValue(value: unknown, path: string, stripped: string[], strip: boolean): unknown {
  if (value === null || typeof value === "boolean") {
    return value;
  }
  if (typeof value === "string") {
    if (!isWellFormed(value)) {
      throw new TypeError(`Login certificate value at ${path} is not well-formed Unicode.`);
    }
    return value;
  }
  if (typeof value === "number") {
    // Floats print differently in PHP and JavaScript, and an integer past
    // 2^53-1 is exact in PHP and rounded here.
    if (!Number.isSafeInteger(value)) {
      throw new TypeError(
        `Login certificate value at ${path} must be an integer within 2^53-1; send floats and big numbers as strings.`,
      );
    }
    return value;
  }
  if (Array.isArray(value)) {
    // Array.from, not map: map skips the holes of a sparse array, which would
    // then canonicalise to invalid JSON. Here a hole is `undefined`, and refused.
    return Array.from(value as unknown[], (item, index) => cleanValue(item, `${path}[${index}]`, stripped, strip));
  }
  if (isPlainObject(value)) {
    return cleanObject(value, path, stripped, strip);
  }
  throw new TypeError(
    `Login certificate value at ${path} must be null, a boolean, an integer, a string, a list or a plain object.`,
  );
}
