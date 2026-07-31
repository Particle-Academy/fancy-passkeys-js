/**
 * `@particle-academy/fancy-passkeys` — passkey (WebAuthn) login for Node.
 *
 * A thin, safe wrapper around `@simplewebauthn/server` that owns exactly what
 * that library deliberately leaves to the caller: issuing, expiring and
 * single-using the challenge; persisting the credential and enforcing
 * credential-id uniqueness; persisting the signature counter; and normalising
 * every failure into a closed, wire-safe set of codes.
 *
 * **It implements no cryptography.** Runtime twin of
 * `particle-academy/fancy-passkeys` (PHP); the two emit byte-identical
 * payloads so one React surface works against either backend.
 *
 * The HTTP handlers live on the `./http` subpath, so importing this module
 * never pulls in the request-shaped code.
 *
 * @module
 */

export { fromBase64Url, isBase64Url, toBase64Url } from "./encoding.js";
export { PasskeyError, mapVerificationError, type PasskeyErrorOptions } from "./errors.js";
export {
  defaultPasskeyPolicy,
  resolvePasskeyPolicy,
  type AttestationPreference,
  type CounterPolicy,
  type PasskeyPolicy,
  type ResidentKeyRequirement,
  type UserVerificationRequirement,
} from "./policy.js";
export { RelyingParty, type RelyingPartyOptions } from "./relying-party.js";
export {
  InMemoryChallengeStore,
  InMemoryCredentialStore,
  type ChallengeStore,
  type CredentialStore,
} from "./stores.js";
export {
  PasskeyServer,
  defaultVerifier,
  toPasskeySummary,
  type FinishAuthenticationInput,
  type FinishAuthenticationResult,
  type FinishRegistrationInput,
  type FinishRegistrationResult,
  type PasskeyServerOptions,
  type StartAuthenticationOptions,
  type StartAuthenticationResult,
  type StartRegistrationResult,
  type Verifier,
} from "./server.js";
export type {
  CeremonyType,
  ChallengeRecord,
  PasskeyErrorCode,
  PasskeySummary,
  PasskeyUser,
  StoredCredential,
} from "./types.js";
