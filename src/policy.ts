/**
 * The tuning knobs, all defaulted to the safe answer.
 *
 * Every value here is a decision a WebAuthn integration lives or dies on, so
 * none of them is a thing the consumer is expected to discover. The defaults
 * are the documented recommendation of `.ai/plans/fancy-passkeys.md` §5 and the
 * PHP twin ships the identical table.
 */

/** How much the user must prove during the ceremony. */
export type UserVerificationRequirement = "required" | "preferred" | "discouraged";

/** Whether the credential is stored on the authenticator (discoverable). */
export type ResidentKeyRequirement = "required" | "preferred" | "discouraged";

/** Which attestation statement to request. */
export type AttestationPreference = "none" | "direct" | "enterprise";

/**
 * What to do when a credential's signature counter goes backwards.
 *
 * - `reject` (**default**) — fail the authentication *and* stamp `clonedAt` on
 *   the credential. The counter is a one-shot detector: fail the login without
 *   recording it and the real device's next attempt succeeds, leaving no trace
 *   that anything was ever wrong.
 * - `log-only` — stamp `clonedAt` but let the login through. For an app that
 *   wants the signal without the outage.
 * - `ignore` — **this disables clone detection.** Named plainly because an
 *   option called `ignore` otherwise reads as harmless. Nothing is flagged and
 *   nothing is recorded; choose it only if a specific buggy authenticator model
 *   is regressing benignly and availability matters more than the detector.
 */
export type CounterPolicy = "reject" | "log-only" | "ignore";

/** The complete, resolved policy a {@link import("./server.js").PasskeyServer} runs under. */
export interface PasskeyPolicy {
  /**
   * Requested user verification, and — because a request alone guarantees
   * nothing — `required` also makes the verifier enforce the returned UV flag.
   */
  userVerification: UserVerificationRequirement;
  /**
   * `preferred` by default: `required` consumes a storage slot on hardware
   * authenticators, of which they have very few.
   */
  residentKey: ResidentKeyRequirement;
  /**
   * `none` by default and the only fully-supported mode. `direct` may be
   * requested and the statement is stored, but **no trust decision is made from
   * it** — that needs the FIDO Metadata Service, chain validation, and a
   * revocation story. See §5.7 of the plan.
   */
  attestation: AttestationPreference;
  /** How long the browser gives the user to complete the ceremony. */
  timeoutMs: number;
  /**
   * How long the server honours the challenge. Deliberately longer than
   * `timeoutMs` so a slow-but-legitimate ceremony is not punished, and short
   * enough that a leaked options blob is worthless before it is useful.
   */
  challengeTtlSeconds: number;
  /** COSE algorithm identifiers, most-preferred first: EdDSA, ES256, RS256. */
  algorithms: number[];
  /** See {@link CounterPolicy}. */
  counterPolicy: CounterPolicy;
}

/** The defaults. Mirrored exactly by `particle-academy/fancy-passkeys` (PHP). */
export const defaultPasskeyPolicy: PasskeyPolicy = Object.freeze({
  userVerification: "preferred",
  residentKey: "preferred",
  attestation: "none",
  timeoutMs: 60_000,
  challengeTtlSeconds: 300,
  algorithms: Object.freeze([-8, -7, -257]) as unknown as number[],
  counterPolicy: "reject",
}) as PasskeyPolicy;

/** Fill a partial policy in from {@link defaultPasskeyPolicy}. */
export function resolvePasskeyPolicy(policy: Partial<PasskeyPolicy> = {}): PasskeyPolicy {
  return {
    ...defaultPasskeyPolicy,
    ...policy,
    // Copy so a later mutation of the caller's array cannot change what the
    // server offers on a subsequent ceremony.
    algorithms: [...(policy.algorithms ?? defaultPasskeyPolicy.algorithms)],
  };
}
