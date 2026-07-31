/**
 * The shared vocabulary of the passkey wire contract.
 *
 * Every name in this file has a twin in `particle-academy/fancy-passkeys` (the
 * PHP runtime). Renaming anything here without renaming it there is how the
 * pair quietly stops being a pair — see `.ai/plans/fancy-passkeys.md` §6.
 */

/**
 * The closed set of failures a client may be told about.
 *
 * Closed on purpose: an error code is part of the wire contract, so a UI can
 * switch on it, and both backends must be able to emit every member. Adding one
 * is a coordinated change across three repos, not a local decision.
 */
export type PasskeyErrorCode =
  | "challenge_expired"
  | "challenge_not_found"
  | "challenge_type_mismatch"
  | "origin_not_allowed"
  | "rp_id_mismatch"
  | "unknown_credential"
  | "credential_already_registered"
  | "counter_regressed"
  | "user_verification_required"
  | "user_handle_mismatch"
  | "verification_failed"
  | "invalid_response"
  | "not_supported";

/**
 * Which ceremony a challenge was issued for.
 *
 * Stored alongside the challenge so a registration challenge cannot be redeemed
 * at the authentication endpoint.
 */
export type CeremonyType = "registration" | "authentication";

/**
 * The account a ceremony is for.
 *
 * `handle` is the WebAuthn **user handle**: 32 random bytes per user, base64url
 * encoded, minted lazily by the host app. It is transmitted to and stored by
 * every authenticator the user enrolls, so it must never be the primary key or
 * the email address.
 */
export interface PasskeyUser {
  /** Opaque, stable, base64url. Never the primary key, never the email. */
  handle: string;
  /** The website-specific username shown in the authenticator picker. */
  name: string;
  /** The human-friendly name shown in the authenticator picker. */
  displayName: string;
}

/**
 * A challenge in flight.
 *
 * Stored server-side under an opaque `state` handle — never under the challenge
 * itself, which would let anyone who observed a challenge probe the store for
 * it.
 */
export interface ChallengeRecord {
  /** The base64url challenge exactly as it was sent to the browser. */
  challenge: string;
  /** The ceremony this challenge was issued for. */
  type: CeremonyType;
  /**
   * The user handle this ceremony is bound to, or `null` for the discoverable
   * (usernameless) authentication flow where no user is known yet.
   */
  userHandle: string | null;
  /** Epoch milliseconds after which this record is worthless. */
  expiresAt: number;
}

/**
 * One enrolled passkey.
 *
 * The record is per **credential**, not per user: the whole point of passkeys
 * is that one account enrolls a laptop, a phone, and a hardware key.
 */
export interface StoredCredential {
  /** base64url credential id. Unique across ALL users — see §5.3 of the plan. */
  id: string;
  /** base64url COSE public key. The only thing that verifies a signature. */
  publicKey: string;
  /** base64url user handle of the owning account. */
  userHandle: string;
  /** Signature counter, as last reported. Clone detection depends on it. */
  signCount: number;
  /** Transport hints so the browser offers the right authenticator next time. */
  transports: string[];
  /** Authenticator model id. Stored for future MDS work; not trusted today. */
  aaguid: string;
  /** BS flag: whether this credential is currently backed up / synced. */
  backedUp: boolean;
  /** BE flag: whether this credential is *allowed* to be backed up. */
  backupEligible: boolean;
  /** Whether the credential was created with user verification. */
  uvInitialized: boolean;
  /** Attestation statement format (`none`, `packed`, …). Stored, not trusted. */
  attestationFormat: string;
  /** User-chosen label. `null` until someone names it. */
  name: string | null;
  /** ISO-8601. */
  createdAt: string;
  /** ISO-8601, or `null` if never used to sign in. */
  lastUsedAt: string | null;
  /**
   * ISO-8601 of the moment a signature-counter regression was observed, or
   * `null`. The counter is a one-shot clone detector: failing the login without
   * recording it loses the signal forever.
   */
  clonedAt: string | null;
}

/** The client-safe projection of a {@link StoredCredential}. */
export interface PasskeySummary {
  id: string;
  name: string | null;
  createdAt: string;
  lastUsedAt: string | null;
  transports: string[];
  backedUp: boolean;
  aaguid: string;
  clonedAt: string | null;
}
