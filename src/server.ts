import {
  generateAuthenticationOptions,
  generateRegistrationOptions,
  verifyAuthenticationResponse,
  verifyRegistrationResponse,
} from "@simplewebauthn/server";
import type {
  AuthenticationResponseJSON,
  AuthenticatorTransportFuture,
  PublicKeyCredentialCreationOptionsJSON,
  PublicKeyCredentialRequestOptionsJSON,
  RegistrationResponseJSON,
} from "@simplewebauthn/server";

import { assertBase64Url, copyBytes, fromBase64Url, toBase64Url } from "./encoding.js";
import { PasskeyError, mapVerificationError } from "./errors.js";
import { resolvePasskeyPolicy, type PasskeyPolicy } from "./policy.js";
import type { RelyingParty } from "./relying-party.js";
import type { ChallengeStore, CredentialStore } from "./stores.js";
import type { PasskeySummary, PasskeyUser, StoredCredential } from "./types.js";

/**
 * The four functions this package borrows from `@simplewebauthn/server`,
 * behind a port.
 *
 * It exists so tests can drive **every wrapper failure path deterministically**.
 * The interesting behaviour of this package — challenge single-use, ceremony
 * binding, credential-id uniqueness, counter policy, error normalisation — all
 * lives *around* the verification, and none of it can be exercised at all if
 * reaching it requires a real authenticator, a real biometric, and a real
 * signature. Auth code whose only tested path is the happy one is untested
 * code: the happy path is the one an attacker never uses.
 *
 * The port is typed as `typeof` the real functions so it cannot drift from
 * them, `defaultVerifier` holds the real functions by identity, and
 * `real-verifier.test.ts` asserts that identity so a fake can never ship.
 */
export interface Verifier {
  generateRegistrationOptions: typeof generateRegistrationOptions;
  verifyRegistrationResponse: typeof verifyRegistrationResponse;
  generateAuthenticationOptions: typeof generateAuthenticationOptions;
  verifyAuthenticationResponse: typeof verifyAuthenticationResponse;
}

/** The real `@simplewebauthn/server`. What every `PasskeyServer` uses unless told otherwise. */
export const defaultVerifier: Verifier = {
  generateRegistrationOptions,
  verifyRegistrationResponse,
  generateAuthenticationOptions,
  verifyAuthenticationResponse,
};

/** Constructor input for {@link PasskeyServer}. */
export interface PasskeyServerOptions {
  /** Who we are and which origins may complete a ceremony. */
  relyingParty: RelyingParty;
  /** Overrides on top of `defaultPasskeyPolicy`. */
  policy?: Partial<PasskeyPolicy>;
  /** Where in-flight challenges live. */
  challenges: ChallengeStore;
  /** Where enrolled passkeys live. */
  credentials: CredentialStore;
  /** Epoch-millisecond clock. Injectable so expiry is testable without waiting. */
  now?: () => number;
  /** CSPRNG. Injectable so the wire-parity fixtures are reproducible. */
  randomBytes?: (size: number) => Uint8Array;
  /** The WebAuthn implementation. Defaults to {@link defaultVerifier}. */
  verifier?: Verifier;
}

/** `startRegistration` result: hand `publicKey` to the browser, keep `state`. */
export interface StartRegistrationResult {
  /**
   * The opaque handle the client must send back with the finish request.
   *
   * 32 random bytes. The store is keyed by this, never by the challenge, so
   * observing a challenge tells an attacker nothing about how to look it up.
   */
  state: string;
  /** Pass straight to `@simplewebauthn/browser`'s `startRegistration`. */
  publicKey: PublicKeyCredentialCreationOptionsJSON;
}

/** `finishRegistration` input. */
export interface FinishRegistrationInput {
  /** The `state` from {@link StartRegistrationResult}. */
  state: string;
  /** Whatever the browser returned, unmodified. */
  response: RegistrationResponseJSON;
  /** Optional user-chosen label ("MacBook Touch ID"). */
  name?: string | null;
}

/** `finishRegistration` result. */
export interface FinishRegistrationResult {
  /** The record as persisted. */
  credential: StoredCredential;
  /** The client-safe projection of the same record. */
  summary: PasskeySummary;
}

/** `startAuthentication` input. Omit everything for the discoverable flow. */
export interface StartAuthenticationOptions {
  /**
   * The user handle for a username-first flow, or absent for the discoverable
   * (usernameless) flow, which is the one this package optimises for.
   */
  userHandle?: string | null;
}

/** `startAuthentication` result. */
export interface StartAuthenticationResult {
  /** The opaque handle the client must send back with the finish request. */
  state: string;
  /** Pass straight to `@simplewebauthn/browser`'s `startAuthentication`. */
  publicKey: PublicKeyCredentialRequestOptionsJSON;
}

/** `finishAuthentication` input. */
export interface FinishAuthenticationInput {
  /** The `state` from {@link StartAuthenticationResult}. */
  state: string;
  /** Whatever the browser returned, unmodified. */
  response: AuthenticationResponseJSON;
}

/** `finishAuthentication` result. Establish the session from `userHandle`. */
export interface FinishAuthenticationResult {
  /** The credential record, with the new counter and `lastUsedAt` applied. */
  credential: StoredCredential;
  /** The client-safe projection of the same record. */
  summary: PasskeySummary;
  /** The account that just authenticated. */
  userHandle: string;
}

/** The client-safe projection of a credential. Never includes the public key. */
export function toPasskeySummary(credential: StoredCredential): PasskeySummary {
  return {
    id: credential.id,
    name: credential.name,
    createdAt: credential.createdAt,
    lastUsedAt: credential.lastUsedAt,
    transports: [...credential.transports],
    backedUp: credential.backedUp,
    aaguid: credential.aaguid,
    clonedAt: credential.clonedAt,
  };
}

/** 32 bytes, per the plan. Not configurable — there is no good reason to shorten it. */
const CHALLENGE_BYTES = 32;
/** 32 bytes of opaque handle. Same reasoning. */
const STATE_BYTES = 32;

const defaultRandomBytes = (size: number): Uint8Array => {
  const bytes = new Uint8Array(size);
  globalThis.crypto.getRandomValues(bytes);
  return bytes;
};

/**
 * The same rule `@simplewebauthn/server` applies internally.
 *
 * **Both counters zero is accepted.** Most synced passkey providers — iCloud
 * Keychain, Google Password Manager — do not implement counters at all and
 * always report 0. A strict `next > stored` rule would reject the majority of
 * real passkeys in the world.
 */
function counterRegressed(stored: number, next: number): boolean {
  return (next > 0 || stored > 0) && next <= stored;
}

/**
 * Both WebAuthn ceremonies, framework-free.
 *
 * Wraps `@simplewebauthn/server` and implements **no cryptography**. What it
 * owns is precisely what that library deliberately leaves to the caller, and
 * what almost every hand-rolled integration gets wrong: issuing, expiring and
 * single-using the challenge; persisting the credential and enforcing id
 * uniqueness; persisting the counter; and normalising every failure into a
 * closed, wire-safe set of codes.
 *
 * @example
 * ```ts
 * const server = new PasskeyServer({
 *   relyingParty: new RelyingParty({ id: "example.com", name: "Example", origins: ["https://example.com"] }),
 *   challenges: new InMemoryChallengeStore(),
 *   credentials: new InMemoryCredentialStore(),
 * });
 * ```
 */
export class PasskeyServer {
  readonly #relyingParty: RelyingParty;
  readonly #policy: PasskeyPolicy;
  readonly #challenges: ChallengeStore;
  readonly #credentials: CredentialStore;
  readonly #now: () => number;
  readonly #randomBytes: (size: number) => Uint8Array;
  readonly #verifier: Verifier;

  constructor(options: PasskeyServerOptions) {
    this.#relyingParty = options.relyingParty;
    this.#policy = resolvePasskeyPolicy(options.policy);
    this.#challenges = options.challenges;
    this.#credentials = options.credentials;
    this.#now = options.now ?? Date.now;
    this.#randomBytes = options.randomBytes ?? defaultRandomBytes;
    this.#verifier = options.verifier ?? defaultVerifier;
  }

  /** The resolved policy this server runs under. */
  get policy(): PasskeyPolicy {
    return this.#policy;
  }

  /** The configured relying party. */
  get relyingParty(): RelyingParty {
    return this.#relyingParty;
  }

  /**
   * Begin enrollment for an already-authenticated user.
   *
   * `excludeCredentials` is populated with every passkey the user already has,
   * so the authenticator itself refuses a duplicate before the second network
   * round-trip ever happens.
   */
  async startRegistration(user: PasskeyUser): Promise<StartRegistrationResult> {
    assertBase64Url(user.handle, "PasskeyUser.handle");

    const existing = await this.#credentials.findByUserHandle(user.handle);

    const publicKey = await this.#verifier.generateRegistrationOptions({
      rpName: this.#relyingParty.name,
      rpID: this.#relyingParty.id,
      userName: user.name,
      userDisplayName: user.displayName,
      // MUST be bytes. v13 throws on a string `userID`, because the base64url
      // encoder it runs the value through would otherwise return "" and the
      // account would silently enroll against an empty handle.
      userID: fromBase64Url(user.handle),
      // Likewise bytes, not a string: a string challenge is UTF-8 encoded by
      // the library, so passing our base64url text would put the base64url of
      // the base64url on the wire and nothing would ever verify.
      challenge: this.#challenge(),
      timeout: this.#policy.timeoutMs,
      attestationType: this.#policy.attestation,
      excludeCredentials: existing.map((credential) => ({
        id: credential.id,
        transports: credential.transports as AuthenticatorTransportFuture[],
      })),
      authenticatorSelection: {
        residentKey: this.#policy.residentKey,
        userVerification: this.#policy.userVerification,
      },
      supportedAlgorithmIDs: this.#policy.algorithms,
    });

    const state = this.#newState();
    await this.#challenges.put(state, {
      // Store what the library actually emitted rather than our own encoding of
      // the same bytes, so the stored value and the wire value cannot disagree.
      challenge: publicKey.challenge,
      type: "registration",
      userHandle: user.handle,
      expiresAt: this.#expiry(),
    });

    return { state, publicKey };
  }

  /**
   * Verify an enrollment and persist the credential.
   *
   * The challenge is consumed **before** anything is verified — see the pull in
   * `#pullChallenge`. Inverted, a replayed response with a valid signature would
   * succeed on every retry and nothing anywhere would report it.
   */
  async finishRegistration(input: FinishRegistrationInput): Promise<FinishRegistrationResult> {
    const record = await this.#pullChallenge(input.state, "registration");

    if (!record.userHandle) {
      // A registration record always carries the enrolling user. Reaching here
      // means the store returned something we did not write.
      throw PasskeyError.invalidResponse();
    }

    // Across ALL users, not just this one. A credential id already registered
    // to another account is an attack or a bug; silently re-pointing it at the
    // current session is account takeover.
    const clash = await this.#credentials.findById(input.response.id);
    if (clash) {
      throw PasskeyError.credentialAlreadyRegistered();
    }

    let verification: Awaited<ReturnType<typeof verifyRegistrationResponse>>;
    try {
      verification = await this.#verifier.verifyRegistrationResponse({
        response: input.response,
        expectedChallenge: record.challenge,
        expectedOrigin: this.#relyingParty.expectedOrigins(),
        expectedRPID: this.#relyingParty.id,
        requireUserVerification: this.#policy.userVerification === "required",
      });
    } catch (err) {
      // v13 throws a bare `Error` for challenge / origin / RP ID / UP / UV
      // mismatches. Unwrapped, every one of those is a 500.
      throw mapVerificationError(err);
    }

    if (!verification.verified) {
      // The one failure the library reports rather than throws: the attestation
      // or signature check itself.
      throw PasskeyError.verificationFailed();
    }

    const info = verification.registrationInfo;
    const credential: StoredCredential = {
      id: info.credential.id,
      publicKey: toBase64Url(info.credential.publicKey),
      userHandle: record.userHandle,
      signCount: info.credential.counter,
      transports: [...(info.credential.transports ?? input.response.response.transports ?? [])],
      aaguid: info.aaguid,
      backedUp: info.credentialBackedUp,
      // BE (backup *eligible*) is what makes a credential multi-device; BS
      // (backed up) is whether it currently is. Storing only the second loses
      // the ability to tell a synced passkey from a hardware one.
      backupEligible: info.credentialDeviceType === "multiDevice",
      uvInitialized: info.userVerified,
      // Stored, never trusted. Attestation trust needs the FIDO MDS, chain
      // validation, and a revocation story — see "Not in scope" in the README.
      attestationFormat: info.fmt,
      name: input.name ?? null,
      createdAt: this.#nowIso(),
      lastUsedAt: null,
      clonedAt: null,
    };

    await this.#credentials.save(credential);

    return { credential, summary: toPasskeySummary(credential) };
  }

  /**
   * Begin a login.
   *
   * With no `userHandle` this is the discoverable flow: `allowCredentials` is
   * empty, the browser shows an account picker, and the assertion comes back
   * carrying the user handle. A `userHandle` for an account with no passkeys
   * also yields an empty `allowCredentials`, which is what keeps the
   * username-first endpoint from being a user-enumeration oracle.
   */
  async startAuthentication(
    options: StartAuthenticationOptions = {},
  ): Promise<StartAuthenticationResult> {
    const userHandle = options.userHandle ?? null;
    if (userHandle !== null) {
      assertBase64Url(userHandle, "userHandle");
    }

    const known = userHandle ? await this.#credentials.findByUserHandle(userHandle) : [];

    const publicKey = await this.#verifier.generateAuthenticationOptions({
      rpID: this.#relyingParty.id,
      allowCredentials: known.map((credential) => ({
        id: credential.id,
        transports: credential.transports as AuthenticatorTransportFuture[],
      })),
      challenge: this.#challenge(),
      timeout: this.#policy.timeoutMs,
      userVerification: this.#policy.userVerification,
    });

    const state = this.#newState();
    await this.#challenges.put(state, {
      challenge: publicKey.challenge,
      type: "authentication",
      userHandle,
      expiresAt: this.#expiry(),
    });

    return { state, publicKey };
  }

  /**
   * Verify an assertion, run the counter policy, and persist the outcome.
   *
   * On success the caller establishes the session from the returned
   * `userHandle`; this package deliberately knows nothing about sessions.
   */
  async finishAuthentication(
    input: FinishAuthenticationInput,
  ): Promise<FinishAuthenticationResult> {
    const record = await this.#pullChallenge(input.state, "authentication");

    const credential = await this.#credentials.findById(input.response.id);
    if (!credential) {
      // Deliberately indistinguishable from a bad signature: same code family,
      // same HTTP status, byte-identical message. A distinct "we've never seen
      // that credential" answer is a credential-existence oracle.
      throw PasskeyError.unknownCredential();
    }

    // Username-first flow: the account we issued the challenge for must be the
    // account that owns the credential that answered it.
    if (record.userHandle !== null && record.userHandle !== credential.userHandle) {
      throw PasskeyError.userHandleMismatch();
    }

    // Discoverable flow: the authenticator reports the handle it stored, and it
    // must be the one we stored. A mismatch is an attack, not a curiosity.
    const assertedHandle = input.response.response.userHandle;
    if (assertedHandle && assertedHandle !== credential.userHandle) {
      throw PasskeyError.userHandleMismatch();
    }

    const nowIso = this.#nowIso();
    const enforceCounterInLibrary = this.#policy.counterPolicy === "reject";

    /*
     * Counter policy, and why it is split in two.
     *
     * The library performs its own counter check and **throws** on regression,
     * which is unrecoverable: there is no way to say "you were right, but
     * continue anyway" and no way to re-run the verification once it has
     * thrown. So:
     *
     * - `reject` (default) — let the library throw, map it, flag the clone, and
     *   rethrow. The library stays the authority.
     * - `log-only` / `ignore` — hand the library a counter of `0`, which makes
     *   its check `(next > 0 || 0 > 0) && next <= 0` — unsatisfiable — and then
     *   apply the identical rule ourselves against the real stored value.
     *
     * The zeroing is confined to the argument; nothing persisted is touched.
     */
    let verification: Awaited<ReturnType<typeof verifyAuthenticationResponse>>;
    try {
      verification = await this.#verifier.verifyAuthenticationResponse({
        response: input.response,
        expectedChallenge: record.challenge,
        expectedOrigin: this.#relyingParty.expectedOrigins(),
        expectedRPID: this.#relyingParty.id,
        requireUserVerification: this.#policy.userVerification === "required",
        credential: {
          id: credential.id,
          publicKey: fromBase64Url(credential.publicKey),
          counter: enforceCounterInLibrary ? credential.signCount : 0,
          transports: credential.transports as AuthenticatorTransportFuture[],
        },
      });
    } catch (err) {
      const mapped = mapVerificationError(err);
      if (mapped.code === "counter_regressed") {
        // Flag BEFORE rethrowing. The counter is a one-shot detector: fail the
        // login without recording it and the real device's next attempt
        // succeeds, leaving no trace that anything was ever wrong.
        await this.#credentials.flagCloned(credential.id, nowIso);
      }
      throw mapped;
    }

    if (!verification.verified) {
      throw PasskeyError.verificationFailed();
    }

    const { newCounter } = verification.authenticationInfo;

    let clonedAt = credential.clonedAt;
    if (!enforceCounterInLibrary && counterRegressed(credential.signCount, newCounter)) {
      if (this.#policy.counterPolicy === "log-only") {
        clonedAt = nowIso;
        await this.#credentials.flagCloned(credential.id, clonedAt);
      }
      // `ignore` records nothing. That is what "this disables clone detection"
      // means, and why the option says so in those words.
    }

    // ALWAYS, including when `newCounter` is 0. Skipping the zero case is the
    // most common silent defeat of the whole mechanism: the stored value never
    // advances, so every future comparison is against 0 and the check that is
    // supposed to catch a clone can never fire.
    await this.#credentials.updateAfterAuthentication(credential.id, newCounter, nowIso);

    const updated: StoredCredential = {
      ...credential,
      signCount: newCounter,
      lastUsedAt: nowIso,
      clonedAt,
    };

    return {
      credential: updated,
      summary: toPasskeySummary(updated),
      userHandle: credential.userHandle,
    };
  }

  /** Every passkey an account has enrolled, as client-safe summaries. */
  async listPasskeys(userHandle: string): Promise<PasskeySummary[]> {
    assertBase64Url(userHandle, "userHandle");
    const credentials = await this.#credentials.findByUserHandle(userHandle);
    return credentials.map(toPasskeySummary);
  }

  /**
   * Consume the challenge, then validate it.
   *
   * The `pull` is the first thing either finish handler does, before a single
   * byte of the response is looked at. That ordering IS the anti-replay
   * mechanism — see AGENTS.md, "The three things a reviewer should check
   * first".
   */
  async #pullChallenge(
    state: string,
    expected: "registration" | "authentication",
  ): Promise<{ challenge: string; userHandle: string | null }> {
    if (typeof state !== "string" || state.length === 0) {
      throw PasskeyError.invalidResponse();
    }

    const record = await this.#challenges.pull(state);
    if (!record) {
      throw PasskeyError.challengeNotFound();
    }
    // Re-checked here even though a good store prunes expired records itself:
    // the store's clock is not ours, and a DB-backed store with no cleanup job
    // is a completely ordinary implementation of the interface.
    if (record.expiresAt <= this.#now()) {
      throw PasskeyError.challengeExpired();
    }
    if (record.type !== expected) {
      // A registration challenge may not be redeemed at the authentication
      // endpoint, nor the reverse.
      throw PasskeyError.challengeTypeMismatch();
    }

    return { challenge: record.challenge, userHandle: record.userHandle };
  }

  #challenge(): Uint8Array<ArrayBuffer> {
    return copyBytes(this.#randomBytes(CHALLENGE_BYTES));
  }

  #newState(): string {
    return toBase64Url(this.#randomBytes(STATE_BYTES));
  }

  #expiry(): number {
    return this.#now() + this.#policy.challengeTtlSeconds * 1000;
  }

  #nowIso(): string {
    return new Date(this.#now()).toISOString();
  }
}
