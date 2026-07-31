import { PasskeyError } from "./errors.js";
import type { ChallengeRecord, StoredCredential } from "./types.js";

/**
 * Where challenges live between the two round-trips of a ceremony.
 *
 * This is the anti-replay mechanism, and the ordering it implies is the single
 * most commonly botched part of a hand-rolled WebAuthn integration.
 */
export interface ChallengeStore {
  /**
   * Store `record` under the opaque `handle` issued to the client.
   *
   * The key is the handle, **never the challenge itself**. Keying by the
   * challenge lets anyone who observes one probe the store for it.
   */
  put(handle: string, record: ChallengeRecord): Promise<void>;

  /**
   * Read the record for `handle` **and delete it in the same operation**.
   *
   * "And delete it" is not an optimisation. `PasskeyServer` pulls *before* it
   * verifies, so a replayed response fails at "no such challenge" however valid
   * its signature is. An implementation that reads without deleting turns every
   * assertion into an infinitely replayable token and nothing anywhere reports
   * it.
   *
   * Returning `null` for an expired record is encouraged (a store with native
   * TTL gets it for free), but `PasskeyServer` **re-checks `expiresAt` itself**:
   * a Redis TTL, a database cleanup job, and this process do not share a clock,
   * and a store that hands back a stale record must still fail closed.
   */
  pull(handle: string): Promise<ChallengeRecord | null>;
}

/**
 * Where enrolled passkeys live.
 *
 * A consumer implements this against their own database. The contract is small
 * on purpose — the only real obligation is `save`, below.
 */
export interface CredentialStore {
  /**
   * Look a credential up by its base64url id, across **all** users.
   *
   * Both ceremonies depend on this being global: registration uses it to refuse
   * an id already registered to somebody else, and authentication uses it
   * because a discoverable credential arrives with no user attached.
   */
  findById(id: string): Promise<StoredCredential | null>;

  /** Every credential enrolled by one account. */
  findByUserHandle(userHandle: string): Promise<StoredCredential[]>;

  /**
   * Persist a newly enrolled credential.
   *
   * **Must throw `PasskeyError.credentialAlreadyRegistered()` if the id already
   * exists**, and the underlying column must carry a `UNIQUE` index so that the
   * throw comes from the database rather than from an application check. The
   * application check races; the index does not. Silently re-pointing an
   * existing credential id at a new account is account takeover.
   */
  save(credential: StoredCredential): Promise<void>;

  /**
   * Record the outcome of a successful assertion.
   *
   * Called on **every** success, including when `signCount` is `0`. Skipping
   * the zero case is the most common way the clone detector is silently
   * defeated — the stored value never advances, so every future comparison is
   * against 0 and the check can never fire.
   */
  updateAfterAuthentication(id: string, signCount: number, lastUsedAt: string): Promise<void>;

  /** Stamp `clonedAt` after a signature-counter regression. */
  flagCloned(id: string, clonedAt: string): Promise<void>;

  /** Remove a credential. Revoking the last one is a lockout — warn the human. */
  delete(id: string): Promise<void>;
}

/**
 * A `ChallengeStore` in process memory.
 *
 * Good for tests and a single-process app. **Not** for more than one process or
 * for anything that restarts mid-ceremony: two workers do not share this Map,
 * so a ceremony started on one and finished on the other fails with
 * `challenge_not_found`. Reach for Redis (with a native TTL) at that point.
 */
export class InMemoryChallengeStore implements ChallengeStore {
  readonly #records = new Map<string, ChallengeRecord>();
  readonly #now: () => number;

  constructor(options: { now?: () => number } = {}) {
    this.#now = options.now ?? Date.now;
  }

  put(handle: string, record: ChallengeRecord): Promise<void> {
    this.#records.set(handle, { ...record });
    return Promise.resolve();
  }

  pull(handle: string): Promise<ChallengeRecord | null> {
    const record = this.#records.get(handle);
    // Delete unconditionally and first: a pull consumes the challenge whether
    // or not the caller ends up liking what it got back.
    this.#records.delete(handle);

    if (!record) {
      return Promise.resolve(null);
    }
    if (record.expiresAt <= this.#now()) {
      return Promise.resolve(null);
    }
    return Promise.resolve(record);
  }

  /** How many challenges are in flight. Exposed for tests and diagnostics. */
  get size(): number {
    return this.#records.size;
  }

  /** Drop every in-flight challenge. */
  clear(): void {
    this.#records.clear();
  }
}

/**
 * A `CredentialStore` in process memory.
 *
 * Records are copied in and out, so nothing a caller holds can mutate the store
 * behind its back — the same isolation a real database gives you for free, and
 * without which a test can pass because two variables are the same object.
 */
export class InMemoryCredentialStore implements CredentialStore {
  readonly #credentials = new Map<string, StoredCredential>();

  constructor(seed: StoredCredential[] = []) {
    for (const credential of seed) {
      this.#credentials.set(credential.id, copy(credential));
    }
  }

  findById(id: string): Promise<StoredCredential | null> {
    const found = this.#credentials.get(id);
    return Promise.resolve(found ? copy(found) : null);
  }

  findByUserHandle(userHandle: string): Promise<StoredCredential[]> {
    const found: StoredCredential[] = [];
    for (const credential of this.#credentials.values()) {
      if (credential.userHandle === userHandle) {
        found.push(copy(credential));
      }
    }
    return Promise.resolve(found);
  }

  save(credential: StoredCredential): Promise<void> {
    // Mirrors the UNIQUE index the contract requires of a real store. Checked
    // across every user, not just this one.
    if (this.#credentials.has(credential.id)) {
      return Promise.reject(PasskeyError.credentialAlreadyRegistered());
    }
    this.#credentials.set(credential.id, copy(credential));
    return Promise.resolve();
  }

  updateAfterAuthentication(id: string, signCount: number, lastUsedAt: string): Promise<void> {
    const credential = this.#credentials.get(id);
    if (!credential) {
      // An UPDATE that matched no rows. Never expected — the caller only gets
      // here having just read the record — so it is a bug, not a login failure.
      return Promise.reject(PasskeyError.unknownCredential());
    }
    credential.signCount = signCount;
    credential.lastUsedAt = lastUsedAt;
    return Promise.resolve();
  }

  flagCloned(id: string, clonedAt: string): Promise<void> {
    const credential = this.#credentials.get(id);
    if (!credential) {
      return Promise.reject(PasskeyError.unknownCredential());
    }
    credential.clonedAt = clonedAt;
    return Promise.resolve();
  }

  delete(id: string): Promise<void> {
    // Idempotent: deleting a passkey that is already gone is the outcome the
    // caller asked for.
    this.#credentials.delete(id);
    return Promise.resolve();
  }

  /** How many credentials are stored. Exposed for tests and diagnostics. */
  get size(): number {
    return this.#credentials.size;
  }
}

function copy(credential: StoredCredential): StoredCredential {
  return { ...credential, transports: [...credential.transports] };
}
