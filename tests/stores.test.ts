import { describe, expect, it } from "vitest";

import { PasskeyError } from "../src/errors.js";
import { InMemoryChallengeStore, InMemoryCredentialStore } from "../src/stores.js";
import type { ChallengeRecord } from "../src/types.js";

import { ADA_HANDLE, GRACE_HANDLE, makeStoredCredential } from "./helpers.js";

function record(overrides: Partial<ChallengeRecord> = {}): ChallengeRecord {
  return {
    challenge: "Y2hhbGxlbmdl",
    type: "registration",
    userHandle: ADA_HANDLE,
    expiresAt: 10_000,
    ...overrides,
  };
}

describe("InMemoryChallengeStore", () => {
  it("deletes the record as it reads it, so a second pull is empty", async () => {
    // This is the anti-replay mechanism, not an optimisation: a store that
    // reads without deleting turns every assertion into an infinitely
    // replayable token, and nothing anywhere reports it.
    const store = new InMemoryChallengeStore({ now: () => 0 });
    await store.put("state-1", record());

    await expect(store.pull("state-1")).resolves.toMatchObject({ type: "registration" });
    await expect(store.pull("state-1")).resolves.toBeNull();
    expect(store.size).toBe(0);
  });

  it("returns null for an unknown handle", async () => {
    const store = new InMemoryChallengeStore({ now: () => 0 });
    await expect(store.pull("never-issued")).resolves.toBeNull();
  });

  it("returns null for an expired record, and deletes it anyway", async () => {
    let clock = 0;
    const store = new InMemoryChallengeStore({ now: () => clock });
    await store.put("state-1", record({ expiresAt: 5_000 }));

    clock = 5_000; // expiry is inclusive: `expiresAt` is the first dead moment.
    await expect(store.pull("state-1")).resolves.toBeNull();
    expect(store.size).toBe(0);
  });

  it("stores a copy, so mutating the caller's record cannot change the store", async () => {
    const store = new InMemoryChallengeStore({ now: () => 0 });
    const mine = record();
    await store.put("state-1", mine);
    mine.type = "authentication";

    await expect(store.pull("state-1")).resolves.toMatchObject({ type: "registration" });
  });
});

describe("InMemoryCredentialStore", () => {
  it("rejects a duplicate credential id, mirroring the UNIQUE index", async () => {
    const store = new InMemoryCredentialStore([makeStoredCredential({ id: "dup" })]);

    await expect(store.save(makeStoredCredential({ id: "dup" }))).rejects.toMatchObject({
      code: "credential_already_registered",
    });
  });

  it("rejects a duplicate even when it belongs to a different user", async () => {
    // Silently re-pointing an existing credential id at another account is
    // account takeover, so the check spans every user rather than just this one.
    const store = new InMemoryCredentialStore([
      makeStoredCredential({ id: "dup", userHandle: ADA_HANDLE }),
    ]);

    const error = await store
      .save(makeStoredCredential({ id: "dup", userHandle: GRACE_HANDLE }))
      .catch((err: unknown) => err);

    expect(error).toBeInstanceOf(PasskeyError);
    expect((error as PasskeyError).httpStatus).toBe(409);
  });

  it("finds by id across all users and by user handle within one", async () => {
    const store = new InMemoryCredentialStore([
      makeStoredCredential({ id: "a", userHandle: ADA_HANDLE }),
      makeStoredCredential({ id: "b", userHandle: ADA_HANDLE }),
      makeStoredCredential({ id: "c", userHandle: GRACE_HANDLE }),
    ]);

    await expect(store.findById("c")).resolves.toMatchObject({ userHandle: GRACE_HANDLE });
    await expect(store.findById("nope")).resolves.toBeNull();
    await expect(store.findByUserHandle(ADA_HANDLE)).resolves.toHaveLength(2);
  });

  it("persists the counter and last-used stamp", async () => {
    const store = new InMemoryCredentialStore([makeStoredCredential({ id: "a", signCount: 4 })]);
    await store.updateAfterAuthentication("a", 9, "2026-02-02T00:00:00.000Z");

    await expect(store.findById("a")).resolves.toMatchObject({
      signCount: 9,
      lastUsedAt: "2026-02-02T00:00:00.000Z",
    });
  });

  it("hands out copies, so a caller cannot mutate the store by accident", async () => {
    const store = new InMemoryCredentialStore([makeStoredCredential({ id: "a" })]);

    const first = await store.findById("a");
    first!.signCount = 999;
    first!.transports.push("hybrid");

    await expect(store.findById("a")).resolves.toMatchObject({
      signCount: 0,
      transports: ["internal"],
    });
  });

  it("stamps clonedAt", async () => {
    const store = new InMemoryCredentialStore([makeStoredCredential({ id: "a" })]);
    await store.flagCloned("a", "2026-03-03T00:00:00.000Z");

    await expect(store.findById("a")).resolves.toMatchObject({
      clonedAt: "2026-03-03T00:00:00.000Z",
    });
  });

  it("deletes idempotently", async () => {
    const store = new InMemoryCredentialStore([makeStoredCredential({ id: "a" })]);
    await store.delete("a");
    await expect(store.delete("a")).resolves.toBeUndefined();
    expect(store.size).toBe(0);
  });
});
