/**
 * Regenerate the wire-parity fixtures.
 *
 * ```bash
 * npx tsx scripts/generate-wire-fixtures.ts
 * ```
 *
 * Reads `tests/fixtures/wire/inputs.json` and drives the **real**
 * `@simplewebauthn/server` through `PasskeyServer` with those exact fixed
 * inputs — fixed challenge and fixed user handle, supplied through the
 * injectable `randomBytes` — then writes the two options payloads out.
 *
 * `parity.test.ts` asserts this package's live output against the results, and
 * `particle-academy/fancy-passkeys` (PHP) asserts **against the same files**.
 * That is the whole reason the pair is a pair: one React surface, either
 * backend. Regenerating is therefore a wire-contract change — copy the outputs
 * into the PHP repo's `tests/fixtures/wire/` in the same session, or the two
 * backends have quietly stopped agreeing and the UI works against only one.
 *
 * How each fixture is driven, so the PHP twin can be driven identically:
 *
 * - `registration-options.json` — `startRegistration(user)` for a user who
 *   already holds both `existingCredentials`, so `excludeCredentials` is
 *   populated (the authenticator refuses a duplicate before the round-trip).
 * - `authentication-options.json` — `startAuthentication({ userHandle })`, the
 *   **username-first** flow, so `allowCredentials` carries both descriptors.
 *   The discoverable flow is the same call with no handle and an empty list;
 *   the populated case is fixtured because it exercises the descriptor mapping
 *   that the empty one cannot.
 */

import { readFileSync, writeFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import {
  InMemoryChallengeStore,
  InMemoryCredentialStore,
  PasskeyServer,
  RelyingParty,
  fromBase64Url,
  toBase64Url,
} from "../src/index.js";
import type { PasskeyPolicy, StoredCredential } from "../src/index.js";

interface WireInputs {
  relyingParty: { id: string; name: string; origins: string[] };
  user: { handle: string; name: string; displayName: string };
  challenge: string;
  existingCredentials: { id: string; transports: string[] }[];
  policy: Omit<PasskeyPolicy, "challengeTtlSeconds" | "counterPolicy">;
}

const here = dirname(fileURLToPath(import.meta.url));
const wireDir = resolve(here, "..", "tests", "fixtures", "wire");

const inputs = JSON.parse(readFileSync(resolve(wireDir, "inputs.json"), "utf8")) as WireInputs;

// A fixture that does not round-trip is a fixture that silently encodes
// something other than what it says it does.
for (const [label, value] of [
  ["challenge", inputs.challenge],
  ["user.handle", inputs.user.handle],
] as const) {
  const roundTripped = toBase64Url(fromBase64Url(value));
  if (roundTripped !== value) {
    throw new Error(`inputs.json ${label} is not canonical base64url: "${value}" -> "${roundTripped}".`);
  }
}

const fixedChallenge = fromBase64Url(inputs.challenge);

// `randomBytes` is called for the challenge and again for the opaque `state`
// handle. Only the challenge reaches the payload, so returning the same fixed
// bytes for both is enough to make the fixture deterministic.
const randomBytes = (): Uint8Array => fixedChallenge;

const server = new PasskeyServer({
  relyingParty: new RelyingParty(inputs.relyingParty),
  policy: inputs.policy,
  challenges: new InMemoryChallengeStore(),
  credentials: new InMemoryCredentialStore(inputs.existingCredentials.map(seedCredential)),
  now: () => Date.parse("2026-01-01T00:00:00.000Z"),
  randomBytes,
});

const registration = await server.startRegistration(inputs.user);
const authentication = await server.startAuthentication({ userHandle: inputs.user.handle });

write("registration-options.json", registration.publicKey);
write("authentication-options.json", authentication.publicKey);

function seedCredential(credential: { id: string; transports: string[] }): StoredCredential {
  return {
    id: credential.id,
    // Never used by an options ceremony; present because the store type is the
    // real one and a fixture that fakes the type proves nothing.
    publicKey: toBase64Url(new Uint8Array([1, 2, 3])),
    userHandle: inputs.user.handle,
    signCount: 0,
    transports: credential.transports,
    aaguid: "00000000-0000-0000-0000-000000000000",
    backedUp: false,
    backupEligible: false,
    uvInitialized: true,
    attestationFormat: "none",
    name: null,
    createdAt: "2026-01-01T00:00:00.000Z",
    lastUsedAt: null,
    clonedAt: null,
  };
}

function write(file: string, payload: unknown): void {
  const target = resolve(wireDir, file);
  // Serialise through JSON first: `undefined`-valued keys are not part of the
  // wire shape and must not be part of the fixture either.
  writeFileSync(target, `${JSON.stringify(JSON.parse(JSON.stringify(payload)), null, 2)}\n`, "utf8");
  process.stdout.write(`wrote ${target}\n`);
}
