# AGENTS.md — fancy-passkeys-js

Passkey (WebAuthn) login for Node. `CLAUDE.md` points here. Read the envelope's
`AGENTS.md` too, and `.ai/plans/fancy-passkeys.md` — that plan is the wire
contract this package and its PHP twin are both held to.

## The rule that shapes this repo

**We do not implement WebAuthn cryptography, and we never will.**

CBOR decoding, COSE key parsing, ASN.1, attestation chains, RP-ID hashing,
`clientDataJSON` canonicalisation — this is the class of code whose bugs are
silent and total. A subtle mistake does not throw; it accepts a signature it
should have rejected, forever, for everyone, and the tests pass. So
`@simplewebauthn/server` does all of it and this package does none of it.

What this package owns is precisely what that library deliberately leaves to
the caller, and what almost every hand-rolled integration gets wrong:

1. **Issuing, storing, expiring, and single-using the challenge.**
2. **Persisting the credential**, and enforcing credential-ID uniqueness.
3. **Persisting the counter** after every successful assertion.
4. **Normalising errors** into a closed, wire-safe set.

If a change to this repo would put a crypto primitive in `src/`, the change is
wrong. Fix the wrapper, or fix it upstream.

## The three things a reviewer should check first

### 1. The challenge is pulled BEFORE it is verified

```ts
const record = await challenges.pull(handle);   // reads AND deletes
if (!record) throw new PasskeyError('challenge_not_found');
// ...only now do we verify
```

Inverted — verify first, delete after — a replayed response with a valid
signature succeeds on every retry, and nothing anywhere reports it. The
ordering is the entire anti-replay mechanism. `store.test.ts` asserts that a
second `pull()` of the same handle returns `null`, and `server.test.ts` asserts
that a replayed finish fails with `challenge_not_found`.

### 2. Every call into `@simplewebauthn/server` is wrapped in try/catch

**v13 throws plain `Error`s for nearly every mismatch** — wrong challenge,
wrong origin, wrong RP ID, missing user presence, missing user verification,
counter regression. Only the final cryptographic check returns
`{ verified: false }`.

An unwrapped call therefore turns "this login is not valid" into "500 Internal
Server Error". That is a bad UX and an information leak (the stack differs by
failure mode). `mapVerificationError()` exists for exactly this and is the only
place those errors are allowed to be interpreted.

### 3. The counter is persisted on EVERY success, including when it is 0

Not persisting it is the most common way the clone detector is silently
defeated: the stored value never advances, so every comparison is against 0 and
the check can never fire.

Related, and load-bearing: **both counters being 0 is accepted.** Most synced
passkey providers (iCloud Keychain, Google Password Manager) do not implement
counters at all and always send 0. A strict `new > stored` rule rejects the
majority of real passkeys in the world.

## Dependencies

- `@simplewebauthn/server` is a **peer, never a dependency**, and is in
  `external` in `tsup.config.ts`. Two copies in a tree means two incompatible
  `WebAuthnCredential` types, and the resolver reports nothing.
- `dependencies` is **empty and stays empty**. `packaging.test.ts` asserts it.
- The `./http` subpath must stay free of any HTTP framework. It exports plain
  `(input) => output` functions; the consumer adapts them. The moment it
  imports Express it stops working for the Hono user.

## Wire parity with the PHP twin

`particle-academy/fancy-passkeys` (PHP) must emit an **equal** payload —
deep-equal once parsed, since key order is not part of the contract.
That is the whole reason the pair exists: one React surface, either backend.
`parity.test.ts` asserts this package's output against fixtures in
`tests/fixtures/wire/`, and the PHP repo asserts against the same files. If you
change a wire shape here, change it there in the same session, or the pair
quietly stops being a pair.

## Commands

```bash
npm install
npm test       # vitest
npm run lint   # tsc --noEmit && eslint .
npm run build  # tsup
```

## Conventions

- **Tests cover failure paths first.** Auth code with only a happy-path test is
  untested code: the happy path is what an attacker never uses. Required
  coverage: replayed challenge, expired challenge, ceremony-type mismatch,
  wrong origin, counter regression, unknown credential, cross-user credential
  reuse.
- **No error message leaks whether a credential exists.** `unknown_credential`
  and a bad signature must be indistinguishable to the client.
- Sibling first-party deps use `>=X <2.0`, never a caret on a `0.x`.
  `devDependencies` keep their carets.
- `CHANGELOG.md` is updated in the SAME commit as the change.
