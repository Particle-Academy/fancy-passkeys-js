# Changelog

All notable changes to `@particle-academy/fancy-passkeys` are documented here.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and
this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

> **Pre-1.0.** Breaking changes land in MINOR releases until 1.0.0. The version
> number is not yet a compatibility promise, so read this file before upgrading
> a minor.

## [Unreleased]

## 0.2.0 — 2026-08-07

### Changed

- **BREAKING — Node 20 is no longer supported.** `engines.node` moves from `>=20` to `>=22`.

  **What you must do:** on Node 22 or newer, nothing. Note npm only *warns* on an `engines` mismatch while **pnpm fails the install**, so this surfaces differently depending on your package manager. Node 18 is end-of-life and 20 is maintenance-only.

### Why

These are the kit 0.5 platform floors, applied across every package at once so a consumer never has to resolve a mix. **No API changed, nothing was removed, nothing was renamed** — only what the package requires.


## 0.1.0 — 2026-08-01

**First published release.** Passkey (WebAuthn) server ceremonies for Node — a thin wrapper over `@simplewebauthn/server` with **no cryptography of our own**. The Node twin of `particle-academy/fancy-passkeys`.

### Added

- Initial implementation. **Not published** — no npm release and no tag exists
  for this yet.
- `PasskeyServer` — a framework-free server for both WebAuthn ceremonies:
  `startRegistration` / `finishRegistration` / `startAuthentication` /
  `finishAuthentication`. Wraps `@simplewebauthn/server`; implements no
  cryptography of its own.
- `RelyingParty` — RP ID, name, and an exact-match origin allow-list, all
  validated **at construction**. A misconfigured RP ID throws a `TypeError` at
  boot rather than failing every ceremony on every device with an
  "Unexpected RP ID hash" that names neither the cause nor the fix.
- `PasskeyPolicy` + `defaultPasskeyPolicy` — challenge TTL, timeout, user
  verification, resident key, attestation, COSE algorithms, and `counterPolicy`
  (`reject` | `log-only` | `ignore`), every value defaulted to the safe answer
  and mirrored by the PHP twin.
- `ChallengeStore` and `CredentialStore` interfaces, plus
  `InMemoryChallengeStore` / `InMemoryCredentialStore` for tests and
  single-process apps.
- `Verifier` — an injectable port over the four `@simplewebauthn/server`
  functions, defaulting to `defaultVerifier`, which holds the real ones by
  identity. It exists so every wrapper failure path can be tested without an
  authenticator and a human fingerprint; `real-verifier.test.ts` asserts the
  identity so the test double can never ship.
- `toPasskeySummary` and the `PasskeySummary` shape — the client-safe projection
  of a credential, which never carries the public key or the user handle.
- `toBase64Url` / `fromBase64Url` / `isBase64Url` for minting user handles and
  implementing a store.
- `scripts/generate-wire-fixtures.ts` — regenerates the shared wire fixtures
  from the real library. Running it is a wire-contract change and the outputs
  must be copied to the PHP repo in the same session.
- `PasskeyError` with a closed `PasskeyErrorCode` set, so every failure the
  underlying library throws as a bare `Error` arrives as a typed, wire-safe
  code instead of a 500.
- `./http` subpath — four dependency-free request→response handlers
  (`createPasskeyHandlers`) that mount on Express, Hono, Fastify, or Node
  `http` without this package knowing which.
- Wire-parity fixtures shared with the PHP twin
  (`particle-academy/fancy-passkeys`), asserted in `parity.test.ts`.

### Security

- **Three codes are true internally and redacted on the wire.**
  `unknown_credential`, `user_handle_mismatch`, and `counter_regressed` all
  reach the client as `verification_failed`, with the same message and the same
  401. Matching messages alone were not enough: `code` is the field a client
  branches on, so a distinct code is just as good a credential-existence oracle
  as a distinct message. `PasskeyError.code` keeps the precise value for logs
  and metrics; only `toJSON()` redacts, and `wireCode` exposes what will
  actually be sent.
- Challenges are 32 CSPRNG bytes, single-use, and **consumed before
  verification** — `ChallengeStore.pull()` deletes as it reads, so a replayed
  response fails at "no such challenge" no matter how valid its signature is.
- Challenges are bound to their ceremony type; a registration challenge cannot
  be redeemed at the authentication endpoint.
- Origins are an exact-match allow-list. The request's own `Origin` header is
  never used to derive the expected value, and the RP ID is never taken from
  the request.
- Credential IDs are unique across all users; re-registering one already held
  by another account is rejected rather than silently repointed.
- Signature-counter regression is rejected by default and the credential is
  flagged, because the counter is a one-shot clone detector and a login that
  merely fails discards the signal. The new counter is persisted on **every**
  success including when it is `0`, and both counters being `0` is accepted —
  most synced passkey providers never implement counters at all.
- An unknown credential and a bad signature are indistinguishable to a client:
  same status, byte-identical message. A distinct answer would be a
  credential-existence oracle.
- No upstream error message reaches the wire. `mapVerificationError` maps
  `@simplewebauthn/server`'s bare `Error`s to typed codes and keeps the raw
  error on a **non-enumerable** `cause`, so a structured logger walking own
  enumerable keys cannot ship it to a client by accident. Nothing escapes
  untyped — an unrecognised message becomes `verification_failed` rather than an
  uncaught throw a framework renders as a 500.
- The RP ID and origin allow-list are validated at boot, never derived from the
  request. Plain `http://` is refused for everything but `localhost` and
  `127.0.0.1`.
