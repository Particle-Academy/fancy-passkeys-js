# Changelog

All notable changes to `@particle-academy/fancy-passkeys` are documented here.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and
this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

> **Pre-1.0.** Breaking changes land in MINOR releases until 1.0.0. The version
> number is not yet a compatibility promise, so read this file before upgrading
> a minor.

## [Unreleased]

### Added

- **`@simplewebauthn/server` 14 is supported.** The peer range widens from
  `^13.0.0` to `>=13.3.0 <15`; the suite runs against 13.3.3 and 14.1.0, and CI
  now tests the 13.3.3 floor as well as the locked 14. **Consumer action:**
  none. Widening only adds versions; whatever you have installed in 13.3+ still
  resolves. If you are on 13.0 to 13.2, move to 13.3 or later.
- **`origins` may be a function** (`OriginResolver`), called on every
  verification and validated each time with the same rules as a static list,
  including the localhost and IP-literal rules. `RelyingParty.setOrigins()`
  replaces the list or resolver (a refused list leaves the old one in place),
  `resolveOrigins()` returns the current list, `hasDynamicOrigins` tells the
  two apart. Built for desktop apps whose local server port is picked at
  launch; the README documents the single-user desktop shape.
- **Optional login certificates.** `loginCertificates` on `PasskeyServer` (off by
  default) issues a canonical record of each successful sign-in and enrollment
  with app-supplied claims, and a token `fplc_v1_<sha256 hex>` of its canonical
  bytes. `issueLoginCertificate`, `loginCertificateToken`,
  `verifyLoginCertificate`, `isSensitiveClaimKey` and `canonicalJson` are
  exported. Known-sensitive claim keys are stripped and reported. The canonical
  form is change-council's, and `tests/fixtures/login-certificate/vectors.json`
  is shared with the PHP twin, so tokens agree across backends. The package
  stores nothing: a `deliver` hook hands the certificate to the app.
- `./http`: an optional `certificateClaims(ctx)` hook, and `onAuthenticated`
  receives the issued certificate (or `null`) as a fourth argument. Existing
  three-argument hooks keep working. The wire contract is unchanged.

### Changed

- `RelyingParty.origins` is now a getter (same `readonly string[]` value for a
  static list). For a resolver it resolves on access, and throws for an async
  resolver. **Consumer action:** none unless you assigned to it, which was
  never allowed.
- `finishRegistration` / `finishAuthentication` results carry a `certificate`
  field (`null` unless certificates are on). Additive.
- **Releases need a lab-run certificate.** `publish.yml` gains a read-only
  `lab-certificate` job that every publishing job needs: a tag is published only
  when the fancy-labs lab has certified that exact version and commit. Consumers
  do nothing; this changes how releases are cut, not what the package does.

### Fixed

- **SECURITY-RELEVANT: registration now accepts only the algorithms it offered.**
  `verifyRegistrationResponse` was called without `supportedAlgorithmIDs`, so
  the library's own default applied. In v14 that default grows to ML-DSA where
  the runtime supports it, which would have enrolled a credential type the
  options never offered. The policy's `algorithms` list is now passed, matching
  the PHP twin, where web-auth's `CheckAlgorithm` step already enforced it.
  **Consumer action:** none; the default list (`-8, -7, -257`) is unchanged.
- Compiles against v14's types, which dropped the `AuthenticatorTransportFuture`
  export. The transport type is now derived from `WebAuthnCredential`.
- **`RelyingParty` now accepts `*.localhost` hosts over plain http.** A
  configuration such as RP ID `genie.localhost` with origin
  `http://genie.localhost:5678` threw at construction, although Chromium runs
  WebAuthn there without complaint. http is allowed for `localhost` and for any
  name whose LAST LABEL is exactly `localhost` (`foo.localhost`,
  `a.b.localhost`), at any port. `localhost.evil.com` and `evilocalhost` still
  need https. The RP ID / origin rule is unchanged: the RP ID must be the
  origin's host or a registrable suffix of it.
- A non-https, non-http scheme on a localhost host (`ftp://localhost`) is now
  refused; only http is relaxed.

### Security

- **SECURITY-RELEVANT — IP-address hosts are no longer accepted, including
  `127.0.0.1`.** `RelyingParty` used to allow `http://127.0.0.1` and an RP ID of
  `127.0.0.1`. Chromium refuses an IP literal as an RP ID ("This is an invalid
  domain"), so such a configuration constructed cleanly and then failed every
  ceremony in the browser. Any IPv4 or IPv6 literal is now refused at
  construction, as an RP ID and as an origin host, over http or https. IPv4 is
  detected by the URL standard's "ends in a number" rule, so short forms such
  as `127.1` are caught too. **Consumer action:** only if you configured
  `127.0.0.1` (or another IP) as the RP ID or an origin: switch to `localhost`
  or a `*.localhost` name. Those configurations never worked in a browser, so
  nothing that worked before stops working. The accepted and refused cases are
  a fixture table (`tests/fixtures/relying-party/origins.json`) shared with the
  PHP twin.
- `source-map-js` is pinned forward to `^1.2.2` via `overrides`. Versions up to
  1.2.1 allow an event-loop denial of service through indexed source-map section
  offsets, and it arrives here transitively through the build toolchain.
  **Nothing for a consumer to do, and no runtime change**: an npm package does
  not ship a lockfile, so this governs builds OF this repo, not anything
  installed FROM it. Recorded rather than left silent because the override it
  sits beside — `shell-quote` `^1.9.0`, added for an earlier advisory — was
  carried with no note of why, and had drifted back inside the vulnerable range
  before anyone looked.
- **Dev toolchain only — no runtime change, nothing for consumers to do.** The
  lockfile now resolves `vite` 8.3.5 (was 8.2.2), whose bundled
  `launch-editor` fixes GHSA-587h-7wmj-h5pm (HIGH, `fs.existsSync()` check
  bypassable on Windows), GHSA-698v-4r3x-3vcv (`escapeCmdArgs()` omits `%`
  escaping on Windows) and GHSA-r825-w8mm-5pxw (editor CLI flag
  misinterpretation). `vite` is only reached through the test/dev toolchain
  and the published package does not ship our lockfile, so the exposure was
  this repo's own dev server.

- Dev-only lockfile update: `vitest` 4.1.11 to 4.1.12, which brings `@vitest/mocker` 4.1.12 (GHSA-qxg6-89mg-rqv8, GHSA-xp26-3454-mjgp). Test tooling only; nothing ships in the package. Consumer action: none.

## [0.2.1] — 2026-08-09

### Added

- **Tests for ceremony-type mismatch and wrong origin**, the two failure paths
  this repo's own AGENTS.md lists as required and that nothing here exercised.

  The enforcing branches and the error codes both existed; what was missing was
  anything driving them. The PHP twin has covered both since it shipped
  (`CeremonyFailureTest`, `OriginValidationTest`), so the pair was asymmetric —
  and a failure path tested on one backend of a matched pair is a failure path
  tested on neither, because the whole promise is that either can serve the same
  UI.

  Covered: a registration challenge redeemed at the authentication endpoint and
  the reverse; that a type-mismatched challenge is still **consumed** (leaving
  it redeemable turns a mismatch into a retry oracle); an origin the relying
  party does not list; and an RP-ID mismatch reported distinctly from an origin
  mismatch, because they are different misconfigurations.

  Verified sensitive — disabling the ceremony-type guard fails three of them.

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
