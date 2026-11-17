# Using @particle-academy/fancy-passkeys (Node) — guide for agents

How an agent installs and uses this package in a consumer app. What the package
is, is in [README.md](./README.md). Notes for working ON this repo's code are in
[CONTRIBUTING.md](./CONTRIBUTING.md).

## Install

```bash
npm install @particle-academy/fancy-passkeys @simplewebauthn/server
```

- The npm name is `@particle-academy/fancy-passkeys` (the repo is
  `fancy-passkeys-js`). The PHP twin is the Composer package
  `particle-academy/fancy-passkeys`.
- **Peer:** `@simplewebauthn/server >=13.3.0 <15`. Install it yourself; it is
  never bundled.
- **Node:** `>=22`. ESM and CJS, types included.
- **Browser side:** `@particle-academy/fancy-passkeys-ui` (or
  `@simplewebauthn/browser`) runs the ceremony.

## Find it on the Fancy MCP server

The catalog server is `https://ui.particle.academy/mcp` (streamable HTTP, no API
key; MCP id `fancy-ui`). This package's registry entry is `fancy-passkeys-js`.
As a server-side package it is found with `search-backend-packages` (stack
`node`); `install-instructions` gives the exact install commands. The UI is
`@particle-academy/fancy-passkeys-ui` (entries `passkey-sign-in`,
`passkey-manager`, `passkey-status`).

## API essentials

- **`new PasskeyServer({ relyingParty, challenges, credentials })`** with
  `new RelyingParty({ id, name, origins })`.
- **Registration** (on an already signed-in user):
  `startRegistration({ handle, name, displayName })` returns `{ state, publicKey }`;
  `finishRegistration({ state, response, name })`.
- **Sign-in:** `startAuthentication()` (discoverable, no username) or
  `startAuthentication({ userHandle })`; `finishAuthentication({ state, response })`
  returns `{ userHandle, credential, summary }`. Sessions are yours.
- **Manage:** `listPasskeys(handle)` returns `PasskeySummary[]`.
- **Stores you implement:** `ChallengeStore` (`put`, `pull`) and
  `CredentialStore` (`findById`, `findByUserHandle`, `save`,
  `updateAfterAuthentication`, `flagCloned`, `delete`).
  `InMemoryChallengeStore` / `InMemoryCredentialStore` are for tests and single
  processes.
- **HTTP:** `createPasskeyHandlers(server, { currentUser, resolveUserByEmail,
  onAuthenticated })` from `/http` gives the four endpoints as plain
  `(input) => Promise<{ status, body }>` functions; adapt them to Express, Hono
  or anything else.
- **Errors:** `PasskeyError` with a closed `code`, a 4xx `httpStatus`, `wireCode`,
  and `toJSON()` for the wire body.
- `origins` may be a function (sync or async), or swapped with
  `rp.setOrigins(...)`. Login certificates are optional and off by default; see
  the README.

## Traps

- **`ChallengeStore.pull` must delete as it reads.** That is the anti-replay
  mechanism. Key by the opaque `state` handle, never by the challenge. Redis
  `GETDEL` with a TTL fits.
- **`InMemoryChallengeStore` is not shared between workers**; a ceremony started
  on one and finished on another fails with `challenge_not_found`.
- **`CredentialStore.save` must throw `PasskeyError.credentialAlreadyRegistered()`
  on a duplicate id, and the column needs a `UNIQUE` index.** `findById` searches
  across all users. Store everything as base64url text.
- **The user handle is 32 random bytes, base64url**, minted by your app. Never
  the primary key or the email.
- **`origins` is an exact-match allow-list**, `https://` only except `localhost`
  and `*.localhost`; never IP hosts; never derived from the request. The RP ID is
  validated at boot.
- **`counterPolicy: 'ignore'` disables clone detection.** The default `reject`
  fails the login and stamps `clonedAt`.
- **Three codes are redacted on the wire** (`unknown_credential`,
  `user_handle_mismatch`, `counter_regressed` all send `verification_failed`).
  Branch on `wireCode` for what the client sees; log `code`.
- **`resolveUserByEmail` returns `null` for an unknown email; never throw.**
- Sessions, CSRF and rate limiting are the host's. Attestation trust, passkey-only
  signup and account recovery are out of scope.
- **Desktop apps:** one user handle minted on first run, one credential per
  device, RP ID `localhost` with a resolver for the port, discoverable sign-in.
