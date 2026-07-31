# @particle-academy/fancy-passkeys

Passkey (WebAuthn) login for Node — a thin, safe wrapper around
[`@simplewebauthn/server`](https://simplewebauthn.dev) that owns exactly the
parts that library deliberately leaves to you, and that almost every hand-rolled
integration gets wrong.

> **This package implements no WebAuthn cryptography, and never will.** CBOR
> decoding, COSE key parsing, ASN.1, attestation chains, RP-ID hashing,
> `clientDataJSON` canonicalisation — that is the class of code whose bugs are
> silent and total: a subtle mistake does not throw, it accepts a signature it
> should have rejected, forever, for everyone, and the tests still pass. So
> `@simplewebauthn/server` does all of it and this package does none of it.

What it *does* own:

1. **Issuing, storing, expiring, and single-using the challenge.**
2. **Persisting the credential**, and enforcing credential-ID uniqueness across
   every user.
3. **Persisting the signature counter** after every successful assertion.
4. **Normalising errors** into a closed, wire-safe set — because v13 throws a
   bare `Error` for nearly every mismatch, and an unwrapped call reports
   "500 Internal Server Error" for "that login is not valid".

It is the Node twin of `particle-academy/fancy-passkeys` (PHP). The two emit
**byte-identical** payloads, so the same React surface
(`@particle-academy/fancy-passkeys-ui`) works against either backend.

---

## Install

```bash
npm install @particle-academy/fancy-passkeys @simplewebauthn/server
```

`@simplewebauthn/server` is a **peer dependency**, not a dependency. Two copies
in one tree means two incompatible `WebAuthnCredential` types and a resolver
quietly choosing whichever it likes, with nothing anywhere reporting it. This
package's own `dependencies` is empty and stays empty.

Node >= 20. ESM and CJS. TypeScript types included.

---

## Quickstart

```ts
import {
  InMemoryChallengeStore,
  InMemoryCredentialStore,
  PasskeyServer,
  RelyingParty,
} from "@particle-academy/fancy-passkeys";

const server = new PasskeyServer({
  relyingParty: new RelyingParty({
    id: "example.com",                     // bare domain, explicit config
    name: "Example App",                   // shown by the authenticator
    origins: ["https://example.com"],      // exact-match allow-list
  }),
  challenges: new InMemoryChallengeStore(),   // swap for Redis in production
  credentials: new InMemoryCredentialStore(), // swap for your database
});
```

### Registration (enrolling a passkey)

Enrollment happens on an **already-authenticated user**.

```ts
// 1. Server issues options.
const { state, publicKey } = await server.startRegistration({
  handle: user.passkeyHandle,   // 32 random bytes, base64url — see "User handles"
  name: user.email,
  displayName: user.fullName,
});
// Send { state, publicKey } to the browser. Keep `state` — the client returns it.

// 2. Browser performs the ceremony (in the UI package, or @simplewebauthn/browser):
//    const response = await startRegistration({ optionsJSON: publicKey });

// 3. Server verifies and persists.
const { credential, summary } = await server.finishRegistration({
  state,
  response,
  name: "MacBook Touch ID",
});
```

### Authentication (signing in)

```ts
// 1. Server issues options. No argument = the discoverable ("usernameless")
//    flow: allowCredentials is empty and the browser shows an account picker.
const { state, publicKey } = await server.startAuthentication();

// Username-first instead? Pass the handle; allowCredentials is filled in.
// const { state, publicKey } = await server.startAuthentication({ userHandle });

// 2. Browser performs the ceremony.
//    const response = await startAuthentication({ optionsJSON: publicKey });

// 3. Server verifies, runs the counter policy, persists, and tells you who it is.
const { userHandle, credential, summary } = await server.finishAuthentication({
  state,
  response,
});
await logIn(userHandle);   // sessions are yours; this package knows nothing about them
```

### Managing passkeys

```ts
const passkeys = await server.listPasskeys(user.passkeyHandle);
// PasskeySummary[] — id, name, createdAt, lastUsedAt, transports, backedUp,
// aaguid, clonedAt. Never the public key, never the user handle.
```

---

## The stores you must implement

Two interfaces. Everything else is defaulted.

### `ChallengeStore`

```ts
interface ChallengeStore {
  put(handle: string, record: ChallengeRecord): Promise<void>;
  pull(handle: string): Promise<ChallengeRecord | null>;
}
```

**`pull` must delete the record as it reads it.** That is not an optimisation —
it is the entire anti-replay mechanism. `PasskeyServer` pulls *before* it
verifies anything, so a replayed response fails at "no such challenge" however
valid its signature is. A store that reads without deleting turns every
assertion into an infinitely replayable token, and nothing anywhere reports it.

The key is the opaque `state` handle, never the challenge itself; keying by the
challenge lets anyone who observes one probe the store for it.

Redis is the natural fit (`GETDEL` plus a native TTL). `InMemoryChallengeStore`
ships for tests and single-process apps — two workers do not share a `Map`, so a
ceremony started on one and finished on the other fails with
`challenge_not_found`.

Returning `null` for an expired record is encouraged, but `PasskeyServer`
re-checks `expiresAt` itself: your store's clock is not its clock, and a
`challenges` table with no cleanup job is a completely ordinary implementation.

### `CredentialStore`

```ts
interface CredentialStore {
  findById(id: string): Promise<StoredCredential | null>;
  findByUserHandle(userHandle: string): Promise<StoredCredential[]>;
  save(credential: StoredCredential): Promise<void>;
  updateAfterAuthentication(id: string, signCount: number, lastUsedAt: string): Promise<void>;
  flagCloned(id: string, clonedAt: string): Promise<void>;
  delete(id: string): Promise<void>;
}
```

- `findById` looks up across **all** users. Registration needs it that way to
  refuse an id registered to somebody else; authentication needs it because a
  discoverable credential arrives with no user attached.
- **`save` must throw `PasskeyError.credentialAlreadyRegistered()` on a
  duplicate id, and the column must carry a `UNIQUE` index** so the throw comes
  from the database. The application check races; the index does not.
- Everything is stored base64url **text**, not binary blobs. Mirroring a store
  across two runtimes and three databases with binary columns is exactly where
  encoding bugs live.

### User handles

The `handle` on `PasskeyUser` is the WebAuthn user handle: **32 random bytes per
user, base64url, minted lazily** by your application. Never the primary key,
never the email. It is transmitted to and stored by every authenticator the user
enrolls, so making it the PK leaks enumerable internal IDs to every device they
ever touch.

```ts
import { toBase64Url } from "@particle-academy/fancy-passkeys";
const handle = toBase64Url(crypto.getRandomValues(new Uint8Array(32)));
```

---

## Security defaults

Every one of these is a decision a WebAuthn integration lives or dies on, so
none is left for you to discover. All are tested; all are mirrored by the PHP
twin.

| Concern | Default | Why |
|---|---|---|
| **Challenge size** | 32 CSPRNG bytes | Never a timestamp, counter, or hash of user data. |
| **Challenge TTL** | 300 s (`challengeTtlSeconds`) | Longer than the 60 s browser timeout so a slow-but-legitimate ceremony is not punished; short enough that a leaked options blob is worthless before it is useful. |
| **Challenge single use** | Always, consumed by `pull` **before** verification | A replayed response fails at "no such challenge" regardless of its signature. |
| **Challenge storage key** | Opaque 32-byte `state` handle | Keying by the challenge lets an observer probe for it. |
| **Ceremony binding** | `type` stored with the record | A registration challenge cannot be redeemed at the login endpoint (`challenge_type_mismatch`). |
| **Origins** | Exact-match allow-list, `https://` only (except `localhost` / `127.0.0.1`) | No wildcards, no regex, no "ends with". The request's own `Origin` header is never used to derive the expected value — that is checking an attacker's claim against itself. |
| **RP ID** | Explicit config, validated at construction | Must equal or be a registrable parent of every origin's host, or `RelyingParty` throws a `TypeError` **at boot**. Never taken from the request. |
| **Credential-ID uniqueness** | Enforced across **all** users | A credential id already registered to another account is an attack or a bug; silently re-pointing it is account takeover. `excludeCredentials` is also populated so the authenticator refuses a duplicate before the round-trip. |
| **User handle check** | Both directions | The challenge's bound handle and the assertion's reported `userHandle` must both match the stored credential (`user_handle_mismatch`). |
| **User verification** | `preferred` | Set `required` and the returned UV flag is *enforced*, not merely requested. |
| **Resident key** | `preferred` | `required` consumes a storage slot on hardware authenticators, which have very few. |
| **Attestation** | `none` | See "Not in scope", below. |
| **Algorithms** | `[-8, -7, -257]` (EdDSA, ES256, RS256) | |
| **Counter policy** | `reject` | See below. |
| **Unknown credential** | Same status and byte-identical message as a bad signature | A distinct answer is a credential-existence oracle. |

### The signature counter

The counter is a monotonic per-credential number some authenticators increment
on each assertion. Its only purpose is **clone detection**: two devices holding
the same private key will eventually produce a counter that goes backwards.

- **Both counters zero → accepted.** Most synced passkey providers (iCloud
  Keychain, Google Password Manager) do not implement counters at all and always
  report 0. A strict `new > stored` rule would reject the majority of real
  passkeys in the world.
- **Otherwise the new counter must be strictly greater.**
- **On regression, `counterPolicy` decides:**
  - `reject` (**default**) — the login fails with `counter_regressed` **and the
    credential is stamped with `clonedAt`**. Both halves matter: fail the login
    without recording it and the real device's next attempt succeeds, leaving no
    trace that anything was ever wrong. The counter is a one-shot detector and
    its entire value is in the record.
  - `log-only` — stamp `clonedAt`, let the login through.
  - `ignore` — **this disables clone detection.** Nothing is flagged and nothing
    is recorded. Said plainly because an option called `ignore` otherwise reads
    as harmless.
- **The new counter is persisted on every success, including when it is 0.**
  Skipping the zero case is the most common silent defeat of the whole
  mechanism: the stored value never advances, so every comparison is against 0
  and the check can never fire.

### Errors

Every failure arrives as a `PasskeyError` with a `code` from a closed set and a
4xx `httpStatus`. `toJSON()` produces the wire body and nothing else — the raw
upstream message is kept on the **non-enumerable** `cause` for your logs, never
on `message`, because it embeds the actual challenge and origin and differs per
failure mode.

```
challenge_expired · challenge_not_found · challenge_type_mismatch ·
origin_not_allowed · rp_id_mismatch · unknown_credential ·
credential_already_registered · counter_regressed ·
user_verification_required · user_handle_mismatch ·
verification_failed · invalid_response · not_supported
```

`mapVerificationError()` is the only place an upstream error is interpreted, and
nothing escapes it untyped — an unrecognised message (including one a future
library version invents) becomes `verification_failed`, never an uncaught throw
your framework renders as a 500.

#### Three codes are true internally and redacted on the wire

Each one answers a question about a credential this server holds, for a caller
who has not authenticated:

| `error.code` | What it would reveal | `toJSON()` sends |
|---|---|---|
| `unknown_credential` | "no such credential here" | `verification_failed` |
| `user_handle_mismatch` | "it exists, but not for this account" | `verification_failed` |
| `counter_regressed` | "it exists and we think it was cloned" | `verification_failed` |

All four share one status (401) and one message, so there is nothing left to
compare. Matching messages alone would not have been enough: `code` is the field
a client branches on, and a distinct code is just as good an oracle as a
distinct message.

`PasskeyError.code` keeps the **precise** value, so your logs and metrics still
see the real answer, and `credentials.flagCloned()` still runs. `wireCode`
tells you what will actually be sent. Only `toJSON()` redacts. Tell the user
about a suspected clone through a channel that has actually identified them; a
login error is readable by a stranger.

### What is *not* closed

**User-enumeration timing.** `POST /login/options` for an unknown email returns
200 with a well-formed payload and an empty `allowCredentials`, never a 404. But
a real lookup still happens, and the timing difference has not been measured or
closed in v1. This is stated plainly rather than implied away. The discoverable
flow — the default — takes no username at all and so has nothing to enumerate.

---

## The wire contract

Both backends emit this, byte for byte. `tests/fixtures/wire/` holds the
fixtures; the PHP twin asserts against the same files.

```
POST {prefix}/register/options    auth required
  → 200 { "state": "<opaque>", "publicKey": PublicKeyCredentialCreationOptionsJSON }

POST {prefix}/register            auth required
  body { "state": "<opaque>", "name"?: string, "response": RegistrationResponseJSON }
  → 201 { "credential": PasskeySummaryJSON }

POST {prefix}/login/options       guest
  body { "email"?: string }        // omitted ⇒ discoverable / usernameless
  → 200 { "state": "<opaque>", "publicKey": PublicKeyCredentialRequestOptionsJSON }

POST {prefix}/login               guest
  body { "state": "<opaque>", "response": AuthenticationResponseJSON }
  → 200 { "user": {...}, "credential": PasskeySummaryJSON }

Errors (all ceremonies) → 4xx
  { "error": { "code": PasskeyErrorCode, "message": string } }
```

`PasskeySummaryJSON`:

```json
{ "id": "base64url", "name": "MacBook Touch ID", "createdAt": "ISO-8601",
  "lastUsedAt": "ISO-8601|null", "transports": ["internal", "hybrid"],
  "backedUp": true, "aaguid": "uuid", "clonedAt": null }
```

The options payloads are the W3C `…JSON` shapes — exactly what
`@simplewebauthn/browser` accepts with no transformation.

To regenerate the fixtures:

```bash
npx tsx scripts/generate-wire-fixtures.ts
```

That is a **wire-contract change**: copy the outputs into the PHP repo's
`tests/fixtures/wire/` in the same session, or the two backends have quietly
stopped agreeing.

---

## Mounting `./http`

`@particle-academy/fancy-passkeys/http` gives you the four endpoints as plain
`(input) => Promise<{ status, body }>` functions. **It imports no HTTP
framework** — the moment it imported Express it would stop working for the Hono
user.

```ts
import { createPasskeyHandlers } from "@particle-academy/fancy-passkeys/http";

const handlers = createPasskeyHandlers(server, {
  async currentUser(ctx) {
    return ctx.session.user ? toPasskeyUser(ctx.session.user) : null;
  },
  async resolveUserByEmail(email) {
    const user = await db.users.findByEmail(email);
    return user ? toPasskeyUser(user) : null;   // null for unknown — never throw
  },
  async onAuthenticated(userHandle, credential, ctx) {
    const user = await db.users.findByPasskeyHandle(userHandle);
    await ctx.session.logIn(user);
    return { id: user.id, email: user.email };  // becomes the `user` field
  },
});
```

### Express

```ts
import express from "express";

const app = express();
const passkeys = express.Router();
passkeys.use(express.json());

const mount = (name: keyof typeof handlers) =>
  async (req: express.Request, res: express.Response, next: express.NextFunction) => {
    try {
      const { status, body } = await handlers[name]({ body: req.body, ctx: req });
      res.status(status).set("Cache-Control", "no-store").json(body);
    } catch (err) {
      next(err);   // genuine 500s stay 500s
    }
  };

passkeys.post("/register/options", mount("registerOptions"));
passkeys.post("/register", mount("register"));
passkeys.post("/login/options", mount("loginOptions"));
passkeys.post("/login", mount("login"));

app.use("/passkeys", passkeys);
```

### Hono

```ts
import { Hono } from "hono";

const app = new Hono();

const mount = (name: keyof typeof handlers) => async (c: Context) => {
  const { status, body } = await handlers[name]({ body: await c.req.json(), ctx: c });
  c.header("Cache-Control", "no-store");
  return c.json(body, status as ContentfulStatusCode);
};

app.post("/passkeys/register/options", mount("registerOptions"));
app.post("/passkeys/register", mount("register"));
app.post("/passkeys/login/options", mount("loginOptions"));
app.post("/passkeys/login", mount("login"));
```

All four are POST. Send `Cache-Control: no-store`. Put **CSRF protection and
rate limiting in front of them** — this package does neither, and an
un-throttled login endpoint next to a throttled one is a bypass, not a feature.
Reuse your existing login limiter so the passkey path is covered by the same
budget.

Authentication middleware belongs in front of the two enrollment routes too. If
`currentUser` returns `null` the handlers answer `401` with code `not_supported`
— the closed error set has no `unauthenticated` member (over in Laravel the
route group sits behind `auth` middleware and the controller is never reached),
so that is the backstop, not the mechanism.

---

## Not in scope for v1

Each of these is a real feature. Shipping a gesture at one is worse than not
shipping it.

- **Attestation trust decisions / FIDO MDS.** `attestation: 'none'` is the
  default and the only fully-supported mode. `direct` can be requested, and the
  statement's format and AAGUID **are stored** — but **no trust decision is made
  from them, by anything, ever.** Verifying attestation meaningfully needs the
  FIDO Metadata Service, certificate-chain validation, and a revocation story;
  half-doing it produces a system that *looks* like it verifies device
  provenance and does not.
- **Enterprise attestation**, and any authenticator allow/deny list by AAGUID.
- **Passkey-only signup.** Creating an account from a registration ceremony with
  no prior user needs an account-provisioning policy, email verification, and an
  anti-abuse story that belong to your application, not to us. Enrollment here
  is always on an authenticated user.
- **Account recovery.** If passkeys are your sole factor and a user loses every
  device, recovery is application policy. We do not invent a second one.
- **Conditional create** (silent enrollment during a password login). The
  browser library supports it; the UX and consent question is not settled, so it
  is not wired.
- **Multi-tenant / per-request RP IDs.** One RP ID per app instance, by
  construction — `RelyingParty` validates it at boot.
- **Sessions, CSRF, rate limiting.** Yours. This package verifies ceremonies and
  persists credentials; what a verified ceremony *means* is your call.

---

## Development

```bash
npm install
npm test       # vitest
npm run lint   # tsc --noEmit && eslint .
npm run build  # tsup
```

Tests cover failure paths first — auth code with only a happy-path test is
untested code, because the happy path is the one an attacker never uses.

## Licence

MIT © Particle Academy
