/**
 * Relying-party configuration: who we are, and which origins are allowed to
 * complete a ceremony on our behalf.
 *
 * Everything here is validated **at construction**, i.e. at boot. A misconfigured
 * RP ID that is not a suffix of its origins produces a WebAuthn ceremony that
 * fails on every device, for every user, with an error message about an
 * "Unexpected RP ID hash" that names neither the cause nor the fix. Catching it
 * when the object is built turns a mystifying production outage into a stack
 * trace at startup.
 *
 * These are **programmer errors, not authentication failures**, so they throw
 * `TypeError` rather than `PasskeyError`: there is no client to tell, no wire
 * code to emit, and nothing an end user could do differently.
 */

/** Constructor input for {@link RelyingParty}. */
export interface RelyingPartyOptions {
  /**
   * The RP ID — a bare domain, no scheme, no port, no path (`example.com`).
   *
   * It scopes the credential: the authenticator will only ever offer this
   * passkey back to this domain and its subdomains. It is **explicit config**
   * and is never derived from a request; an attacker-supplied RP ID is how you
   * mint a credential that works on a domain you do not control.
   */
  id: string;
  /** The user-visible name shown by the authenticator during enrollment. */
  name: string;
  /**
   * The exact origins a ceremony may be completed from — full origin strings
   * (`https://app.example.com`, `http://localhost:5173`), matched by equality.
   *
   * No wildcards, no regex, no "ends with". The request's own `Origin` /
   * `Referer` header is never consulted to build this list, because checking an
   * attacker's claim against itself is not a check.
   *
   * **Or a function**, for an app whose origin is only known at run time — a
   * desktop app serving its UI from a local server on a port chosen at launch.
   * It is called on EVERY verification, and every list it returns is held to
   * exactly the rules a static list is held to at construction (https, or http
   * on `localhost` / `*.localhost`; no IP literals; the RP ID must be the host
   * or a registrable suffix of it). A resolver is a way to change the
   * allow-list, never a way around it.
   */
  origins: readonly string[] | OriginResolver;
}

/**
 * Returns the allowed origins for the verification about to run.
 *
 * May be async. Must not consult the request being verified: deriving the
 * expected origin from the request is checking the attacker's claim against
 * itself, and a resolver is no exception.
 */
export type OriginResolver = () => readonly string[] | Promise<readonly string[]>;

/**
 * Whether plain `http://` is tolerated for this host: `localhost` itself, or any
 * `*.localhost` name, matched by LABEL (every label non-empty, the last one
 * exactly `localhost`). `localhost.evil.com` and `evilocalhost` do not qualify.
 *
 * This is what Chromium accepts for WebAuthn, and it is the whole list: an IP
 * literal such as `127.0.0.1` is refused by the browser as an RP ID ("This is an
 * invalid domain"), so it is refused here too. Mirrored in the PHP twin's
 * `RelyingParty::isLocalhost()`; both are driven by the shared fixture table.
 */
function isLocalhost(host: string): boolean {
  const labels = host.split(".");
  return labels.every((label) => label.length > 0) && labels[labels.length - 1] === "localhost";
}

/**
 * Whether a host is an IP literal, which WebAuthn never accepts as an RP ID.
 *
 * IPv6 is anything bracketed or containing a colon. IPv4 follows the URL
 * standard's "ends in a number" rule — the last label all digits, or `0x` plus
 * hex — because that is exactly when a browser parses a host as IPv4, so short
 * forms such as `127.1` are caught as well as dotted quads.
 */
function isIpLiteral(host: string): boolean {
  if (host.includes(":") || host.startsWith("[")) {
    return true;
  }
  const labels = host.split(".");
  if (labels.length > 1 && labels[labels.length - 1] === "") {
    labels.pop();
  }
  const last = labels[labels.length - 1] ?? "";
  return /^[0-9]+$/.test(last) || /^0x[0-9a-f]*$/i.test(last);
}

/**
 * A validated relying party.
 *
 * @example
 * ```ts
 * const rp = new RelyingParty({
 *   id: "example.com",
 *   name: "Example App",
 *   origins: ["https://example.com", "https://app.example.com"],
 * });
 * ```
 */
export class RelyingParty {
  readonly id: string;
  readonly name: string;
  #origins: readonly string[] | OriginResolver;

  constructor(options: RelyingPartyOptions) {
    const id = typeof options.id === "string" ? options.id.trim().toLowerCase() : "";
    if (id.length === 0) {
      throw new TypeError("RelyingParty `id` must be a non-empty domain, e.g. \"example.com\".");
    }
    if (id.includes("/") || id.includes(":")) {
      throw new TypeError(
        `RelyingParty \`id\` must be a bare domain with no scheme, port, or path — got "${options.id}".`,
      );
    }
    if (isIpLiteral(id)) {
      throw new TypeError(
        `RelyingParty \`id\` must be a domain name, not an IP address — got "${options.id}". Browsers refuse an IP literal as an RP ID; for local development use "localhost" or a "*.localhost" name.`,
      );
    }

    const name = typeof options.name === "string" ? options.name.trim() : "";
    if (name.length === 0) {
      throw new TypeError(
        "RelyingParty `name` must be a non-empty string; the authenticator shows it to the user during enrollment.",
      );
    }

    this.id = id;
    this.name = name;
    this.#origins = typeof options.origins === "function"
      ? options.origins
      : validateOrigins(id, options.origins);
  }

  /** Whether the origins come from a resolver rather than a fixed list. */
  get hasDynamicOrigins(): boolean {
    return typeof this.#origins === "function";
  }

  /**
   * The configured allow-list. For a resolver this resolves it now — see
   * {@link expectedOrigins}.
   */
  get origins(): readonly string[] {
    return Object.freeze(this.expectedOrigins());
  }

  /**
   * Replace the allowed origins: a new fixed list, or a resolver.
   *
   * A fixed list is validated here, and when it is refused the previous
   * configuration stays in place — a failed update must not leave the relying
   * party with no allow-list, or with a half-applied one.
   */
  setOrigins(origins: readonly string[] | OriginResolver): void {
    this.#origins = typeof origins === "function" ? origins : validateOrigins(this.id, origins);
  }

  /**
   * The allow-list to hand the verifier as `expectedOrigin`, synchronously.
   *
   * A synchronous resolver is called and its result validated. An async one
   * cannot be answered here, so this throws and points at
   * {@link resolveOrigins}, which is what `PasskeyServer` uses.
   *
   * Returns a fresh array so a caller cannot mutate the configured list.
   */
  expectedOrigins(): string[] {
    const source = this.#origins;
    if (typeof source !== "function") {
      return [...source];
    }
    const resolved = source();
    if (isPromiseLike(resolved)) {
      throw new TypeError(
        "RelyingParty origins come from an async resolver; call `await relyingParty.resolveOrigins()` instead of expectedOrigins().",
      );
    }
    return [...validateOrigins(this.id, resolved)];
  }

  /**
   * The allow-list for the verification about to run.
   *
   * A resolver is called on every call, and whatever it returns is validated
   * with the construction rules every time — a value that would have been
   * refused at boot is refused here, and the ceremony never reaches the
   * verifier. A resolver that throws propagates: no list is never "allow all".
   */
  async resolveOrigins(): Promise<string[]> {
    const source = this.#origins;
    if (typeof source !== "function") {
      return [...source];
    }
    return [...validateOrigins(this.id, await source())];
  }
}

function isPromiseLike(value: unknown): value is PromiseLike<unknown> {
  return (
    typeof value === "object" &&
    value !== null &&
    typeof (value as { then?: unknown }).then === "function"
  );
}

/**
 * The origin rules, in one place, so a static list at construction, a list
 * passed to `setOrigins`, and every list a resolver returns are held to exactly
 * the same checks. Returns a frozen copy.
 */
function validateOrigins(id: string, candidate: unknown): readonly string[] {
  const origins: unknown[] = Array.isArray(candidate) ? candidate : [];
  if (origins.length === 0) {
    throw new TypeError(
      "RelyingParty `origins` must list at least one origin. It is an exact-match allow-list, never derived from the request.",
    );
  }

  for (const origin of origins) {
    if (typeof origin !== "string") {
      throw new TypeError("Every RelyingParty origin must be a string.");
    }

    let url: URL;
    try {
      url = new URL(origin);
    } catch {
      throw new TypeError(
        `RelyingParty origin "${origin}" is not a valid URL. Use a full origin, e.g. "https://example.com".`,
      );
    }

    // The browser reports `clientData.origin` in canonical serialised form
    // (`scheme://host[:port]`, never a trailing slash). Anything else here
    // would never match, so it is rejected now rather than on every login.
    if (url.origin !== origin) {
      throw new TypeError(
        `RelyingParty origin "${origin}" must be exactly a serialised origin with no path or trailing slash — did you mean "${url.origin}"?`,
      );
    }

    const host = url.hostname.toLowerCase();

    if (isIpLiteral(host)) {
      throw new TypeError(
        `RelyingParty origin "${origin}" has an IP-address host. WebAuthn needs a domain name; for local development use "localhost" or a "*.localhost" name.`,
      );
    }

    if (url.protocol !== "https:" && !(url.protocol === "http:" && isLocalhost(host))) {
      throw new TypeError(
        `RelyingParty origin "${origin}" must use https. Only localhost and *.localhost hosts may use http.`,
      );
    }

    // The RP ID must be the origin's host or a registrable parent of it —
    // exactly the rule the browser applies before it will run the ceremony.
    if (host !== id && !host.endsWith(`.${id}`)) {
      throw new TypeError(
        `RelyingParty id "${id}" is not the host of origin "${origin}" nor a registrable parent of it. The browser would reject every ceremony.`,
      );
    }
  }

  return Object.freeze([...(origins as string[])]);
}
