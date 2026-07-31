import { existsSync, readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { describe, expect, it } from "vitest";

/**
 * The dependency shape is a security property here, not housekeeping.
 *
 * Two copies of `@simplewebauthn/server` in one tree means two incompatible
 * `WebAuthnCredential` types, a resolver quietly choosing whichever it likes,
 * and nothing anywhere reporting it. So the library is a **peer**, `external`
 * to the bundler, and never a dependency.
 */

const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");

const pkg = JSON.parse(readFileSync(resolve(root, "package.json"), "utf8")) as {
  dependencies?: Record<string, string>;
  peerDependencies?: Record<string, string>;
  devDependencies?: Record<string, string>;
};

describe("packaging", () => {
  it("has no runtime dependencies at all", () => {
    expect(Object.keys(pkg.dependencies ?? {})).toEqual([]);
  });

  it("declares @simplewebauthn/server as a peer", () => {
    expect(pkg.peerDependencies?.["@simplewebauthn/server"]).toBeTruthy();
  });

  it("also keeps it as a devDependency, so the suite is built against a known version", () => {
    // The peer range is wide by design; the devDependency is the version this
    // package is actually tested against, which is what turns the wide range
    // into a tested claim rather than a hopeful one.
    expect(pkg.devDependencies?.["@simplewebauthn/server"]).toBeTruthy();
  });

  it("marks it external to the bundler", () => {
    const config = readFileSync(resolve(root, "tsup.config.ts"), "utf8");
    expect(config).toMatch(/external:\s*\[[^\]]*"@simplewebauthn\/server"/);
  });

  it("does not inline it into the build", () => {
    // Runs whenever `dist/` exists (locally, and in CI when build precedes
    // test). The bundled copy would show up as the disappearance of this
    // import, so its presence is the assertion.
    const dist = resolve(root, "dist", "index.js");
    if (!existsSync(dist)) {
      expect(existsSync(resolve(root, "tsup.config.ts"))).toBe(true);
      return;
    }

    const built = readFileSync(dist, "utf8");
    expect(built).toMatch(/from\s*["']@simplewebauthn\/server["']/);
    // A telltale of the library's own source having been pulled in.
    expect(built).not.toMatch(/isoBase64URL/);
  });

  it("exposes ./http as its own entry so the core never imports request code", () => {
    const config = readFileSync(resolve(root, "tsup.config.ts"), "utf8");
    expect(config).toMatch(/src\/index\.ts/);
    expect(config).toMatch(/src\/http\.ts/);
  });

  it("keeps the ./http entry free of any HTTP framework", () => {
    // The moment this file imports Express it stops working for the Hono user.
    const source = readFileSync(resolve(root, "src", "http.ts"), "utf8");
    const imports = [...source.matchAll(/from\s+"([^"]+)"/g)].map((match) => match[1]);

    for (const specifier of imports) {
      expect(
        specifier?.startsWith(".") || specifier === "@simplewebauthn/server",
        `unexpected import "${specifier ?? ""}" in src/http.ts`,
      ).toBe(true);
    }
  });
});
