import { readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { describe, expect, it } from "vitest";

import { RelyingParty } from "../src/relying-party.js";

/**
 * The origin / RP ID table shared with the PHP twin.
 *
 * `particle-academy/fancy-passkeys` drives the SAME file
 * (`tests/fixtures/relying-party/origins.json`), so both backends accept and
 * refuse exactly the same configurations. The table follows what Chromium
 * actually does for WebAuthn: any `*.localhost` host may use http, and an IP
 * literal is refused as an RP ID ("This is an invalid domain").
 */

interface Row {
  rpId: string;
  origin: string;
  why: string;
}

const table = JSON.parse(
  readFileSync(
    resolve(dirname(fileURLToPath(import.meta.url)), "fixtures", "relying-party", "origins.json"),
    "utf8",
  ),
) as { accept: Row[]; reject: Row[] };

function build(row: Row): RelyingParty {
  return new RelyingParty({ id: row.rpId, name: "Example App", origins: [row.origin] });
}

describe("RelyingParty origin table (shared with the PHP twin)", () => {
  it("is not empty on either side", () => {
    // A table that failed to load would make both loops below vacuous.
    expect(table.accept.length).toBeGreaterThan(5);
    expect(table.reject.length).toBeGreaterThan(5);
  });

  it.each(table.accept.map((row) => [row.origin, row.rpId, row] as const))(
    "accepts %s with RP ID %s",
    (_origin, _rpId, row) => {
      const rp = build(row);
      expect(rp.expectedOrigins()).toEqual([row.origin]);
      expect(rp.id).toBe(row.rpId);
    },
  );

  it.each(table.reject.map((row) => [row.origin, row.rpId, row] as const))(
    "refuses %s with RP ID %s",
    (_origin, _rpId, row) => {
      expect(() => build(row)).toThrow(TypeError);
    },
  );

  it("refuses an IP-literal RP ID by name, not by accident of the suffix rule", () => {
    expect(
      () => new RelyingParty({ id: "127.0.0.1", name: "Example App", origins: ["http://127.0.0.1:1"] }),
    ).toThrow(/IP/);
  });
});
