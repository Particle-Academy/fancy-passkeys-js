import { describe, expect, it } from "vitest";

import { canonicalJson } from "../src/canonical-json.js";

/**
 * `canonicalJson` is change-council's canonical form, copied rather than
 * reinvented (`council/lib/record.mjs` `canonical()`, PHP
 * `ChangeCouncil\Support\CanonicalJson`). These are change-council's own
 * assertions, so a local "improvement" that drifts from the kit's one canonical
 * form fails here first.
 */
describe("canonicalJson (change-council's canonical form)", () => {
  it("sorts keys, keeps list order, leaves slashes and non-ASCII alone", () => {
    expect(canonicalJson({ b: 1, a: { y: "é/", x: [3, 1] } })).toBe('{"a":{"x":[3,1],"y":"é/"},"b":1}');
  });

  it("refuses floats", () => {
    expect(() => canonicalJson({ n: 1.5 })).toThrow();
  });

  it("writes an empty object as {} and an empty list as []", () => {
    expect(canonicalJson({ o: {}, l: [] })).toBe('{"l":[],"o":{}}');
  });

  it("has no whitespace", () => {
    expect(canonicalJson({ a: [1, { b: null, c: true }] })).toBe('{"a":[1,{"b":null,"c":true}]}');
  });
});
