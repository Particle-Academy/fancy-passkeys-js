/**
 * The kit's canonical JSON form — **change-council's, copied, not reinvented.**
 *
 * Source: `change-council` `council/lib/record.mjs` `canonical()`, which must
 * agree byte for byte with `ChangeCouncil\Support\CanonicalJson` (PHP). The PHP
 * twin of this package carries the same copy of the PHP class. Change neither
 * copy on its own: the login-certificate fixture is the shared check that the
 * two still agree.
 *
 * - object keys sorted by code unit, recursively; list order kept
 * - no whitespace; `/` and non-ASCII unescaped (exactly `JSON.stringify`)
 * - floats refused: PHP and JavaScript do not print them the same way
 *
 * Code-unit order equals PHP's byte order only for ASCII keys, and this
 * function does not police that, nor `undefined`, nor class instances. Callers
 * that hash its output for cross-runtime comparison must restrict their input
 * first — `login-certificate.ts` does.
 */
export function canonicalJson(value: unknown): string {
  if (Array.isArray(value)) {
    return `[${value.map(canonicalJson).join(",")}]`;
  }
  if (value !== null && typeof value === "object") {
    const record = value as Record<string, unknown>;
    return `{${Object.keys(record)
      .sort()
      .map((key) => `${JSON.stringify(key)}:${canonicalJson(record[key])}`)
      .join(",")}}`;
  }
  if (typeof value === "number" && !Number.isInteger(value)) {
    throw new TypeError("canonical JSON refuses floats");
  }
  return JSON.stringify(value);
}
