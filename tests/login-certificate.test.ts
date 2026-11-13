import { readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { describe, expect, it } from "vitest";

import { canonicalJson } from "../src/canonical-json.js";
import {
  LOGIN_CERTIFICATE_TOKEN_PREFIX,
  isSensitiveClaimKey,
  issueLoginCertificate,
  loginCertificateToken,
  verifyLoginCertificate,
  type LoginCertificateInput,
} from "../src/login-certificate.js";

/**
 * The login-certificate vectors shared with the PHP twin.
 *
 * `particle-academy/fancy-passkeys` drives the SAME file
 * (`tests/fixtures/login-certificate/vectors.json`): given input X, both
 * runtimes must produce certificate C, canonical bytes B and token T. A token
 * minted by one backend has to verify on the other, or a log line written by
 * the PHP app cannot be traced through the Node one.
 */

interface Vector {
  name: string;
  input: LoginCertificateInput;
  certificate: Record<string, unknown>;
  stripped: string[];
  canonical: string;
  token: string;
}

interface Refusal {
  name: string;
  claims: unknown;
}

interface Mismatch {
  name: string;
  certificate: unknown;
  token: string;
}

const fixture = JSON.parse(
  readFileSync(
    resolve(dirname(fileURLToPath(import.meta.url)), "fixtures", "login-certificate", "vectors.json"),
    "utf8",
  ),
) as { tokenPrefix: string; vectors: Vector[]; refuse: Refusal[]; mismatch: Mismatch[] };

/**
 * Computed with `printf '%s' '<canonical>' | sha256sum` — outside this package
 * entirely — so the first vector does not only agree with an implementation
 * that might share a bug with the generator that wrote the fixture.
 */
const MINIMAL_CANONICAL =
  '{"ceremony":"authentication","claims":{},"credentialId":"Y3JlZC1vbmU","issuedAt":"2026-11-13T09:30:00.000Z","nonce":"AAECAwQFBgcICQoLDA0ODw","rpId":"example.com","type":"fancy-passkeys.login-certificate","userHandle":"YWRhLXVzZXItaGFuZGxl","version":1}';
const MINIMAL_TOKEN =
  "fplc_v1_2a5e10b3fda4de20f24436d9da848dee27212e1205782fa5383dc5f541ee929e";

describe("login certificate fixture (shared with the PHP twin)", () => {
  it("is not empty", () => {
    // A fixture that failed to load would make every loop below vacuous.
    expect(fixture.vectors.length).toBeGreaterThanOrEqual(4);
    expect(fixture.refuse.length).toBeGreaterThanOrEqual(5);
    expect(fixture.mismatch.length).toBeGreaterThanOrEqual(3);
    expect(fixture.tokenPrefix).toBe(LOGIN_CERTIFICATE_TOKEN_PREFIX);
  });

  it("pins the minimal vector to a hash computed outside the package", async () => {
    const minimal = fixture.vectors.find((vector) => vector.name === "minimal");
    expect(minimal?.canonical).toBe(MINIMAL_CANONICAL);
    expect(minimal?.token).toBe(MINIMAL_TOKEN);

    const issued = await issueLoginCertificate(minimal!.input);
    expect(issued.canonical).toBe(MINIMAL_CANONICAL);
    expect(issued.token).toBe(MINIMAL_TOKEN);
  });

  it.each(fixture.vectors.map((vector) => [vector.name, vector] as const))(
    "issues vector %s exactly",
    async (_name, vector) => {
      const issued = await issueLoginCertificate(vector.input);

      expect(issued.certificate).toEqual(vector.certificate);
      expect(issued.stripped).toEqual(vector.stripped);
      expect(issued.canonical).toBe(vector.canonical);
      expect(issued.token).toBe(vector.token);
      expect(canonicalJson(issued.certificate)).toBe(vector.canonical);
    },
  );

  it.each(fixture.vectors.map((vector) => [vector.name, vector] as const))(
    "verifies vector %s from the object and from its stored JSON",
    async (_name, vector) => {
      expect(await verifyLoginCertificate(vector.certificate, vector.token)).toBe(true);
      expect(await verifyLoginCertificate(vector.canonical, vector.token)).toBe(true);
      expect(await loginCertificateToken(vector.certificate)).toBe(vector.token);
    },
  );

  it.each(fixture.refuse.map((row) => [row.name, row] as const))(
    "refuses claims: %s",
    async (_name, row) => {
      await expect(
        issueLoginCertificate({ ...fixture.vectors[0]!.input, claims: row.claims as Record<string, unknown> }),
      ).rejects.toThrow(TypeError);
    },
  );

  it.each(fixture.mismatch.map((row) => [row.name, row] as const))(
    "does not verify: %s",
    async (_name, row) => {
      expect(await verifyLoginCertificate(row.certificate, row.token)).toBe(false);
    },
  );
});

describe("issueLoginCertificate", () => {
  const base: LoginCertificateInput = {
    ceremony: "authentication",
    issuedAt: "2026-11-13T09:30:00.000Z",
    nonce: "AAECAwQFBgcICQoLDA0ODw",
    rpId: "example.com",
    credentialId: "Y3JlZC1vbmU",
    userHandle: "YWRhLXVzZXItaGFuZGxl",
  };

  it("token is the prefix plus 64 lowercase hex characters", async () => {
    const { token } = await issueLoginCertificate(base);
    expect(token).toMatch(/^fplc_v1_[0-9a-f]{64}$/);
  });

  it("does not let a claim overwrite a package field", async () => {
    // Claims live under `claims`, never beside the package's own fields, so an
    // app cannot forge `userHandle` or `ceremony` by naming a claim after it.
    const issued = await issueLoginCertificate({
      ...base,
      claims: { userHandle: "forged", ceremony: "registration" },
    });
    expect(issued.certificate.userHandle).toBe(base.userHandle);
    expect(issued.certificate.ceremony).toBe("authentication");
    expect(issued.certificate.claims).toEqual({ userHandle: "forged", ceremony: "registration" });
  });

  it("does not mutate the claims it was given", async () => {
    const claims = { password: "hunter2", device: { token: "t", name: "Phone" } };
    await issueLoginCertificate({ ...base, claims });
    expect(claims).toEqual({ password: "hunter2", device: { token: "t", name: "Phone" } });
  });

  it.each([
    ["undefined", { a: undefined }],
    ["a function", { a: () => 1 }],
    ["a bigint", { a: 1n }],
    ["a Date", { a: new Date(0) }],
    ["a Map", { a: new Map() }],
    ["NaN", { a: Number.NaN }],
    ["Infinity", { a: Number.POSITIVE_INFINITY }],
    ["a lone surrogate", { a: String.fromCharCode(0xd800) }],
    ["a class instance", { a: new (class Thing {})() }],
  ])("refuses %s, which has no canonical JSON form shared with PHP", async (_label, claims) => {
    await expect(issueLoginCertificate({ ...base, claims })).rejects.toThrow(TypeError);
  });

  it.each([
    ["an unknown ceremony", { ceremony: "signup" }],
    ["an empty rpId", { rpId: "" }],
    ["an empty credentialId", { credentialId: "" }],
    ["an empty userHandle", { userHandle: "" }],
    ["a non-base64url nonce", { nonce: "not base64url!" }],
    ["an empty issuedAt", { issuedAt: "" }],
  ])("refuses %s", async (_label, override) => {
    await expect(
      issueLoginCertificate({ ...base, ...(override as Partial<LoginCertificateInput>) }),
    ).rejects.toThrow(TypeError);
  });
});

describe("verifyLoginCertificate", () => {
  it("is false, never a throw, for garbage", async () => {
    expect(await verifyLoginCertificate(null, MINIMAL_TOKEN)).toBe(false);
    expect(await verifyLoginCertificate("{not json", MINIMAL_TOKEN)).toBe(false);
    expect(await verifyLoginCertificate({ version: 1 }, 42)).toBe(false);
    expect(await verifyLoginCertificate({ a: 1.5 }, MINIMAL_TOKEN)).toBe(false);
  });
});

describe("isSensitiveClaimKey", () => {
  it.each([
    "password",
    "Password",
    "db_password",
    "passwd",
    "client_secret",
    "accessToken",
    "csrf-token",
    "api_key",
    "X-Api-Key",
    "Authorization",
    "cookie",
    "Set-Cookie",
    "privateKey",
    "session_id",
    "recovery_codes",
    "otp",
    "TOTP",
    "pin",
    "pwd",
    "cvv",
    "ssn",
    "session",
    "auth",
  ])("strips %s", (key) => {
    expect(isSensitiveClaimKey(key)).toBe(true);
  });

  it.each(["ip", "userAgent", "requestId", "device", "passkeyName", "footprint", "authMethod", "spin", "user"])(
    "keeps %s",
    (key) => {
      expect(isSensitiveClaimKey(key)).toBe(false);
    },
  );
});
