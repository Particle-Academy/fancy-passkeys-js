/**
 * Writes tests/fixtures/login-certificate/vectors.json — the login-certificate
 * conformance fixture shared byte for byte with the PHP twin
 * (particle-academy/fancy-passkeys, same path). Copy the file across after
 * regenerating it.
 *
 *   npx tsx scripts/generate-certificate-fixtures.ts
 *
 * The INPUTS and the EXPECTED certificates (what survives stripping) are
 * written by hand below. Only `canonical` and `token` are computed, and the
 * script refuses to write anything if the implementation's certificate or
 * stripped list differs from the hand-written expectation — so regenerating
 * cannot quietly bless a change in what gets stripped.
 *
 * Characters that are invisible or that are escape-sensitive (U+2028, control
 * characters, the backslash) are built with String.fromCharCode rather than
 * typed, so no editor or shell can mangle them on the way into this file, and
 * U+2028 / U+2029 are written to the JSON as escapes so the fixture stays
 * readable.
 */

import { writeFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { isDeepStrictEqual } from "node:util";

import { issueLoginCertificate, type LoginCertificateInput } from "../src/login-certificate.js";

const BACKSLASH = String.fromCharCode(92);
const LINE_SEPARATOR = String.fromCharCode(0x2028);
const PARAGRAPH_SEPARATOR = String.fromCharCode(0x2029);
const TAB = String.fromCharCode(9);
const SOH = String.fromCharCode(1);

const subject = {
  issuedAt: "2026-11-13T09:30:00.000Z",
  // 16 bytes 0x00..0x0f, base64url.
  nonce: "AAECAwQFBgcICQoLDA0ODw",
  rpId: "example.com",
  credentialId: "Y3JlZC1vbmU",
  // base64url("ada-user-handle")
  userHandle: "YWRhLXVzZXItaGFuZGxl",
};

const envelope = { type: "fancy-passkeys.login-certificate", version: 1 };

interface Case {
  name: string;
  input: LoginCertificateInput;
  expectedClaims: Record<string, unknown>;
  stripped: string[];
}

const unicodeClaims = {
  note: "café / naïve",
  emoji: "🔑",
  separators: `a${LINE_SEPARATOR}b${PARAGRAPH_SEPARATOR}c`,
  control: `tab${TAB}here${SOH}`,
  quote: `say "hi" ${BACKSLASH} back`,
  nested: { empty: {}, list: [], deep: [1, -2, true, false, null, { z: 1, a: 2 }] },
  big: 9007199254740991,
  neg: -9007199254740991,
  "key with space": 1,
  Zed: 1,
  alpha: 1,
  _under: 1,
};

const cases: Case[] = [
  {
    name: "minimal",
    input: { ceremony: "authentication", ...subject },
    expectedClaims: {},
    stripped: [],
  },
  {
    name: "typical-sign-in",
    input: {
      ceremony: "authentication",
      ...subject,
      claims: {
        ip: "203.0.113.7",
        userAgent: "Mozilla/5.0 (X11; Linux x86_64)",
        requestId: "req_01HZX",
        user: { id: 42, email: "ada@example.com" },
        device: { name: "MacBook Touch ID", platform: "macOS" },
        at: "2026-11-13T09:30:00.000Z",
      },
    },
    expectedClaims: {
      ip: "203.0.113.7",
      userAgent: "Mozilla/5.0 (X11; Linux x86_64)",
      requestId: "req_01HZX",
      user: { id: 42, email: "ada@example.com" },
      device: { name: "MacBook Touch ID", platform: "macOS" },
      at: "2026-11-13T09:30:00.000Z",
    },
    stripped: [],
  },
  {
    name: "registration-unicode-and-edges",
    input: { ceremony: "registration", ...subject, claims: unicodeClaims },
    expectedClaims: unicodeClaims,
    stripped: [],
  },
  {
    name: "sensitive-claims-stripped",
    input: {
      ceremony: "authentication",
      ...subject,
      claims: {
        ip: "203.0.113.7",
        password: "hunter2",
        api_key: "k1",
        "X-Api-Key": "k2",
        accessToken: "t1",
        Authorization: "Bearer t2",
        cookie: "c1",
        set_cookie: "c2",
        otp: "123456",
        footprint: "kept: otp only matches as the whole key",
        passkeyName: "kept: passkey is not password",
        authMethod: "kept: auth only matches as the whole key",
        device: { name: "Phone", sessionId: "s1", pin: "1234" },
        list: [{ secret: "x", keep: 1 }],
      },
    },
    expectedClaims: {
      ip: "203.0.113.7",
      footprint: "kept: otp only matches as the whole key",
      passkeyName: "kept: passkey is not password",
      authMethod: "kept: auth only matches as the whole key",
      device: { name: "Phone" },
      list: [{ keep: 1 }],
    },
    stripped: [
      "claims.Authorization",
      "claims.X-Api-Key",
      "claims.accessToken",
      "claims.api_key",
      "claims.cookie",
      "claims.device.pin",
      "claims.device.sessionId",
      "claims.list[0].secret",
      "claims.otp",
      "claims.password",
      "claims.set_cookie",
    ],
  },
];

const refuse = [
  { name: "a float", claims: { n: 1.5 } },
  { name: "an integer past 2^53-1", claims: { n: 9007199254740992 } },
  { name: "a float inside a list", claims: { list: [1, 2.5] } },
  { name: "a non-ASCII key", claims: { "clé": 1 } },
  { name: "an all-digit key", claims: { "123": 1 } },
  { name: "a negative all-digit key", claims: { "-1": 1 } },
  { name: "a nested all-digit key", claims: { device: { "0": "a" } } },
  { name: "claims that are a list", claims: [1, 2] },
  { name: "claims that are a string", claims: "ip=203.0.113.7" },
];

async function main(): Promise<void> {
  const vectors = [];
  for (const c of cases) {
    const issued = await issueLoginCertificate(c.input);
    const expectedCertificate = { ...envelope, ceremony: c.input.ceremony, ...subject, claims: c.expectedClaims };

    if (!isDeepStrictEqual(issued.certificate, expectedCertificate)) {
      throw new Error(`${c.name}: issued certificate differs from the hand-written expectation`);
    }
    if (!isDeepStrictEqual(issued.stripped, c.stripped)) {
      throw new Error(`${c.name}: stripped ${JSON.stringify(issued.stripped)}, expected ${JSON.stringify(c.stripped)}`);
    }

    vectors.push({
      name: c.name,
      input: c.input,
      certificate: issued.certificate,
      stripped: issued.stripped,
      canonical: issued.canonical,
      token: issued.token,
    });
  }

  const typical = vectors[1]!;
  const tamperedCertificate = {
    ...typical.certificate,
    claims: { ...(typical.certificate.claims as Record<string, unknown>), ip: "203.0.113.8" },
  };

  const mismatch = [
    { name: "a changed claim", certificate: tamperedCertificate, token: typical.token },
    { name: "an upper-case token", certificate: typical.certificate, token: typical.token.toUpperCase() },
    { name: "an unknown token version", certificate: typical.certificate, token: typical.token.replace("fplc_v1_", "fplc_v2_") },
    { name: "a truncated token", certificate: typical.certificate, token: typical.token.slice(0, -1) },
    { name: "another vector's token", certificate: typical.certificate, token: vectors[0]!.token },
    {
      name: "a certificate claiming version 2 with the hash of its own bytes",
      certificate: { ...vectors[0]!.certificate, version: 2 },
      // The SHA-256 of the version-2 bytes is irrelevant: verification refuses
      // any certificate that is not v1 before it hashes anything.
      token: vectors[0]!.token,
    },
  ];

  const fixture = {
    about:
      "Login-certificate conformance vectors, shared byte for byte by @particle-academy/fancy-passkeys (Node) and particle-academy/fancy-passkeys (PHP) at tests/fixtures/login-certificate/vectors.json. Given input X, both runtimes produce certificate C, canonical bytes B (change-council's canonical JSON) and token T = 'fplc_v1_' + lowercase hex SHA-256 of B. Generated by fancy-passkeys-js scripts/generate-certificate-fixtures.ts from hand-written inputs and expectations; regenerate there and copy here.",
    tokenPrefix: "fplc_v1_",
    vectors,
    refuse,
    mismatch,
  };

  let json = `${JSON.stringify(fixture, null, 2)}\n`;
  for (const ch of [LINE_SEPARATOR, PARAGRAPH_SEPARATOR]) {
    json = json.split(ch).join(`${BACKSLASH}u${ch.charCodeAt(0).toString(16).padStart(4, "0")}`);
  }

  const target = resolve(
    dirname(fileURLToPath(import.meta.url)),
    "..",
    "tests",
    "fixtures",
    "login-certificate",
    "vectors.json",
  );
  writeFileSync(target, json, "utf8");
  console.log(`wrote ${vectors.length} vectors, ${refuse.length} refusals, ${mismatch.length} mismatches to ${target}`);
}

await main();
