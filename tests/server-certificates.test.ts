import { describe, expect, it, vi } from "vitest";

import { createPasskeyHandlers } from "../src/http.js";
import { verifyLoginCertificate, type IssuedLoginCertificate } from "../src/login-certificate.js";
import { PasskeyServer, type PasskeyServerOptions } from "../src/server.js";
import { InMemoryChallengeStore, InMemoryCredentialStore } from "../src/stores.js";

import {
  ADA_HANDLE,
  FakeVerifier,
  RP_ID,
  ada,
  authenticationResponse,
  makeRelyingParty,
  makeStoredCredential,
  registrationResponse,
  sequentialBytes,
} from "./helpers.js";

const NOW = Date.parse("2026-11-13T09:30:00.000Z");

function setup(loginCertificates?: PasskeyServerOptions["loginCertificates"]) {
  const verifier = new FakeVerifier();
  const credentials = new InMemoryCredentialStore();
  const server = new PasskeyServer({
    relyingParty: makeRelyingParty(),
    challenges: new InMemoryChallengeStore({ now: () => NOW }),
    credentials,
    verifier,
    now: () => NOW,
    randomBytes: sequentialBytes(),
    ...(loginCertificates === undefined ? {} : { loginCertificates }),
  });
  return { server, verifier, credentials };
}

async function signIn(
  server: PasskeyServer,
  credentials: InMemoryCredentialStore,
  certificateClaims?: Record<string, unknown>,
) {
  await credentials.save(makeStoredCredential({ id: "Y3JlZC1vbmU" }));
  const { state } = await server.startAuthentication();
  return server.finishAuthentication({
    state,
    response: authenticationResponse("Y3JlZC1vbmU"),
    ...(certificateClaims === undefined ? {} : { certificateClaims }),
  });
}

describe("login certificates are off by default", () => {
  it("issues nothing and calls nothing when not configured", async () => {
    const { server, credentials } = setup();
    const result = await signIn(server, credentials, { ip: "203.0.113.7" });
    expect(result.certificate).toBeNull();
  });

  it("issues nothing for `false`", async () => {
    const { server, credentials } = setup(false);
    const result = await signIn(server, credentials);
    expect(result.certificate).toBeNull();
  });

  it("issues nothing for registration either", async () => {
    const { server } = setup();
    const { state } = await server.startRegistration(ada());
    const result = await server.finishRegistration({ state, response: registrationResponse("bmV3") });
    expect(result.certificate).toBeNull();
  });
});

describe("login certificates when enabled", () => {
  it("issues one on sign-in, carrying the ceremony facts and the claims", async () => {
    const { server, credentials } = setup({});
    const result = await signIn(server, credentials, { ip: "203.0.113.7", requestId: "req-1" });

    const issued = result.certificate!;
    expect(issued.certificate).toMatchObject({
      type: "fancy-passkeys.login-certificate",
      version: 1,
      ceremony: "authentication",
      issuedAt: "2026-11-13T09:30:00.000Z",
      rpId: RP_ID,
      credentialId: "Y3JlZC1vbmU",
      userHandle: ADA_HANDLE,
      claims: { ip: "203.0.113.7", requestId: "req-1" },
    });
    // 16 bytes from the injected CSPRNG: unguessable, so a token cannot be
    // reversed by enumerating plausible IPs and timestamps.
    expect(issued.certificate.nonce).toMatch(/^[A-Za-z0-9_-]{22}$/);
    expect(issued.token).toMatch(/^fplc_v1_[0-9a-f]{64}$/);
    expect(await verifyLoginCertificate(issued.certificate, issued.token)).toBe(true);
  });

  it("issues one on registration, with the new credential", async () => {
    const { server } = setup({});
    const { state } = await server.startRegistration(ada());
    const result = await server.finishRegistration({
      state,
      response: registrationResponse("bmV3LWNyZWQ"),
      certificateClaims: { device: "Phone" },
    });
    expect(result.certificate?.certificate).toMatchObject({
      ceremony: "registration",
      credentialId: "bmV3LWNyZWQ",
      userHandle: ADA_HANDLE,
      claims: { device: "Phone" },
    });
  });

  it("can be limited to sign-in", async () => {
    const { server } = setup({ ceremonies: ["authentication"] });
    const { state } = await server.startRegistration(ada());
    const result = await server.finishRegistration({ state, response: registrationResponse("bmV3") });
    expect(result.certificate).toBeNull();
  });

  it("gives every sign-in a different nonce, so identical logins have different tokens", async () => {
    const { server, credentials, verifier } = setup({});
    const first = await signIn(server, credentials, { ip: "203.0.113.7" });
    verifier.newCounter = 2;
    const { state } = await server.startAuthentication();
    const second = await server.finishAuthentication({
      state,
      response: authenticationResponse("Y3JlZC1vbmU"),
      certificateClaims: { ip: "203.0.113.7" },
    });
    expect(first.certificate!.certificate.nonce).not.toBe(second.certificate!.certificate.nonce);
    expect(first.certificate!.token).not.toBe(second.certificate!.token);
  });

  it("strips known-sensitive claims and reports where", async () => {
    const { server, credentials } = setup({});
    const result = await signIn(server, credentials, {
      ip: "203.0.113.7",
      password: "hunter2",
      device: { name: "Phone", sessionId: "abc" },
    });
    expect(result.certificate!.certificate.claims).toEqual({ ip: "203.0.113.7", device: { name: "Phone" } });
    expect(result.certificate!.stripped).toEqual(["claims.device.sessionId", "claims.password"]);
  });

  it("merges the host's default claims under the per-call claims", async () => {
    const claims = vi.fn(() => ({ app: "desktop", ip: "default" }));
    const { server, credentials } = setup({ claims });
    const result = await signIn(server, credentials, { ip: "203.0.113.7" });

    expect(claims).toHaveBeenCalledWith({
      ceremony: "authentication",
      rpId: RP_ID,
      credentialId: "Y3JlZC1vbmU",
      userHandle: ADA_HANDLE,
    });
    expect(result.certificate!.certificate.claims).toEqual({ app: "desktop", ip: "203.0.113.7" });
  });

  it("delivers the certificate and token to the host hook, and stores nothing itself", async () => {
    const delivered: IssuedLoginCertificate[] = [];
    const { server, credentials } = setup({ deliver: (issued) => void delivered.push(issued) });
    const result = await signIn(server, credentials, { ip: "203.0.113.7" });

    expect(delivered).toHaveLength(1);
    expect(delivered[0]).toEqual(result.certificate);
  });

  it("waits for an async delivery, and a failing delivery fails the call", async () => {
    // A host that opted in to an audit trail would rather a sign-in fail than
    // succeed with no record; a host that would not catches in its own hook.
    const { server, credentials } = setup({ deliver: () => Promise.reject(new Error("log sink down")) });
    await expect(signIn(server, credentials)).rejects.toThrow("log sink down");
  });

  it("issues nothing when the ceremony fails", async () => {
    const deliver = vi.fn();
    const { server, credentials, verifier } = setup({ deliver });
    verifier.authenticationVerified = false;
    await expect(signIn(server, credentials)).rejects.toMatchObject({ code: "verification_failed" });
    expect(deliver).not.toHaveBeenCalled();
  });
});

describe("the ./http adapter", () => {
  it("takes request-level claims from a hook and hands the certificate to onAuthenticated", async () => {
    const { server, credentials } = setup({});
    await credentials.save(makeStoredCredential({ id: "Y3JlZC1vbmU" }));

    const onAuthenticated = vi.fn(async () => ({ id: 1 }));
    const handlers = createPasskeyHandlers<{ ip: string }>(server, {
      currentUser: async () => ada(),
      onAuthenticated,
      certificateClaims: (ctx) => ({ ip: ctx.ip }),
    });

    const options = await handlers.loginOptions({ ctx: { ip: "203.0.113.7" } });
    const state = (options.body as { state: string }).state;
    const result = await handlers.login({
      body: { state, response: authenticationResponse("Y3JlZC1vbmU") },
      ctx: { ip: "203.0.113.7" },
    });

    expect(result.status).toBe(200);
    // The wire contract does not change: the certificate is server-side only.
    expect(Object.keys(result.body as object).sort()).toEqual(["credential", "user"]);

    const certificate = (onAuthenticated.mock.calls[0] as unknown[])[3] as IssuedLoginCertificate;
    expect(certificate.certificate.claims).toEqual({ ip: "203.0.113.7" });
  });
});

describe("registration verification is held to the policy's algorithms", () => {
  it("passes the policy's algorithm list to verifyRegistrationResponse", async () => {
    // v14 widened the library's own default (ML-DSA where the runtime has it).
    // The offered list and the accepted list must be the same list; the PHP
    // twin enforces this through web-auth's CheckAlgorithm step.
    const { server, verifier } = setup();
    const { state } = await server.startRegistration(ada());
    await server.finishRegistration({ state, response: registrationResponse("bmV3") });
    expect(verifier.lastRegistrationOpts?.supportedAlgorithmIDs).toEqual([-8, -7, -257]);
  });
});
