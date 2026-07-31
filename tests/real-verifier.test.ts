import {
  generateAuthenticationOptions,
  generateRegistrationOptions,
  verifyAuthenticationResponse,
  verifyRegistrationResponse,
} from "@simplewebauthn/server";
import { describe, expect, it } from "vitest";

import { PasskeyServer, defaultVerifier } from "../src/server.js";
import { InMemoryChallengeStore, InMemoryCredentialStore } from "../src/stores.js";

import { ADA_HANDLE, RP_ID, ada, makeRelyingParty, makeStoredCredential } from "./helpers.js";

describe("defaultVerifier", () => {
  /**
   * The whole rest of the suite drives a fake verifier, because reaching a real
   * one needs an authenticator and a human fingerprint. That makes exactly one
   * mistake catastrophic and invisible: shipping the fake. These are identity
   * checks — not "behaves like", but "is".
   */
  it("is the real @simplewebauthn/server, by identity", () => {
    expect(defaultVerifier.generateRegistrationOptions).toBe(generateRegistrationOptions);
    expect(defaultVerifier.verifyRegistrationResponse).toBe(verifyRegistrationResponse);
    expect(defaultVerifier.generateAuthenticationOptions).toBe(generateAuthenticationOptions);
    expect(defaultVerifier.verifyAuthenticationResponse).toBe(verifyAuthenticationResponse);
  });
});

describe("a PasskeyServer with no verifier injected", () => {
  function realServer(credentials = new InMemoryCredentialStore()): PasskeyServer {
    return new PasskeyServer({
      relyingParty: makeRelyingParty(),
      challenges: new InMemoryChallengeStore(),
      credentials,
    });
  }

  it("produces real registration options", async () => {
    const { state, publicKey } = await realServer().startRegistration(ada());

    expect(state).toMatch(/^[A-Za-z0-9_-]{43}$/); // 32 bytes, base64url, unpadded
    expect(publicKey.rp).toEqual({ id: RP_ID, name: "Example App" });
    // The user handle must survive the byte round-trip the library performs.
    expect(publicKey.user).toEqual({
      id: ADA_HANDLE,
      name: "ada@example.com",
      displayName: "Ada Lovelace",
    });
    // 32 random bytes, base64url encoded by the library — not the UTF-8 of a
    // string we handed it, which is what passing our own base64url would do.
    expect(publicKey.challenge).toMatch(/^[A-Za-z0-9_-]{43}$/);
    expect(publicKey.pubKeyCredParams.map((param) => param.alg)).toEqual([-8, -7, -257]);
    expect(publicKey.timeout).toBe(60_000);
    expect(publicKey.attestation).toBe("none");
    expect(publicKey.authenticatorSelection).toMatchObject({
      residentKey: "preferred",
      userVerification: "preferred",
      requireResidentKey: false,
    });
    expect(publicKey.extensions).toMatchObject({ credProps: true });
    expect(publicKey.excludeCredentials).toEqual([]);
  });

  it("produces real authentication options for the discoverable flow", async () => {
    const { publicKey } = await realServer().startAuthentication();

    expect(publicKey.rpId).toBe(RP_ID);
    expect(publicKey.challenge).toMatch(/^[A-Za-z0-9_-]{43}$/);
    expect(publicKey.allowCredentials).toEqual([]);
    expect(publicKey.timeout).toBe(60_000);
    expect(publicKey.userVerification).toBe("preferred");
  });

  it("passes real stored credentials through as descriptors", async () => {
    const credentials = new InMemoryCredentialStore([
      makeStoredCredential({ id: "Y3JlZC1vbmU", transports: ["internal", "hybrid"] }),
    ]);

    const registration = await realServer(credentials).startRegistration(ada());
    expect(registration.publicKey.excludeCredentials).toEqual([
      { id: "Y3JlZC1vbmU", type: "public-key", transports: ["internal", "hybrid"] },
    ]);

    const authentication = await realServer(credentials).startAuthentication({
      userHandle: ADA_HANDLE,
    });
    expect(authentication.publicKey.allowCredentials).toEqual([
      { id: "Y3JlZC1vbmU", type: "public-key", transports: ["internal", "hybrid"] },
    ]);
  });

  it("issues a different challenge every time", async () => {
    const server = realServer();
    const first = await server.startAuthentication();
    const second = await server.startAuthentication();

    expect(first.publicKey.challenge).not.toBe(second.publicKey.challenge);
    expect(first.state).not.toBe(second.state);
  });
});
