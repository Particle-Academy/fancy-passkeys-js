import { readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { describe, expect, it } from "vitest";

import { RelyingParty } from "../src/relying-party.js";
import { PasskeyServer } from "../src/server.js";
import { InMemoryChallengeStore, InMemoryCredentialStore } from "../src/stores.js";

import {
  FakeVerifier,
  ORIGIN,
  RP_ID,
  ada,
  authenticationResponse,
  makeStoredCredential,
  registrationResponse,
  sequentialBytes,
} from "./helpers.js";

/**
 * `origins` as a function, for desktop apps whose origin is not known until
 * the app is running (a local server on a port picked at launch).
 *
 * The rule under test: a resolved list is held to EXACTLY the construction
 * rules, on EVERY verification. A resolver is not a way around the allow-list;
 * a value it returns that the constructor would refuse is refused, every time.
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

describe("RelyingParty with an origin resolver", () => {
  it("does not call the resolver at construction", () => {
    let calls = 0;
    const rp = new RelyingParty({
      id: RP_ID,
      name: "Example App",
      origins: () => {
        calls += 1;
        return [ORIGIN];
      },
    });
    expect(calls).toBe(0);
    expect(rp.hasDynamicOrigins).toBe(true);
  });

  it("resolves on every call, not once", async () => {
    let port = 5000;
    const rp = new RelyingParty({
      id: "localhost",
      name: "Desktop",
      origins: () => [`http://localhost:${port}`],
    });

    expect(await rp.resolveOrigins()).toEqual(["http://localhost:5000"]);
    port = 5001;
    expect(await rp.resolveOrigins()).toEqual(["http://localhost:5001"]);
  });

  it("accepts an async resolver", async () => {
    const rp = new RelyingParty({
      id: RP_ID,
      name: "Example App",
      origins: () => Promise.resolve([ORIGIN, "https://app.example.com"]),
    });
    expect(await rp.resolveOrigins()).toEqual([ORIGIN, "https://app.example.com"]);
  });

  it("resolves a synchronous resolver through expectedOrigins() too", () => {
    const rp = new RelyingParty({ id: RP_ID, name: "Example App", origins: () => [ORIGIN] });
    expect(rp.expectedOrigins()).toEqual([ORIGIN]);
  });

  it("refuses to answer synchronously for an async resolver", () => {
    const rp = new RelyingParty({
      id: RP_ID,
      name: "Example App",
      origins: () => Promise.resolve([ORIGIN]),
    });
    expect(() => rp.expectedOrigins()).toThrow(/resolveOrigins/);
  });

  it.each(table.accept.map((row) => [row.origin, row.rpId, row] as const))(
    "a resolved %s with RP ID %s passes, as at construction",
    async (_origin, _rpId, row) => {
      const rp = new RelyingParty({ id: row.rpId, name: "Example App", origins: () => [row.origin] });
      expect(await rp.resolveOrigins()).toEqual([row.origin]);
    },
  );

  it.each(table.reject.map((row) => [row.origin, row.rpId, row] as const))(
    "a resolved %s with RP ID %s is refused, as at construction",
    async (_origin, _rpId, row) => {
      // The RP ID itself may be the thing the table refuses (an IP literal), in
      // which case construction throws before any resolver is involved. Either
      // way the configuration never reaches a verifier.
      let rp: RelyingParty;
      try {
        rp = new RelyingParty({ id: row.rpId, name: "Example App", origins: () => [row.origin] });
      } catch (err) {
        expect(err).toBeInstanceOf(TypeError);
        return;
      }
      await expect(rp.resolveOrigins()).rejects.toThrow(TypeError);
    },
  );

  it("refuses a bad value on EVERY call, not just the first", async () => {
    let origin = ORIGIN;
    const rp = new RelyingParty({ id: RP_ID, name: "Example App", origins: () => [origin] });

    origin = "http://example.com";
    await expect(rp.resolveOrigins()).rejects.toThrow(/https/);
    origin = ORIGIN;
    expect(await rp.resolveOrigins()).toEqual([ORIGIN]);
    origin = "https://evil.test";
    await expect(rp.resolveOrigins()).rejects.toThrow(TypeError);
  });

  it.each([
    ["an empty list", () => []],
    ["a non-array", () => "https://example.com" as unknown as string[]],
    ["a non-string entry", () => [42 as unknown as string]],
    ["an origin with a path", () => ["https://example.com/login"]],
  ])("refuses %s from the resolver", async (_label, resolver) => {
    const rp = new RelyingParty({ id: RP_ID, name: "Example App", origins: resolver });
    await expect(rp.resolveOrigins()).rejects.toThrow(TypeError);
  });

  it("propagates a resolver that throws, rather than allowing anything", async () => {
    const rp = new RelyingParty({
      id: RP_ID,
      name: "Example App",
      origins: () => {
        throw new Error("config service down");
      },
    });
    await expect(rp.resolveOrigins()).rejects.toThrow("config service down");
  });

  it("returns a copy, so a caller cannot mutate what the resolver returned", async () => {
    const list = [ORIGIN];
    const rp = new RelyingParty({ id: RP_ID, name: "Example App", origins: () => list });
    const resolved = await rp.resolveOrigins();
    resolved.push("https://evil.test");
    expect(await rp.resolveOrigins()).toEqual([ORIGIN]);
  });
});

describe("RelyingParty.setOrigins", () => {
  it("replaces a static list, validated immediately", async () => {
    const rp = new RelyingParty({ id: "localhost", name: "Desktop", origins: ["http://localhost:5000"] });
    rp.setOrigins(["http://localhost:6000"]);
    expect(rp.expectedOrigins()).toEqual(["http://localhost:6000"]);
    expect(await rp.resolveOrigins()).toEqual(["http://localhost:6000"]);
    expect(rp.hasDynamicOrigins).toBe(false);
  });

  it("leaves the previous list in place when the new one is refused", () => {
    const rp = new RelyingParty({ id: "localhost", name: "Desktop", origins: ["http://localhost:5000"] });
    expect(() => rp.setOrigins(["http://127.0.0.1:6000"])).toThrow(TypeError);
    expect(() => rp.setOrigins([])).toThrow(TypeError);
    expect(rp.expectedOrigins()).toEqual(["http://localhost:5000"]);
  });

  it("can switch to a resolver and back", async () => {
    const rp = new RelyingParty({ id: "localhost", name: "Desktop", origins: ["http://localhost:5000"] });
    rp.setOrigins(() => ["http://localhost:7000"]);
    expect(rp.hasDynamicOrigins).toBe(true);
    expect(await rp.resolveOrigins()).toEqual(["http://localhost:7000"]);
    rp.setOrigins(["http://localhost:5000"]);
    expect(rp.hasDynamicOrigins).toBe(false);
  });
});

describe("PasskeyServer with an origin resolver", () => {
  function setup(origins: () => string[] | Promise<string[]>) {
    const verifier = new FakeVerifier();
    const credentials = new InMemoryCredentialStore();
    const server = new PasskeyServer({
      relyingParty: new RelyingParty({ id: "localhost", name: "Desktop", origins }),
      challenges: new InMemoryChallengeStore(),
      credentials,
      randomBytes: sequentialBytes(),
      verifier,
    });
    return { server, verifier, credentials };
  }

  it("hands the verifier the list resolved for THIS verification", async () => {
    let port = 5000;
    const { server, verifier, credentials } = setup(() => [`http://localhost:${port}`]);
    await credentials.save(makeStoredCredential({ id: "Y3JlZC1vbmU" }));

    const first = await server.startAuthentication();
    await server.finishAuthentication({ state: first.state, response: authenticationResponse("Y3JlZC1vbmU") });
    expect(verifier.lastAuthenticationOpts?.expectedOrigin).toEqual(["http://localhost:5000"]);

    port = 5001;
    verifier.newCounter = 2;
    const second = await server.startAuthentication();
    await server.finishAuthentication({ state: second.state, response: authenticationResponse("Y3JlZC1vbmU") });
    expect(verifier.lastAuthenticationOpts?.expectedOrigin).toEqual(["http://localhost:5001"]);
  });

  it("resolves for registration too", async () => {
    const { server, verifier } = setup(() => Promise.resolve(["http://localhost:5173"]));
    const { state } = await server.startRegistration(ada());
    await server.finishRegistration({ state, response: registrationResponse("bmV3LWNyZWQ") });
    expect(verifier.lastRegistrationOpts?.expectedOrigin).toEqual(["http://localhost:5173"]);
  });

  it("never reaches the verifier, and persists nothing, when the resolved list is invalid", async () => {
    const { server, verifier, credentials } = setup(() => ["http://127.0.0.1:5000"]);
    const { state } = await server.startRegistration(ada());

    await expect(
      server.finishRegistration({ state, response: registrationResponse("bmV3LWNyZWQ") }),
    ).rejects.toThrow(TypeError);
    expect(verifier.lastRegistrationOpts).toBeNull();
    expect(await credentials.findById("bmV3LWNyZWQ")).toBeNull();
  });
});
