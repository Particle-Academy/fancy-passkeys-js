import { describe, expect, it } from "vitest";

import { RelyingParty } from "../src/relying-party.js";

describe("RelyingParty", () => {
  it("accepts an RP ID that is the origin's host", () => {
    const rp = new RelyingParty({
      id: "example.com",
      name: "Example App",
      origins: ["https://example.com"],
    });

    expect(rp.id).toBe("example.com");
    expect(rp.expectedOrigins()).toEqual(["https://example.com"]);
  });

  it("accepts an RP ID that is a registrable parent of the origin's host", () => {
    // The credential is scoped to example.com, so it works on app. and admin.
    const rp = new RelyingParty({
      id: "example.com",
      name: "Example App",
      origins: ["https://app.example.com", "https://admin.example.com"],
    });

    expect(rp.expectedOrigins()).toHaveLength(2);
  });

  it("rejects an RP ID that is not a suffix of an origin", () => {
    // The browser would refuse every ceremony with "Unexpected RP ID hash",
    // which names neither the cause nor the fix. Better to fail at boot.
    expect(
      () =>
        new RelyingParty({
          id: "example.com",
          name: "Example App",
          origins: ["https://example.org"],
        }),
    ).toThrow(TypeError);
  });

  it("rejects a partial-label near miss", () => {
    // "notexample.com".endsWith("example.com") is true; the RP ID rule is not
    // string suffix matching, it is label matching.
    expect(
      () =>
        new RelyingParty({
          id: "example.com",
          name: "Example App",
          origins: ["https://notexample.com"],
        }),
    ).toThrow(TypeError);
  });

  it("rejects plain http for anything but localhost", () => {
    expect(
      () =>
        new RelyingParty({
          id: "example.com",
          name: "Example App",
          origins: ["http://example.com"],
        }),
    ).toThrow(/https/);
  });

  it("accepts http://localhost with a port", () => {
    const rp = new RelyingParty({
      id: "localhost",
      name: "Example App",
      origins: ["http://localhost:5173"],
    });

    expect(rp.expectedOrigins()).toEqual(["http://localhost:5173"]);
  });

  it("accepts http://127.0.0.1", () => {
    expect(
      () =>
        new RelyingParty({
          id: "127.0.0.1",
          name: "Example App",
          origins: ["http://127.0.0.1:8000"],
        }),
    ).not.toThrow();
  });

  it("requires at least one origin", () => {
    expect(
      () => new RelyingParty({ id: "example.com", name: "Example App", origins: [] }),
    ).toThrow(TypeError);
  });

  it("requires a non-empty id and name", () => {
    expect(
      () => new RelyingParty({ id: "  ", name: "Example App", origins: ["https://example.com"] }),
    ).toThrow(TypeError);
    expect(
      () => new RelyingParty({ id: "example.com", name: "", origins: ["https://example.com"] }),
    ).toThrow(TypeError);
  });

  it("rejects an id carrying a scheme or port", () => {
    expect(
      () =>
        new RelyingParty({
          id: "https://example.com",
          name: "Example App",
          origins: ["https://example.com"],
        }),
    ).toThrow(TypeError);
  });

  it("rejects a value that is not a URL at all", () => {
    expect(
      () =>
        new RelyingParty({ id: "example.com", name: "Example App", origins: ["example.com"] }),
    ).toThrow(TypeError);
  });

  it("rejects an origin with a path or trailing slash", () => {
    // The browser reports `clientData.origin` with no trailing slash, so an
    // exact-match allow-list containing one would never match anything.
    expect(
      () =>
        new RelyingParty({
          id: "example.com",
          name: "Example App",
          origins: ["https://example.com/"],
        }),
    ).toThrow(/trailing slash/);
  });

  it("hands out a copy of the origin list", () => {
    const rp = new RelyingParty({
      id: "example.com",
      name: "Example App",
      origins: ["https://example.com"],
    });

    rp.expectedOrigins().push("https://evil.example");
    expect(rp.expectedOrigins()).toEqual(["https://example.com"]);
  });
});
