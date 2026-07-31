import { createHash } from "node:crypto";

import {
  generateAuthenticationOptions,
  generateRegistrationOptions,
} from "@simplewebauthn/server";
import type {
  AuthenticationResponseJSON,
  RegistrationResponseJSON,
  VerifyAuthenticationResponseOpts,
  VerifyRegistrationResponseOpts,
} from "@simplewebauthn/server";

import { toBase64Url } from "../src/encoding.js";
import { RelyingParty } from "../src/relying-party.js";
import type { Verifier } from "../src/server.js";
import type { PasskeyUser, StoredCredential } from "../src/types.js";

export const RP_ID = "example.com";
export const ORIGIN = "https://example.com";

export const ADA_HANDLE = toBase64Url(new TextEncoder().encode("ada-user-handle"));
export const GRACE_HANDLE = toBase64Url(new TextEncoder().encode("grace-user-handle"));

export function makeRelyingParty(): RelyingParty {
  return new RelyingParty({ id: RP_ID, name: "Example App", origins: [ORIGIN] });
}

export function ada(): PasskeyUser {
  return { handle: ADA_HANDLE, name: "ada@example.com", displayName: "Ada Lovelace" };
}

export function grace(): PasskeyUser {
  return { handle: GRACE_HANDLE, name: "grace@example.com", displayName: "Grace Hopper" };
}

/**
 * A deterministic stand-in for the CSPRNG.
 *
 * Every call returns different bytes, so the challenge and the `state` handle
 * of a single ceremony are distinct — a generator that returned one constant
 * would let a bug that conflated the two pass unnoticed.
 */
export function sequentialBytes(): (size: number) => Uint8Array {
  let call = 0;
  return (size: number) => {
    call += 1;
    const bytes = new Uint8Array(size);
    for (let i = 0; i < size; i += 1) {
      bytes[i] = (call * 31 + i * 7) & 0xff;
    }
    return bytes;
  };
}

export function makeStoredCredential(overrides: Partial<StoredCredential> = {}): StoredCredential {
  return {
    id: "Y3JlZC1vbmU",
    publicKey: toBase64Url(new Uint8Array([1, 2, 3, 4])),
    userHandle: ADA_HANDLE,
    signCount: 0,
    transports: ["internal"],
    aaguid: "00000000-0000-0000-0000-000000000000",
    backedUp: true,
    backupEligible: true,
    uvInitialized: true,
    attestationFormat: "none",
    name: null,
    createdAt: "2026-01-01T00:00:00.000Z",
    lastUsedAt: null,
    clonedAt: null,
    ...overrides,
  };
}

/**
 * A registration response with only the fields `PasskeyServer` itself reads.
 *
 * Everything else is the verifier's business, and when the verifier is
 * {@link FakeVerifier} there is nothing to parse. Building a *real* attestation
 * would mean minting a key pair and a CBOR attestation object — i.e. writing
 * the WebAuthn implementation this package exists not to have.
 */
export function registrationResponse(
  id: string,
  transports: string[] = ["internal"],
): RegistrationResponseJSON {
  return {
    id,
    rawId: id,
    type: "public-key",
    clientExtensionResults: {},
    response: {
      clientDataJSON: "",
      attestationObject: "",
      transports: transports as RegistrationResponseJSON["response"]["transports"],
    },
  };
}

/** An assertion with only the fields `PasskeyServer` itself reads. */
export function authenticationResponse(
  id: string,
  userHandle?: string,
): AuthenticationResponseJSON {
  return {
    id,
    rawId: id,
    type: "public-key",
    clientExtensionResults: {},
    response: {
      clientDataJSON: "",
      authenticatorData: "",
      signature: "",
      ...(userHandle === undefined ? {} : { userHandle }),
    },
  };
}

/**
 * A stand-in for `@simplewebauthn/server`'s two verification functions.
 *
 * The options generators are **the real ones**: they are pure, they are fast,
 * and faking them would mean the `excludeCredentials` / `allowCredentials`
 * assertions were checking a fake's arguments rather than the payload that
 * actually goes on the wire.
 *
 * Only the verifiers are faked, because reaching them for real requires an
 * authenticator, a human fingerprint, and a signature — which is precisely why
 * every failure path around them would otherwise go untested.
 *
 * The counter check is **reimplemented verbatim from v13**, including the
 * message text, because `counterPolicy: 'reject'` depends on the library
 * throwing exactly that. `counter.test.ts` additionally provokes the real
 * library into throwing it, so this copy cannot drift silently.
 */
export class FakeVerifier implements Verifier {
  generateRegistrationOptions = generateRegistrationOptions;
  generateAuthenticationOptions = generateAuthenticationOptions;

  /** Thrown instead of verifying, when set. */
  registrationError: unknown = null;
  /** Thrown instead of verifying, when set. */
  authenticationError: unknown = null;

  /** What `verified` should be for a registration that does not throw. */
  registrationVerified = true;
  /** What `verified` should be for an assertion that does not throw. */
  authenticationVerified = true;

  /** The counter the imaginary authenticator reports. */
  newCounter = 1;
  /** The UV flag the imaginary authenticator reports. */
  userVerified = true;

  lastRegistrationOpts: VerifyRegistrationResponseOpts | null = null;
  lastAuthenticationOpts: VerifyAuthenticationResponseOpts | null = null;

  verifyRegistrationResponse: Verifier["verifyRegistrationResponse"] = (opts) => {
    this.lastRegistrationOpts = opts;

    if (this.registrationError) {
      return Promise.reject(this.registrationError);
    }
    if (!this.registrationVerified) {
      return Promise.resolve({ verified: false as const });
    }

    return Promise.resolve({
      verified: true as const,
      registrationInfo: {
        fmt: "none" as const,
        aaguid: "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
        credential: {
          id: opts.response.id,
          publicKey: new Uint8Array([9, 8, 7, 6]),
          counter: this.newCounter,
          transports: opts.response.response.transports,
        },
        credentialType: "public-key" as const,
        attestationObject: new Uint8Array([0]),
        userVerified: this.userVerified,
        credentialDeviceType: "multiDevice" as const,
        credentialBackedUp: true,
        origin: ORIGIN,
        rpID: RP_ID,
      },
    });
  };

  verifyAuthenticationResponse: Verifier["verifyAuthenticationResponse"] = (opts) => {
    this.lastAuthenticationOpts = opts;

    if (this.authenticationError) {
      return Promise.reject(this.authenticationError);
    }

    // Verbatim from v13's verifyAuthenticationResponse: both counters at zero
    // is accepted, anything else must strictly increase.
    const stored = opts.credential.counter;
    const next = this.newCounter;
    if ((next > 0 || stored > 0) && next <= stored) {
      return Promise.reject(
        new Error(`Response counter value ${next} was lower than expected ${stored}`),
      );
    }

    return Promise.resolve({
      verified: this.authenticationVerified,
      authenticationInfo: {
        credentialID: opts.credential.id,
        newCounter: next,
        userVerified: this.userVerified,
        credentialDeviceType: "multiDevice" as const,
        credentialBackedUp: true,
        origin: ORIGIN,
        rpID: RP_ID,
      },
    });
  };
}

/**
 * Build an assertion the **real** `verifyAuthenticationResponse` will accept as
 * far as its signature-counter check.
 *
 * The library's order of operations is: client data type → challenge → origin →
 * authenticator data → RP ID hash → UP/UV flags → **counter** → signature. So
 * everything up to the counter can be satisfied with a hash of the RP ID and a
 * hand-assembled 37-byte authenticator data blob, and no key material is needed
 * because the signature check comes after.
 *
 * This is not a WebAuthn implementation — it is the smallest possible input
 * that reaches the one upstream behaviour this package's clone detection is
 * built on top of.
 */
export function realisticAssertion(options: {
  credentialId: string;
  challenge: string;
  counter: number;
  origin?: string;
  rpId?: string;
}): AuthenticationResponseJSON {
  const rpIdHash = createHash("sha256")
    .update(options.rpId ?? RP_ID)
    .digest();

  // UP (0x01) | UV (0x04) | BE (0x08) | BS (0x10). No attested credential data,
  // no extensions, so the blob is exactly 37 bytes.
  const authData = new Uint8Array(37);
  authData.set(new Uint8Array(rpIdHash), 0);
  authData[32] = 0x01 | 0x04 | 0x08 | 0x10;
  new DataView(authData.buffer).setUint32(33, options.counter, false);

  const clientData = JSON.stringify({
    type: "webauthn.get",
    challenge: options.challenge,
    origin: options.origin ?? ORIGIN,
    crossOrigin: false,
  });

  return {
    id: options.credentialId,
    rawId: options.credentialId,
    type: "public-key",
    clientExtensionResults: {},
    response: {
      clientDataJSON: toBase64Url(new TextEncoder().encode(clientData)),
      authenticatorData: toBase64Url(authData),
      // Never reached: the counter check precedes signature verification.
      signature: toBase64Url(new Uint8Array([0, 1, 2, 3])),
    },
  };
}
