import { defineConfig } from "tsup";

export default defineConfig({
  entry: ["src/index.ts", "src/http.ts"],
  format: ["esm", "cjs"],
  dts: { entry: ["src/index.ts", "src/http.ts"] },
  // The WebAuthn library is a PEER and must never be bundled. A bundled copy
  // means a consumer who also imports it directly gets two, with two
  // incompatible `WebAuthnCredential` types and no error to say so.
  external: ["@simplewebauthn/server"],
  treeshake: true,
  clean: true,
  sourcemap: true,
});
