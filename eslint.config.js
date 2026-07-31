import tseslint from "typescript-eslint";

/**
 * This package has no React, so there are no Rules of Hooks to enforce. What it
 * does have is auth code, where the failure that matters is a `catch` that
 * swallows a verification error and lets the caller read it as success.
 * `no-empty` (which reports empty catch blocks by default) is the one rule that
 * catches the shape of that mistake mechanically.
 */
export default [
  // MUST be its own object with no `files` key — an `ignores` alongside `files`
  // only filters THAT block and ESLint still walks `dist/`.
  {
    ignores: ["**/dist/**", "**/coverage/**", "**/node_modules/**", "**/*.d.ts"],
  },
  {
    files: ["**/*.{ts,js,mjs,cjs}"],
    linterOptions: { reportUnusedDisableDirectives: "off" },
    languageOptions: {
      parser: tseslint.parser,
      parserOptions: { sourceType: "module", ecmaVersion: "latest" },
    },
    plugins: { "@typescript-eslint": tseslint.plugin },
    rules: {
      "no-empty": "error",
      "no-fallthrough": "error",
    },
  },
];
