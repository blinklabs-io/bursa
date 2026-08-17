import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

const here = dirname(fileURLToPath(import.meta.url));
const read = (rel: string) => readFileSync(join(here, rel), "utf8");

// These are SOURCE-level assertions on purpose.
//
// The bug they guard against — `ReferenceError: Buffer is not defined` thrown
// while @ledgerhq/hw-transport-webhid was being evaluated, which aborted the
// bundle and left a blank page — is invisible to a normal test here: vitest
// runs on Node, where `Buffer` is a real global, so every runtime assertion
// passes in the test environment and fails only in a browser. The structural
// properties that actually keep the browser working are the ones checked below.

test("main.tsx installs the polyfills before importing anything else", () => {
  const main = read("./main.tsx");
  const imports = [...main.matchAll(/^import\s.*$/gm)].map((m) => m[0]);

  expect(imports.length).toBeGreaterThan(1);
  // Import order is evaluation order: a later import (./app, and the hardware
  // modules it reaches) must not be evaluated before the globals are in place.
  expect(imports[0]).toContain("./polyfills");
});

test("polyfills installs Buffer on the global object", () => {
  const src = read("./polyfills.ts");
  expect(src).toMatch(/import\s*\{\s*Buffer\s*\}\s*from\s*["']buffer["']/);
  expect(src).toMatch(/globalThis\.Buffer\s*\?\?=/);
});

test("the Ledger WebHID transport is loaded on demand, not at module scope", () => {
  const ledger = read("./hw/ledger.ts");

  // A top-level `import ... from "@ledgerhq/hw-transport-webhid"` puts the
  // transport in the initial bundle and evaluates it during startup, so a
  // fault in it takes down the whole app rather than just the Ledger flow.
  const staticImport =
    /^import\s+[^;]*from\s+["']@ledgerhq\/hw-transport-webhid["']/m;
  expect(ledger).not.toMatch(staticImport);

  expect(ledger).toMatch(
    /await\s+import\(\s*["']@ledgerhq\/hw-transport-webhid["']\s*\)/,
  );
});
