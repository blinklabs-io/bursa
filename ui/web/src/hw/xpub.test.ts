import { describe, test, expect } from "vitest";
import { encodeXpub } from "./xpub";

// Canonical 32-byte halves (same vector as ledger.test.ts / trezor.test.ts).
const PUB = "beb7e770b3d0f1932b0a2f3a63285bf9ef7d3e461d55446d6a3911d8f0ee55c0";
const CC = "b0e2df16538508046649d0e6d5b32969555a23f2f1ebf2db2819359b0d88bd16";
const XPUB =
  "root_xvk1h6m7wu9n6rcex2c29uaxx2zml8hh60jxr425gmt28yga3u8w2hqtpcklzefc2zqyveyapek4kv5kj426y0e0r6ljmv5pjdvmpkyt69s8fpd2x";

describe("encodeXpub", () => {
  test("encodes two 32-byte halves to the canonical bech32 xpub", () => {
    expect(encodeXpub(PUB, CC)).toBe(XPUB);
  });

  test("rejects a public key that is not 32 bytes", () => {
    expect(() => encodeXpub(PUB.slice(0, 62), CC)).toThrow(/public key must be 32 bytes/i);
    expect(() => encodeXpub(PUB + "aa", CC)).toThrow(/public key must be 32 bytes/i);
  });

  test("rejects a chain code that is not 32 bytes", () => {
    expect(() => encodeXpub(PUB, CC.slice(0, 62))).toThrow(/chain code must be 32 bytes/i);
    expect(() => encodeXpub(PUB, CC + "aa")).toThrow(/chain code must be 32 bytes/i);
  });

  test("propagates malformed hex rejection", () => {
    expect(() => encodeXpub("zz", CC)).toThrow(/non-hex/i);
  });
});
