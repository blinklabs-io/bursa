import { describe, test, expect } from "vitest";
import { encodeCoseSign1, encodeCoseKey } from "./cose";

// Ground-truth vectors produced INDEPENDENTLY by the `cbor` library's canonical
// encoder for the same inputs — the hand-rolled encoder in cose.ts must match
// them byte-for-byte, which is what makes a hardware-produced COSE_Sign1 verify
// with the backend (bursa.VerifyData) exactly like the software path:
//
//   protected  = canonical CBOR({1: -8, "address": 0x0011})
//   COSE_Sign1 = [ protected_bstr, {"hashed": false}, "Hello", <64-byte sig> ]
//   COSE_Key   = canonical CBOR({1:1, 3:-8, -1:6, -2: <32-byte pubkey>})
const ADDRESS_HEX = "0011";
const PAYLOAD_HEX = "48656c6c6f"; // "Hello"
const SIGNATURE_HEX = "ab".repeat(64); // 64-byte Ed25519 signature
const PUBKEY_HEX = "cd".repeat(32); // 32-byte Ed25519 public key

const EXPECTED_COSE_SIGN1 =
  "844ea201276761646472657373420011a166686173686564f44548656c6c6f5840" +
  "ab".repeat(64);
const EXPECTED_COSE_KEY = "a4010103272006215820" + "cd".repeat(32);

describe("encodeCoseSign1", () => {
  test("matches the canonical CBOR oracle byte-for-byte", () => {
    expect(encodeCoseSign1(ADDRESS_HEX, PAYLOAD_HEX, SIGNATURE_HEX)).toBe(
      EXPECTED_COSE_SIGN1,
    );
  });

  test("wraps the protected headers {1:-8, address} as a byte string", () => {
    const out = encodeCoseSign1(ADDRESS_HEX, PAYLOAD_HEX, SIGNATURE_HEX);
    // 0x84 = array(4); 0x4e = bstr(14); then the canonical protected map.
    expect(out.startsWith("844e" + "a201276761646472657373420011")).toBe(true);
  });

  test("carries the unprotected {\"hashed\": false} header", () => {
    const out = encodeCoseSign1(ADDRESS_HEX, PAYLOAD_HEX, SIGNATURE_HEX);
    // a1 66 686173686564 f4 = map(1){"hashed": false}
    expect(out).toContain("a166686173686564f4");
  });

  test("emits {\"hashed\": true} but still stores the raw payload when hashed", () => {
    // For a device-hashed payload (Blake2b-224) the header flips to true
    // (a1 66 686173686564 f5) while the COSE payload field keeps the RAW
    // message — the bursa verifier re-hashes it. Only the flag byte differs
    // from the unhashed encoding.
    const hashed = encodeCoseSign1(ADDRESS_HEX, PAYLOAD_HEX, SIGNATURE_HEX, true);
    expect(hashed).toContain("a166686173686564f5");
    expect(hashed).toContain(PAYLOAD_HEX);
    expect(hashed).toBe(EXPECTED_COSE_SIGN1.replace("a166686173686564f4", "a166686173686564f5"));
  });

  test("defaults to unhashed, byte-identical to the explicit false", () => {
    expect(encodeCoseSign1(ADDRESS_HEX, PAYLOAD_HEX, SIGNATURE_HEX)).toBe(
      encodeCoseSign1(ADDRESS_HEX, PAYLOAD_HEX, SIGNATURE_HEX, false),
    );
  });

  test("includes the payload and signature bytes verbatim", () => {
    const out = encodeCoseSign1(ADDRESS_HEX, PAYLOAD_HEX, SIGNATURE_HEX);
    expect(out).toContain(PAYLOAD_HEX);
    expect(out).toContain(SIGNATURE_HEX);
  });
});

describe("encodeCoseKey", () => {
  test("matches the canonical CBOR oracle byte-for-byte", () => {
    expect(encodeCoseKey(PUBKEY_HEX)).toBe(EXPECTED_COSE_KEY);
  });

  test("encodes an OKP/EdDSA/Ed25519 key carrying the public key at label -2", () => {
    const out = encodeCoseKey(PUBKEY_HEX);
    // a4 (map4) 01 01 (kty OKP) 03 27 (alg EdDSA) 20 06 (crv Ed25519) 21 5820 <pub>
    expect(out.startsWith("a4010103272006215820")).toBe(true);
    expect(out).toContain(PUBKEY_HEX);
  });
});
