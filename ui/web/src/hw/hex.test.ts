import { describe, test, expect } from "vitest";
import { hexToBytes, bytesToHex } from "./hex";

describe("hexToBytes", () => {
  test("decodes a valid even-length hex string", () => {
    expect(Array.from(hexToBytes("deadbeef"))).toEqual([0xde, 0xad, 0xbe, 0xef]);
  });

  test("accepts an empty string", () => {
    expect(hexToBytes("").length).toBe(0);
  });

  test("decodes uppercase hex", () => {
    expect(Array.from(hexToBytes("AABB"))).toEqual([0xaa, 0xbb]);
  });

  test("rejects odd-length input instead of dropping the last nibble", () => {
    expect(() => hexToBytes("abc")).toThrow(/odd-length/i);
  });

  test("rejects invalid pairs instead of zero-filling", () => {
    expect(() => hexToBytes("zz")).toThrow(/non-hex/i);
    // A single bad nibble in an otherwise even string must still be rejected
    // (parseInt would silently accept "a" from "az").
    expect(() => hexToBytes("aazz")).toThrow(/non-hex/i);
    expect(() => hexToBytes("gg")).toThrow(/non-hex/i);
  });
});

describe("bytesToHex", () => {
  test("round-trips with hexToBytes", () => {
    expect(bytesToHex(Array.from(hexToBytes("00ff10")))).toBe("00ff10");
  });
});
