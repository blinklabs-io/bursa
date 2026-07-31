import { describe, test, expect } from "vitest";
import { encodeCbor, decodeCbor, type CborWritable } from "./cbor";

function bytes(hex: string): Uint8Array {
  return Uint8Array.from(hex.match(/../g)?.map((b) => parseInt(b, 16)) ?? []);
}

function toHex(b: Uint8Array): string {
  return Array.from(b, (x) => x.toString(16).padStart(2, "0")).join("");
}

function roundTrip(v: CborWritable) {
  const encoded = encodeCbor(v);
  const { value, next } = decodeCbor(encoded, 0);
  expect(next).toBe(encoded.length); // consumed the whole buffer
  return value;
}

describe("encodeCbor — byte-level", () => {
  test("integer-keyed map emits an untagged map with minimal headers, in insertion order", () => {
    // map {1: 2, 3: h'aabb'} → a2 01 02 03 42 aa bb
    const m = new Map<number, CborWritable>([
      [1, 2],
      [3, bytes("aabb")],
    ]);
    expect(toHex(encodeCbor(m))).toBe("a2" + "01" + "02" + "03" + "42aabb");
  });

  test("chooses the minimal length header for each additional-info boundary", () => {
    expect(toHex(encodeCbor(23))).toBe("17"); // inline
    expect(toHex(encodeCbor(24))).toBe("1818"); // 1-byte
    expect(toHex(encodeCbor(255))).toBe("18ff");
    expect(toHex(encodeCbor(256))).toBe("190100"); // 2-byte
    expect(toHex(encodeCbor(65535))).toBe("19ffff");
    expect(toHex(encodeCbor(65536))).toBe("1a00010000"); // 4-byte
  });

  test("text string uses major 3, byte string uses major 2", () => {
    expect(toHex(encodeCbor("a"))).toBe("6161"); // text "a"
    expect(toHex(encodeCbor(bytes("61")))).toBe("4161"); // bytes 0x61
  });

  test("never emits a tag (major 6)", () => {
    const encoded = encodeCbor(new Map<number, CborWritable>([[0, [1, "x", bytes("ff")]]]));
    for (const b of encoded) {
      expect(b >> 5).not.toBe(6);
    }
  });
});

describe("encodeCbor ⇄ decodeCbor round-trip", () => {
  test("unsigned integers across every header width", () => {
    for (const n of [0, 1, 23, 24, 255, 256, 65535, 65536, 4294967295, 4294967296]) {
      expect(roundTrip(n)).toBe(n);
    }
  });

  test("byte strings and text strings", () => {
    expect(roundTrip(bytes("deadbeef"))).toEqual(bytes("deadbeef"));
    expect(roundTrip("hello world")).toBe("hello world");
    expect(roundTrip("")).toBe("");
    expect(roundTrip(bytes(""))).toEqual(bytes(""));
  });

  test("arrays, including nested", () => {
    expect(roundTrip([1, 2, 3])).toEqual([1, 2, 3]);
    expect(roundTrip([1, "two", bytes("03")])).toEqual([1, "two", bytes("03")]);
    expect(roundTrip([[1], [2, [3]]])).toEqual([[1], [2, [3]]]);
  });

  test("integer-keyed maps, including nested and mixed values", () => {
    const m = new Map<number, CborWritable>([
      [1, bytes("cafe")],
      [2, "sign-data"],
      [3, [10, 20]],
      [4, new Map<number, CborWritable>([[0, 7]])],
    ]);
    expect(roundTrip(m)).toEqual(m);
  });

  test("a witness-set-shaped map {0: [[pub, sig]]} round-trips to the same bytes the reader accepts", () => {
    const pub = bytes("ab".repeat(32));
    const sig = bytes("cd".repeat(64));
    const witnessSet = new Map<number, CborWritable>([[0, [[pub, sig]]]]);
    const decoded = roundTrip(witnessSet) as Map<number, unknown>;
    const arr = decoded.get(0) as Uint8Array[][];
    expect(arr[0][0]).toEqual(pub);
    expect(arr[0][1]).toEqual(sig);
  });
});

describe("encodeCbor — rejects unsupported values", () => {
  test("negative integers", () => {
    expect(() => encodeCbor(-1)).toThrow(/non-negative integers/i);
  });

  test("non-integer numbers", () => {
    expect(() => encodeCbor(1.5)).toThrow(/non-negative integers/i);
  });

  test("non-integer map keys", () => {
    const m = new Map<number, CborWritable>([[-1, 0]]);
    expect(() => encodeCbor(m)).toThrow(/map keys must be non-negative integers/i);
  });
});
