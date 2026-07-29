import { describe, test, expect, beforeEach } from "vitest";
import {
  setDeviceKind,
  getDeviceKind,
  getStoredDeviceKind,
  STORAGE_KEY,
  setKeystoneXfp,
  getKeystoneXfp,
  isValidKeystoneXfp,
  KEYSTONE_XFP_KEY,
} from "./deviceKind";

beforeEach(() => {
  localStorage.clear();
});

describe("getStoredDeviceKind", () => {
  test("returns undefined when nothing is stored", () => {
    expect(getStoredDeviceKind("w1")).toBeUndefined();
  });

  test("round-trips ledger and trezor", () => {
    setDeviceKind("w1", "ledger");
    setDeviceKind("w2", "trezor");
    expect(getStoredDeviceKind("w1")).toBe("ledger");
    expect(getStoredDeviceKind("w2")).toBe("trezor");
  });

  test("honors a stored keystone hint", () => {
    // Keystone is an implemented signer now, so its hint is a recognised kind.
    setDeviceKind("w1", "keystone");
    expect(getStoredDeviceKind("w1")).toBe("keystone");
  });

  test("rejects an unrecognised value", () => {
    localStorage.setItem(STORAGE_KEY, JSON.stringify({ w1: "bogus" }));
    expect(getStoredDeviceKind("w1")).toBeUndefined();
  });
});

describe("getDeviceKind", () => {
  test("defaults to ledger when nothing recognised is stored", () => {
    expect(getDeviceKind("w1")).toBe("ledger");
    localStorage.setItem(STORAGE_KEY, JSON.stringify({ w1: "bogus" }));
    expect(getDeviceKind("w1")).toBe("ledger");
  });

  test("returns the stored recognised kind", () => {
    setDeviceKind("w1", "trezor");
    expect(getDeviceKind("w1")).toBe("trezor");
  });
});

describe("isValidKeystoneXfp", () => {
  test("accepts an 8-hex-digit fingerprint (either case)", () => {
    expect(isValidKeystoneXfp("52744703")).toBe(true);
    expect(isValidKeystoneXfp("ABCDEF01")).toBe(true);
  });

  test("accepts boundary/edge fingerprints that are structurally valid hex", () => {
    expect(isValidKeystoneXfp("00000000")).toBe(true); // all-zeros
    expect(isValidKeystoneXfp("99999999")).toBe(true); // all-nines
    expect(isValidKeystoneXfp("aBcDeF01")).toBe(true); // mixed-case hex
  });

  test("rejects malformed or non-string values", () => {
    expect(isValidKeystoneXfp("5274470")).toBe(false); // too short
    expect(isValidKeystoneXfp("527447033")).toBe(false); // too long
    expect(isValidKeystoneXfp("5274470g")).toBe(false); // non-hex
    expect(isValidKeystoneXfp(1234 as unknown)).toBe(false);
    expect(isValidKeystoneXfp(undefined)).toBe(false);
    expect(isValidKeystoneXfp({} as unknown)).toBe(false);
  });
});

describe("getKeystoneXfp", () => {
  test("returns undefined when nothing is stored", () => {
    expect(getKeystoneXfp("w1")).toBeUndefined();
  });

  test("round-trips a valid fingerprint", () => {
    setKeystoneXfp("w1", "52744703");
    expect(getKeystoneXfp("w1")).toBe("52744703");
  });

  test("treats a malformed persisted value as unknown", () => {
    // A corrupt/hand-edited entry must not be forwarded into a sign-request.
    localStorage.setItem(KEYSTONE_XFP_KEY, JSON.stringify({ w1: "not-hex", w2: 42 }));
    expect(getKeystoneXfp("w1")).toBeUndefined();
    expect(getKeystoneXfp("w2")).toBeUndefined();
  });
});
