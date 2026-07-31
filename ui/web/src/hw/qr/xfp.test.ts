import { describe, test, expect, beforeEach } from "vitest";
import { isValidXfp, setWalletXfp, getWalletXfp, XFP_STORAGE_KEY } from "./xfp";

beforeEach(() => {
  localStorage.clear();
});

describe("isValidXfp", () => {
  test("accepts an 8-hex-digit fingerprint (either case)", () => {
    expect(isValidXfp("52744703")).toBe(true);
    expect(isValidXfp("ABCDEF01")).toBe(true);
    expect(isValidXfp("aBcDeF01")).toBe(true);
  });

  test("accepts structurally-valid boundary fingerprints", () => {
    // A device-reported all-zero fingerprint is a legitimate (1-in-2^32) value;
    // the validator only rejects ABSENCE/corruption, never a real zero.
    expect(isValidXfp("00000000")).toBe(true);
    expect(isValidXfp("ffffffff")).toBe(true);
  });

  test("rejects malformed or non-string values", () => {
    expect(isValidXfp("5274470")).toBe(false); // too short
    expect(isValidXfp("527447033")).toBe(false); // too long
    expect(isValidXfp("5274470g")).toBe(false); // non-hex
    expect(isValidXfp(1234 as unknown)).toBe(false);
    expect(isValidXfp(undefined)).toBe(false);
    expect(isValidXfp(null as unknown)).toBe(false);
    expect(isValidXfp({} as unknown)).toBe(false);
  });
});

describe("wallet xfp store", () => {
  test("returns undefined when nothing is stored (caller must re-scan account-sync)", () => {
    expect(getWalletXfp("w1")).toBeUndefined();
  });

  test("round-trips a valid fingerprint under the preserved storage key", () => {
    setWalletXfp("w1", "52744703");
    expect(getWalletXfp("w1")).toBe("52744703");
    // The key value is preserved so previously-stored hints keep resolving.
    expect(XFP_STORAGE_KEY).toBe("bursa.hw.keystoneXfp");
    expect(localStorage.getItem(XFP_STORAGE_KEY)).toContain("52744703");
  });

  test("keeps distinct fingerprints per wallet id", () => {
    setWalletXfp("w1", "52744703");
    setWalletXfp("w2", "abcdef01");
    expect(getWalletXfp("w1")).toBe("52744703");
    expect(getWalletXfp("w2")).toBe("abcdef01");
  });

  test("treats a malformed persisted value as unknown (→ re-scan recovery)", () => {
    // A corrupt/hand-edited entry must not be forwarded into a sign-request; the
    // caller sees `undefined` and steers the user to re-scan the account-sync QR.
    localStorage.setItem(XFP_STORAGE_KEY, JSON.stringify({ w1: "not-hex", w2: 42 }));
    expect(getWalletXfp("w1")).toBeUndefined();
    expect(getWalletXfp("w2")).toBeUndefined();
  });
});
