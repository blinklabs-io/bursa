import { describe, test, expect, beforeEach } from "vitest";
import { setDeviceKind, getDeviceKind, getStoredDeviceKind, STORAGE_KEY } from "./deviceKind";

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

  test("rejects a stale keystone hint (disabled this phase)", () => {
    // A "keystone" hint must NOT select an unsupported signer — the allowlist
    // omits it, so a stored keystone value reads back as unknown.
    localStorage.setItem(STORAGE_KEY, JSON.stringify({ w1: "keystone" }));
    expect(getStoredDeviceKind("w1")).toBeUndefined();
  });

  test("rejects an unrecognised value", () => {
    localStorage.setItem(STORAGE_KEY, JSON.stringify({ w1: "bogus" }));
    expect(getStoredDeviceKind("w1")).toBeUndefined();
  });
});

describe("getDeviceKind", () => {
  test("defaults to ledger when nothing recognised is stored", () => {
    expect(getDeviceKind("w1")).toBe("ledger");
    localStorage.setItem(STORAGE_KEY, JSON.stringify({ w1: "keystone" }));
    expect(getDeviceKind("w1")).toBe("ledger");
  });

  test("returns the stored recognised kind", () => {
    setDeviceKind("w1", "trezor");
    expect(getDeviceKind("w1")).toBe("trezor");
  });
});
