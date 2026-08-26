import { describe, test, expect, afterEach, vi } from "vitest";
import {
  newRequestId,
  assertStringRequestIdMatches,
  assertUuidRequestIdMatches,
} from "./requestId";

describe("newRequestId", () => {
  afterEach(() => {
    vi.unstubAllGlobals();
  });

  test("returns a well-formed RFC-4122 UUID string", () => {
    const id = newRequestId();
    expect(id).toMatch(/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i);
  });

  test("returns a fresh id on each call", () => {
    expect(newRequestId()).not.toBe(newRequestId());
  });

  test("fails closed (throws) rather than falling back to a predictable id when crypto.randomUUID is unavailable", () => {
    // A fixed fallback (e.g. a nil UUID) would defeat the whole point of this
    // id: every request would carry the same value, so a captured old reply
    // would pass the active-request match check.
    vi.stubGlobal("crypto", {});
    expect(() => newRequestId()).toThrow(/crypto\.randomUUID/i);
  });
});

describe("assertStringRequestIdMatches (SeedSigner's plain-string dialect)", () => {
  test("accepts a matching id", () => {
    expect(() => assertStringRequestIdMatches("id", "id", "ctx")).not.toThrow();
  });

  test("rejects a missing id", () => {
    expect(() => assertStringRequestIdMatches("id", undefined, "ctx")).toThrow(
      /ctx has no request identifier/i,
    );
  });

  test("rejects a non-string id (malformed)", () => {
    expect(() => assertStringRequestIdMatches("id", 42, "ctx")).toThrow(
      /ctx has a malformed request identifier/i,
    );
  });

  test("rejects a different (stale) id", () => {
    expect(() => assertStringRequestIdMatches("id", "earlier-request", "ctx")).toThrow(
      /ctx request identifier does not match the active request/i,
    );
  });
});

describe("assertUuidRequestIdMatches (Keystone's tagged-UUID dialect)", () => {
  const EXPECTED = "11111111-1111-4111-8111-111111111111";
  const expectedBytes = Uint8Array.from(Buffer.from(EXPECTED.replace(/-/g, ""), "hex"));

  test("accepts a matching 16-byte id, case-insensitively", () => {
    expect(() => assertUuidRequestIdMatches(EXPECTED, expectedBytes, "ctx")).not.toThrow();
    expect(() =>
      assertUuidRequestIdMatches(EXPECTED.toUpperCase(), expectedBytes, "ctx"),
    ).not.toThrow();
  });

  test("rejects a missing id", () => {
    expect(() => assertUuidRequestIdMatches(EXPECTED, undefined, "ctx")).toThrow(
      /ctx has no request identifier/i,
    );
  });

  test("rejects a wrong-length id (malformed)", () => {
    const short = Uint8Array.from(Buffer.from("aabbccdd", "hex"));
    expect(() => assertUuidRequestIdMatches(EXPECTED, short, "ctx")).toThrow(
      /ctx has a malformed request identifier/i,
    );
  });

  test("rejects a different (stale) id of the correct length", () => {
    const other = Uint8Array.from(
      Buffer.from("22222222" + "2222" + "4222" + "8222" + "222222222222", "hex"),
    );
    expect(other.length).toBe(16);
    expect(() => assertUuidRequestIdMatches(EXPECTED, other, "ctx")).toThrow(
      /ctx request identifier does not match the active request/i,
    );
  });
});
