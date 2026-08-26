/**
 * hw/requestId.ts — the "active request" identifier shared by every air-gapped
 * QR round-trip (Keystone sign, SeedSigner account import, SeedSigner tx sign).
 *
 * Each of those exchanges stamps a fresh identifier on the request it displays
 * and expects the device to echo it back on the reply. A response is only the
 * answer to the request THIS call made if that identifier matches: without the
 * check, a stale scan (an earlier reply, still showing on a phone or in a
 * screenshot) or a reply meant for an unrelated request would be silently
 * accepted and its signature attached to the current operation.
 */

/**
 * A fresh RFC-4122 UUID string. crypto.randomUUID is available in every target
 * (secure-context browsers); fall back to a fixed nil UUID if it is missing.
 */
export function newRequestId(): string {
  const c = (globalThis as { crypto?: { randomUUID?: () => string } }).crypto;
  return c?.randomUUID ? c.randomUUID() : "00000000-0000-0000-0000-000000000000";
}

/**
 * Validate a request identifier carried as a plain UTF-8 string in a bespoke
 * CBOR payload (SeedSigner's dialect) against the id the active request sent.
 */
export function assertStringRequestIdMatches(
  expected: string,
  actual: unknown,
  context: string,
): void {
  if (actual === undefined) {
    throw new Error(
      `${context} has no request identifier — cannot confirm it answers the active request (possible stale scan).`,
    );
  }
  if (typeof actual !== "string") {
    throw new Error(`${context} has a malformed request identifier (not a text string).`);
  }
  if (actual !== expected) {
    throw new Error(
      `${context} request identifier does not match the active request — this looks like a stale or unrelated scan.`,
    );
  }
}

/**
 * Validate a request identifier carried as a raw 16-byte UUID (Keystone's UR
 * registry, tagged UUID) against the RFC-4122 string id the active request sent.
 */
export function assertUuidRequestIdMatches(
  expectedUuid: string,
  actual: Uint8Array | undefined,
  context: string,
): void {
  if (actual === undefined) {
    throw new Error(
      `${context} has no request identifier — cannot confirm it answers the active request (possible stale scan).`,
    );
  }
  if (actual.length !== 16) {
    throw new Error(
      `${context} has a malformed request identifier (expected a 16-byte UUID, got ${actual.length} bytes).`,
    );
  }
  const expectedHex = expectedUuid.replace(/-/g, "").toLowerCase();
  let actualHex = "";
  for (const b of actual) actualHex += b.toString(16).padStart(2, "0");
  if (actualHex !== expectedHex) {
    throw new Error(
      `${context} request identifier does not match the active request — this looks like a stale or unrelated scan.`,
    );
  }
}
