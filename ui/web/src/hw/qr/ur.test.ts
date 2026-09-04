import { describe, test, expect } from "vitest";
import {
  encodeUR,
  decodeUR,
  createURAssembler,
  ensureBuffer,
  DEFAULT_UR_LIMITS,
  URDecodeLimitError,
} from "./ur";
import { encodeCbor } from "./cbor";

function toHex(b: Uint8Array): string {
  return Array.from(b, (x) => x.toString(16).padStart(2, "0")).join("");
}

// A CBOR byte-string payload of `n` bytes (0x00..) — a realistic UR message.
function payload(n: number): Uint8Array {
  return encodeCbor(Uint8Array.from({ length: n }, (_, i) => i & 0xff));
}

describe("UR transport", () => {
  test("single small payload encodes to one ur: part and round-trips", async () => {
    const cbor = payload(8);
    const parts = await encodeUR("test-payload", cbor);
    expect(parts.length).toBe(1);
    expect(parts[0].toLowerCase()).toMatch(/^ur:test-payload\//);

    const decoded = await decodeUR(parts);
    expect(decoded.type).toBe("test-payload");
    expect(decoded.cborHex).toBe(toHex(cbor));
  });

  test("a payload larger than the fragment size splits into multiple parts and reassembles", async () => {
    const cbor = payload(400);
    const parts = await encodeUR("test-payload", cbor, 50);
    // Must have fanned out across several animated-QR frames.
    expect(parts.length).toBeGreaterThan(1);
    for (const p of parts) {
      expect(p.toLowerCase()).toMatch(/^ur:test-payload\//);
    }

    const decoded = await decodeUR(parts);
    expect(decoded.type).toBe("test-payload");
    expect(decoded.cborHex).toBe(toHex(cbor));
  });

  test("assembler reports progress and completes as parts arrive", async () => {
    const cbor = payload(400);
    const parts = await encodeUR("test-payload", cbor, 50);
    const assembler = await createURAssembler();

    expect(assembler.isComplete()).toBe(false);
    for (const p of parts) {
      assembler.receivePart(p);
      if (assembler.isComplete()) break;
    }
    expect(assembler.isComplete()).toBe(true);
    expect(assembler.isSuccess()).toBe(true);
    expect(assembler.progressPercent()).toBe(100);
    expect(assembler.result()).toEqual({ type: "test-payload", cborHex: toHex(cbor) });
  });

  test("decodeUR throws when the parts are incomplete", async () => {
    const parts = await encodeUR("test-payload", payload(400), 50);
    await expect(decodeUR(parts.slice(0, 1))).rejects.toThrow(/incomplete/i);
  });

  test("rejects an oversized part before passing it to bc-ur", async () => {
    const assembler = await createURAssembler({ maxPartBytes: 32 });

    expect(() => assembler.receivePart(`ur:test-payload/${"x".repeat(64)}`)).toThrow(
      URDecodeLimitError,
    );
    expect(assembler.isError()).toBe(true);
  });

  test("rejects a stream whose advertised part count is too large", async () => {
    const assembler = await createURAssembler({ maxParts: 2 });

    expect(() => assembler.receivePart("ur:test-payload/1-3/00")).toThrow(/too many parts/i);
    expect(assembler.isError()).toBe(true);
  });

  test("rejects a stream after its cumulative byte limit", async () => {
    const part = (await encodeUR("test-payload", payload(8)))[0];
    const assembler = await createURAssembler({
      maxTotalBytes: part.length * 2 - 1,
      maxPartBytes: part.length + 1,
    });

    assembler.receivePart(part);
    expect(() => assembler.receivePart(part)).toThrow(/too large/i);
    expect(assembler.isError()).toBe(true);
  });

  test("rejects incomplete streams that exceed the frame limit", async () => {
    const assembler = await createURAssembler({ maxFrames: 2 });
    const parts = await encodeUR("test-payload", payload(400), 50);

    assembler.receivePart(parts[0]);
    assembler.receivePart(parts[1]);
    expect(() => assembler.receivePart(parts[2])).toThrow(/too many frames/i);
  });

  test("rejects a slow stream after the elapsed-time limit", async () => {
    let clock = 1000;
    const assembler = await createURAssembler({ maxDurationMs: 10 }, () => clock);
    const part = (await encodeUR("test-payload", payload(8)))[0];

    assembler.receivePart(part);
    clock += 11;
    expect(() => assembler.receivePart(part)).toThrow(/too long/i);
    expect(assembler.isError()).toBe(true);
  });

  test("default limits remain finite", () => {
    expect(DEFAULT_UR_LIMITS.maxPartBytes).toBeGreaterThan(0);
    expect(DEFAULT_UR_LIMITS.maxTotalBytes).toBeGreaterThan(DEFAULT_UR_LIMITS.maxPartBytes);
    expect(DEFAULT_UR_LIMITS.maxParts).toBeGreaterThan(0);
    expect(DEFAULT_UR_LIMITS.maxFrames).toBeGreaterThan(0);
    expect(DEFAULT_UR_LIMITS.maxDurationMs).toBeGreaterThan(0);
  });

  test("ensureBuffer installs a global Buffer", async () => {
    await ensureBuffer();
    expect((globalThis as unknown as { Buffer?: unknown }).Buffer).toBeDefined();
  });
});
