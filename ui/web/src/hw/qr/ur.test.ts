import { describe, test, expect } from "vitest";
import { encodeUR, decodeUR, createURAssembler, ensureBuffer } from "./ur";
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

  test("ensureBuffer installs a global Buffer", async () => {
    await ensureBuffer();
    expect((globalThis as unknown as { Buffer?: unknown }).Buffer).toBeDefined();
  });
});
