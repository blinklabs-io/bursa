/**
 * hw/qr/ur.ts — BC-UR2 transport shared by air-gapped-QR devices.
 *
 * A Uniform Resource (UR) is the standard way an air-gapped device exchanges a
 * (possibly large) CBOR payload as an animated ("fountain") QR: the sender
 * splits it into part strings that cycle as QR frames, and the receiver
 * reassembles them. This module wraps `@ngraveio/bc-ur` so a device only has to
 * supply {UR type, CBOR bytes}; it owns neither pixels nor camera.
 *
 * `@ngraveio/bc-ur` reads a global `Buffer`, which browsers do not provide, so
 * it (and the `buffer` shim) is DYNAMICALLY imported inside each call — code-split
 * out of the initial bundle and only ever loaded when a QR flow actually runs.
 */

import type { ScannedUR } from "./types";

/** Resource limits applied before untrusted camera data reaches bc-ur. */
export const DEFAULT_UR_LIMITS = {
  maxPartBytes: 4 * 1024,
  maxTotalBytes: 1024 * 1024,
  maxParts: 256,
  maxFrames: 1024,
  maxDurationMs: 60_000,
} as const;

export interface URLimits {
  maxPartBytes?: number;
  maxTotalBytes?: number;
  maxParts?: number;
  maxFrames?: number;
  maxDurationMs?: number;
}

export class URDecodeLimitError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "URDecodeLimitError";
  }
}

/**
 * The @ngraveio/bc-ur CBOR/UR libraries read a global `Buffer`, which browsers do
 * not provide. Install one lazily — only when a QR flow actually runs — so the
 * `buffer` shim rides the code-split QR chunk and never bloats the initial bundle.
 */
export async function ensureBuffer(): Promise<void> {
  const g = globalThis as unknown as { Buffer?: unknown };
  if (typeof g.Buffer === "undefined") {
    const mod = await import("buffer");
    g.Buffer = mod.Buffer;
  }
}

function globalBuffer(): { from(input: Uint8Array | string, enc?: string): Buffer } {
  return (globalThis as unknown as { Buffer: { from(input: Uint8Array | string, enc?: string): Buffer } })
    .Buffer;
}

function toHex(bytes: Uint8Array): string {
  let out = "";
  for (const b of bytes) out += b.toString(16).padStart(2, "0");
  return out;
}

/**
 * Encode a CBOR payload as BC-UR2 animated-QR part strings.
 *
 * @param type - the UR type (e.g. "cardano-sign-request").
 * @param cbor - the already-CBOR-encoded payload bytes.
 * @param maxFragmentLen - max payload bytes per QR frame; larger payloads simply
 *   animate across more frames. Omit for a single (or default-sized) frame.
 * @returns the "pure" part strings (`ur:<type>/…`) the UI cycles as QR frames.
 */
export async function encodeUR(
  type: string,
  cbor: Uint8Array,
  maxFragmentLen?: number,
): Promise<string[]> {
  await ensureBuffer();
  const { UR, UREncoder } = await import("@ngraveio/bc-ur");
  const ur = new UR(globalBuffer().from(cbor), type);
  return new UREncoder(ur, maxFragmentLen).encodeWhole();
}

/**
 * Stateful assembler for a (possibly multi-part) UR scanned off a camera.
 *
 * Wraps `@ngraveio/bc-ur`'s URDecoder so a scanner component just feeds it the
 * `ur:` strings it reads and polls the completion/error state. Construct via
 * {@link createURAssembler} (which loads the code-split decoder).
 */
export interface URAssembler {
  /** Feed one scanned `ur:` part string into the assembler. */
  receivePart(part: string): void;
  /** Fraction assembled so far, as a whole-number percent (0–100). */
  progressPercent(): number;
  /**
   * True once the multipart stream has reached a permanent ERROR state (e.g.
   * mismatched fragment checksums) WITHOUT ever completing — otherwise the UI
   * would sit on "scanning" forever.
   */
  isError(): boolean;
  /** The decoder's error message, if any. */
  error(): string;
  /** True once every part needed to reconstruct the UR has been received. */
  isComplete(): boolean;
  /** True when a completed assembly decoded successfully. */
  isSuccess(): boolean;
  /** The assembled UR as {type, cborHex}. Only valid once complete + successful. */
  result(): ScannedUR;
}

function advertisedPartCount(part: string): number {
  const match = /^ur:[^/]+\/(\d+)-(\d+)\//i.exec(part);
  if (!match) return 1;
  const sequence = Number(match[1]);
  const count = Number(match[2]);
  if (!Number.isSafeInteger(sequence) || sequence < 1 || !Number.isSafeInteger(count) || count < 1) {
    throw new URDecodeLimitError("BC-UR part has an invalid sequence");
  }
  if (sequence > count) {
    throw new URDecodeLimitError("BC-UR part sequence exceeds its advertised count");
  }
  return count;
}

function resolveLimits(requestedLimits: URLimits): Required<URLimits> {
  const limits = {
    maxPartBytes: requestedLimits.maxPartBytes ?? DEFAULT_UR_LIMITS.maxPartBytes,
    maxTotalBytes: requestedLimits.maxTotalBytes ?? DEFAULT_UR_LIMITS.maxTotalBytes,
    maxParts: requestedLimits.maxParts ?? DEFAULT_UR_LIMITS.maxParts,
    maxFrames: requestedLimits.maxFrames ?? DEFAULT_UR_LIMITS.maxFrames,
    maxDurationMs: requestedLimits.maxDurationMs ?? DEFAULT_UR_LIMITS.maxDurationMs,
  };
  for (const [name, value] of Object.entries(limits)) {
    if (!Number.isFinite(value) || value <= 0 || !Number.isInteger(value)) {
      throw new RangeError(`BC-UR limit ${name} must be a positive finite integer`);
    }
  }
  return limits;
}

/**
 * Load the BC-UR2 decoder and return a fresh {@link URAssembler}. Dynamically
 * imports `@ngraveio/bc-ur` so it stays out of the initial bundle.
 */
export async function createURAssembler(
  requestedLimits: URLimits = {},
  now: () => number = Date.now,
): Promise<URAssembler> {
  await ensureBuffer();
  const { URDecoder } = await import("@ngraveio/bc-ur");
  const decoder = new URDecoder();
  const limits = resolveLimits(requestedLimits);
  const startedAt = now();
  let frames = 0;
  let totalBytes = 0;
  let terminalError = "";

  function rejectLimit(message: string): never {
    terminalError = message;
    throw new URDecodeLimitError(message);
  }

  return {
    receivePart(part: string) {
      if (terminalError) throw new URDecodeLimitError(terminalError);
      const partBytes = new TextEncoder().encode(part).byteLength;
      if (partBytes > limits.maxPartBytes) {
        rejectLimit("The scanned QR part is too large.");
      }
      let count: number;
      try {
        count = advertisedPartCount(part);
      } catch (err) {
        rejectLimit(err instanceof Error ? err.message : "BC-UR part has an invalid sequence");
      }
      if (count > limits.maxParts) {
        rejectLimit("The scanned QR stream advertises too many parts.");
      }
      if (now() - startedAt > limits.maxDurationMs) {
        rejectLimit("The scanned QR stream took too long to complete.");
      }
      if (frames >= limits.maxFrames) {
        rejectLimit("The scanned QR stream contains too many frames.");
      }
      if (totalBytes + partBytes > limits.maxTotalBytes) {
        rejectLimit("The scanned QR stream is too large.");
      }
      frames++;
      totalBytes += partBytes;
      decoder.receivePart(part);
    },
    progressPercent() {
      // getProgress() can be 0/undefined before any part arrives; clamp to 0.
      return Math.round((decoder.getProgress() || 0) * 100);
    },
    isError() {
      // bc-ur returns undefined before the first part; normalise to a boolean.
      return terminalError !== "" || decoder.isError() === true;
    },
    error() {
      return terminalError || decoder.resultError() || "";
    },
    isComplete() {
      return decoder.isComplete() === true;
    },
    isSuccess() {
      return decoder.isSuccess() === true;
    },
    result() {
      const ur = decoder.resultUR();
      return { type: ur.type, cborHex: toHex(new Uint8Array(ur.cbor)) };
    },
  };
}

/**
 * Reassemble an ordered list of BC-UR2 part strings into a {@link ScannedUR}.
 *
 * The counterpart of {@link encodeUR} for testing and non-streaming callers:
 * feeds the parts through a {@link URAssembler} and throws if they do not
 * decode to a complete, successful UR.
 */
export async function decodeUR(parts: string[]): Promise<ScannedUR> {
  const assembler = await createURAssembler();
  for (const part of parts) {
    assembler.receivePart(part);
    if (assembler.isError() || assembler.isComplete()) break;
  }
  if (assembler.isError()) {
    throw new Error(assembler.error() || "UR decode failed");
  }
  if (!assembler.isComplete() || !assembler.isSuccess()) {
    throw new Error(assembler.error() || "UR is incomplete — not all parts were received");
  }
  return assembler.result();
}
