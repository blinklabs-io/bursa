/**
 * hw/qr/cbor.ts — Minimal CBOR reader + writer shared by air-gapped-QR devices.
 *
 * Air-gapped signers exchange bespoke, untagged, integer-keyed CBOR payloads
 * (a Keystone `cardano-signature` witness set, a SeedSigner request map, …). The
 * device SDKs that ship one already carry their own codec, but a device that
 * defines its own payload shape needs a small, dependency-free codec that is
 * BYTE-STABLE and bounds-checked. This module is that codec:
 *   - {@link decodeCbor} — a defensive reader (used to pull the vkey witnesses
 *     out of a scanned Keystone witness set) that rejects truncated/overrun
 *     input rather than silently yielding a plausible-but-wrong value.
 *   - {@link encodeCbor} — an untagged, integer-keyed writer whose output the
 *     reader round-trips exactly. It emits the MINIMAL header for every length
 *     so the same value always serialises to the same bytes.
 *
 * Scope is deliberately narrow: unsigned integers, byte strings, text strings,
 * arrays, and maps keyed by non-negative integers. No tags, no floats, no
 * negative integers — the shapes air-gapped Cardano payloads actually use.
 */

// ── Reader ───────────────────────────────────────────────────────────────────

export type CborValue =
  | number
  | Uint8Array
  | string
  | CborValue[]
  | Map<number, CborValue>;

// This decoder parses input that arrives off a camera (a scanned QR), so every
// multi-byte read is bounds-checked against the buffer length: past the end,
// `buf[i]` yields `undefined`, which would otherwise coerce to a plausible-looking
// zero/NaN length and produce a silently-empty result. Overrun MUST throw here so
// a truncated/hostile frame fails at the parse rather than at submission.
function need(buf: Uint8Array, pos: number, n: number): void {
  if (pos + n > buf.length) {
    throw new Error(
      `CBOR: unexpected end of input (need ${n} byte(s) at offset ${pos}, have ${buf.length})`,
    );
  }
}

/** Decode one CBOR data item at `offset`; returns the value and the next offset. */
export function decodeCbor(buf: Uint8Array, offset: number): { value: CborValue; next: number } {
  need(buf, offset, 1);
  const first = buf[offset];
  const major = first >> 5;
  const info = first & 0x1f;
  let len = info;
  let pos = offset + 1;
  if (info === 24) {
    need(buf, pos, 1);
    len = buf[pos];
    pos += 1;
  } else if (info === 25) {
    need(buf, pos, 2);
    len = (buf[pos] << 8) | buf[pos + 1];
    pos += 2;
  } else if (info === 26) {
    need(buf, pos, 4);
    len = buf[pos] * 0x1000000 + (buf[pos + 1] << 16) + (buf[pos + 2] << 8) + buf[pos + 3];
    pos += 4;
  } else if (info === 27) {
    // 64-bit length: witness sets never approach 2^53, so a Number is safe here.
    need(buf, pos, 8);
    len = 0;
    for (let i = 0; i < 8; i++) len = len * 256 + buf[pos + i];
    pos += 8;
  } else if (info > 27) {
    throw new Error(`CBOR: unsupported additional-info ${info}`);
  }

  switch (major) {
    case 0: // unsigned int
      return { value: len, next: pos };
    case 2: {
      // byte string
      need(buf, pos, len);
      const value = buf.slice(pos, pos + len);
      return { value, next: pos + len };
    }
    case 3: {
      // text string
      need(buf, pos, len);
      const value = new TextDecoder().decode(buf.slice(pos, pos + len));
      return { value, next: pos + len };
    }
    case 4: {
      // array
      const arr: CborValue[] = [];
      let p = pos;
      for (let i = 0; i < len; i++) {
        const r = decodeCbor(buf, p);
        arr.push(r.value);
        p = r.next;
      }
      return { value: arr, next: p };
    }
    case 5: {
      // map
      const map = new Map<number, CborValue>();
      let p = pos;
      for (let i = 0; i < len; i++) {
        const k = decodeCbor(buf, p);
        const v = decodeCbor(buf, k.next);
        map.set(k.value as number, v.value);
        p = v.next;
      }
      return { value: map, next: p };
    }
    case 6: {
      // tag — unwrap (e.g. the Conway set tag 258 around a witness array)
      const r = decodeCbor(buf, pos);
      return { value: r.value, next: r.next };
    }
    default:
      throw new Error(`CBOR: unsupported major type ${major}`);
  }
}

// ── Writer ───────────────────────────────────────────────────────────────────

/**
 * A value the {@link encodeCbor} writer can serialise. Mirrors the reader's
 * {@link CborValue}: a `number` is an unsigned integer, a `Uint8Array` a byte
 * string, a `string` a text string, an array an array, and a `Map` an
 * integer-keyed map. Encoding then decoding any of these yields an equal value.
 */
export type CborWritable =
  | number
  | Uint8Array
  | string
  | CborWritable[]
  | Map<number, CborWritable>;

/**
 * Encode a length/value as a CBOR head of the given major type, choosing the
 * MINIMAL additional-info form so a given number always yields the same bytes
 * (deterministic output the reader accepts).
 */
function encodeHead(major: number, n: number): number[] {
  const mt = major << 5;
  if (n < 24) return [mt | n];
  if (n < 0x100) return [mt | 24, n & 0xff];
  if (n < 0x10000) return [mt | 25, (n >>> 8) & 0xff, n & 0xff];
  if (n < 0x100000000) {
    return [mt | 26, (n >>> 24) & 0xff, (n >>> 16) & 0xff, (n >>> 8) & 0xff, n & 0xff];
  }
  // 64-bit: split into two 32-bit halves (values never approach 2^53 here).
  const hi = Math.floor(n / 0x100000000);
  const lo = n % 0x100000000;
  return [
    mt | 27,
    (hi >>> 24) & 0xff,
    (hi >>> 16) & 0xff,
    (hi >>> 8) & 0xff,
    hi & 0xff,
    (lo >>> 24) & 0xff,
    (lo >>> 16) & 0xff,
    (lo >>> 8) & 0xff,
    lo & 0xff,
  ];
}

function encodeValue(v: CborWritable, out: number[]): void {
  if (typeof v === "number") {
    if (!Number.isInteger(v) || v < 0) {
      throw new Error(`encodeCbor: only non-negative integers are supported (got ${v})`);
    }
    out.push(...encodeHead(0, v));
  } else if (v instanceof Uint8Array) {
    out.push(...encodeHead(2, v.length));
    for (const b of v) out.push(b);
  } else if (typeof v === "string") {
    const bytes = new TextEncoder().encode(v);
    out.push(...encodeHead(3, bytes.length));
    for (const b of bytes) out.push(b);
  } else if (Array.isArray(v)) {
    out.push(...encodeHead(4, v.length));
    for (const item of v) encodeValue(item, out);
  } else if (v instanceof Map) {
    out.push(...encodeHead(5, v.size));
    // Keys are emitted in the map's insertion order — the caller controls the
    // ordering, which is what integer-keyed device payloads rely on.
    for (const [k, val] of v) {
      if (!Number.isInteger(k) || k < 0) {
        throw new Error(`encodeCbor: map keys must be non-negative integers (got ${String(k)})`);
      }
      out.push(...encodeHead(0, k));
      encodeValue(val, out);
    }
  } else {
    throw new Error("encodeCbor: unsupported value");
  }
}

/**
 * Encode a {@link CborWritable} to untagged, integer-keyed CBOR bytes.
 * {@link decodeCbor} round-trips the result exactly.
 */
export function encodeCbor(value: CborWritable): Uint8Array {
  const out: number[] = [];
  encodeValue(value, out);
  return Uint8Array.from(out);
}
