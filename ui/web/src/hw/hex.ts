/**
 * hw/hex.ts — Minimal hex ⇄ bytes helpers shared by the hardware-signer
 * encoders (xpub bech32 and vkey-witness CBOR).
 *
 * Factored out so ledger.ts, trezor.ts, xpub.ts, and witness.ts all encode
 * from the SAME primitives — the byte-for-byte parity of every device's xpub
 * and witness output depends on there being exactly one implementation.
 */

/** Decode a lowercase/uppercase hex string to bytes. */
export function hexToBytes(hex: string): Uint8Array {
  const len = hex.length;
  const out = new Uint8Array(len / 2);
  for (let i = 0; i < len; i += 2) {
    out[i / 2] = parseInt(hex.slice(i, i + 2), 16);
  }
  return out;
}

/** Encode bytes as a lowercase hex string. */
export function bytesToHex(bytes: number[]): string {
  return bytes.map((b) => b.toString(16).padStart(2, "0")).join("");
}
