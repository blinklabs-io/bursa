/**
 * hw/witness.ts — Raw vkey-witness-array CBOR encoding, shared by every
 * hardware signer.
 *
 * The backend's SubmitSigned / submit-hardware endpoint consumes a standard
 * witness array:
 *   [[pubkey_bytes, sig_bytes], ...]
 *     - each witness = [32-byte Ed25519 pubkey, 64-byte Ed25519 signature]
 *
 * Every device returns its witnesses in its own shape (Ledger: path→pubkey +
 * signature; Trezor: pubKey + signature per witness); each maps them to the
 * {pubKeyHex, sigHex} pairs this single encoder turns into the canonical CBOR.
 */

import { hexToBytes, bytesToHex } from "./hex";

// ── CBOR helpers (minimal, covers only the witness-set structure) ─────────────

/**
 * Encode a small non-negative integer as CBOR unsigned int.
 * This is only ever called with small witness-array cardinalities (the count of
 * distinct signers in a transaction), NOT with lovelace amounts (those go
 * through the device SDK's own encoders). The 65535 cap is therefore never
 * reached in practice.
 */
function cborUint(n: number): number[] {
  if (n < 24) return [n];
  if (n < 256) return [0x18, n];
  if (n < 65536) return [0x19, n >> 8, n & 0xff];
  throw new RangeError(`cborUint: ${n} is too large`);
}

/** Encode a byte array as a CBOR byte string. */
function cborBytes(hex: string): number[] {
  const bytes = hexToBytes(hex);
  const hdr = cborUint(bytes.length);
  hdr[0] |= 0x40; // major type 2 = byte string
  return [...hdr, ...Array.from(bytes)];
}

/** Encode a fixed-size array of already-encoded CBOR items. */
function cborArray(items: number[][]): number[] {
  const hdr = cborUint(items.length);
  hdr[0] |= 0x80; // major type 4 = array
  return [...hdr, ...items.flat()];
}

/**
 * Encode the raw vkey-witness array consumed by the backend's SubmitSigned.
 *
 * Format: [[pubkey_bytes, sig_bytes], ...]
 *   - each witness = [32-byte Ed25519 pubkey, 64-byte Ed25519 signature]
 */
export function encodeWitnessArray(
  witnesses: { pubKeyHex: string; sigHex: string }[],
): string {
  return bytesToHex(
    cborArray(
      witnesses.map(({ pubKeyHex, sigHex }) =>
        cborArray([cborBytes(pubKeyHex), cborBytes(sigHex)]),
      ),
    ),
  );
}
