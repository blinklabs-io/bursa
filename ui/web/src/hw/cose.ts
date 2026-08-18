/**
 * hw/cose.ts — Minimal COSE_Sign1 / COSE_Key assembly for CIP-8 / CIP-30
 * message signing, shared by hardware signers that return the raw pieces of a
 * signature (a Ledger returns signature + public key + address field, not an
 * assembled COSE structure).
 *
 * The byte layout MUST match what the bursa keys layer emits (bursa.SignData in
 * the Go root module) so the same backend verifier (bursa.VerifyData, behind the
 * Verify screen) accepts a hardware-produced signature identically to a
 * software-produced one:
 *
 *   COSE_Sign1 = [ protected_bstr, {"hashed": <bool>}, payload_bstr, signature_bstr ]
 *     protected = CBOR( {1: -8 (EdDSA), "address": <address bytes>} )
 *   COSE_Key   = { 1: 1 (OKP), 3: -8 (EdDSA), -1: 6 (Ed25519), -2: <pubkey> }
 *
 * The COSE payload field always carries the RAW message bytes, even when the
 * device hashed the payload before signing (CIP-8 hashed=true, Blake2b-224).
 * The bursa verifier (message.go payloadToVerify) re-hashes c.Payload when the
 * "hashed" header is true, so a device signature over Blake2b-224(message)
 * verifies against the raw message stored here — do NOT store the hash.
 *
 * The device signs the COSE Sig_structure over these EXACT protected-header
 * bytes, so the map here is canonical CBOR (integer label 1 sorts before the
 * "address" text label) — identical to the gouroboros canonical encoding the Go
 * side produces.
 *
 * A hand-rolled encoder (like hw/witness.ts) is used deliberately: the structure
 * is tiny and fixed, so pulling a CBOR library into the bundle is unwarranted.
 */

import { hexToBytes, bytesToHex } from "./hex";

const COSE_ALG_EDDSA = -8;
const COSE_KTY_OKP = 1;
const COSE_CRV_ED25519 = 6;

/** Encode a non-negative integer as a CBOR unsigned-int head (major type 0). */
function cborUintHead(n: number): number[] {
  if (n < 24) return [n];
  if (n < 256) return [0x18, n];
  if (n < 65536) return [0x19, n >> 8, n & 0xff];
  throw new RangeError(`cborUintHead: ${n} is too large`);
}

/** Encode a small negative integer (CBOR major type 1: value = -1 - arg). */
function cborNint(n: number): number[] {
  if (n >= 0) throw new RangeError(`cborNint: ${n} is not negative`);
  const head = cborUintHead(-1 - n);
  head[0] |= 0x20; // major type 1 = negative integer
  return head;
}

/** Encode raw bytes as a CBOR byte string (major type 2). */
function cborBytes(bytes: Uint8Array): number[] {
  const head = cborUintHead(bytes.length);
  head[0] |= 0x40;
  return [...head, ...Array.from(bytes)];
}

/** Encode an ASCII string as a CBOR text string (major type 3). */
function cborText(s: string): number[] {
  const bytes = Array.from(s, (c) => c.charCodeAt(0));
  const head = cborUintHead(bytes.length);
  head[0] |= 0x60;
  return [...head, ...bytes];
}

/**
 * Serialize the COSE protected-header map {1: -8, "address": addr} to CBOR.
 * Integer label 1 encodes shorter than the "address" text label, so canonical
 * ordering places it first — matching the bytes the device signed over.
 */
function protectedHeaders(addr: Uint8Array): number[] {
  return [
    0xa2, // map(2)
    ...cborUintHead(1), // label 1
    ...cborNint(COSE_ALG_EDDSA), // -8
    ...cborText("address"),
    ...cborBytes(addr),
  ];
}

/**
 * Assemble a COSE_Sign1 (hex) from the raw pieces a device returns.
 *
 * @param addressHex   The address bytes carried in the protected header — for a
 *   Ledger these are the `addressFieldHex` the device returns (the exact bytes it
 *   signed over).
 * @param payloadHex   The RAW signed message bytes (COSE payload), hex-encoded.
 *   Always the raw message, even when `hashed` is true (see the module header).
 * @param signatureHex The 64-byte Ed25519 signature the device produced.
 * @param hashed       Whether the device hashed the payload (Blake2b-224) before
 *   signing. Emitted as the unprotected `{"hashed": <bool>}` header so the
 *   verifier re-hashes the raw payload before checking the signature. Defaults
 *   to false, keeping the short/unhashed path byte-identical to before.
 */
export function encodeCoseSign1(
  addressHex: string,
  payloadHex: string,
  signatureHex: string,
  hashed = false,
): string {
  const prot = protectedHeaders(hexToBytes(addressHex));
  const bytes = [
    0x84, // array(4): [protected, unprotected, payload, signature]
    ...cborBytes(new Uint8Array(prot)), // protected headers as a byte string
    // unprotected headers: {"hashed": <bool>}
    0xa1, // map(1)
    ...cborText("hashed"),
    hashed ? 0xf5 : 0xf4, // true : false
    ...cborBytes(hexToBytes(payloadHex)),
    ...cborBytes(hexToBytes(signatureHex)),
  ];
  return bytesToHex(bytes);
}

/** Assemble a COSE_Key (hex) for an Ed25519 public key. */
export function encodeCoseKey(publicKeyHex: string): string {
  const bytes = [
    0xa4, // map(4)
    ...cborUintHead(1), // label 1 (kty)
    ...cborUintHead(COSE_KTY_OKP), // 1 (OKP)
    ...cborUintHead(3), // label 3 (alg)
    ...cborNint(COSE_ALG_EDDSA), // -8 (EdDSA)
    ...cborNint(-1), // label -1 (crv)
    ...cborUintHead(COSE_CRV_ED25519), // 6 (Ed25519)
    ...cborNint(-2), // label -2 (x / public key)
    ...cborBytes(hexToBytes(publicKeyHex)),
  ];
  return bytesToHex(bytes);
}
