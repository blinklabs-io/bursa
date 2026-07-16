/**
 * hw/ledger.ts — Thin WebHID wrapper for the Cardano Ledger app.
 *
 * Cloud-free: uses only @ledgerhq/hw-transport-webhid,
 * @cardano-foundation/ledgerjs-hw-app-cardano, and bech32.
 * No network calls are made beyond the HID transport.
 *
 * Xpub encoding parity with Go:
 *   bip32.XPub.String() encodes 64 bytes (publicKey || chainCode) as bech32
 *   with HRP "root_xvk" — exactly what getAccountXpub produces here.
 *   Verified against the Go canonical vector for the "abandon ×11 about"
 *   test mnemonic at account 0 (see ledger.test.ts).
 */

import TransportWebHID from "@ledgerhq/hw-transport-webhid";
import Ada from "@cardano-foundation/ledgerjs-hw-app-cardano";
import type { SignTransactionRequest } from "@cardano-foundation/ledgerjs-hw-app-cardano";
import { encode as bech32Encode, toWords as bech32ToWords } from "bech32";

// ── CBOR helpers (minimal, covers only the witness-set structure) ─────────────

/**
 * Encode a small non-negative integer as CBOR unsigned int.
 * This is only ever called with small witness-array cardinalities (the count of
 * distinct signers in a transaction), NOT with lovelace amounts (those go
 * through ledgerjs BigInt). The 65535 cap is therefore never reached in practice.
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

/** Encode a hex string as Uint8Array. */
function hexToBytes(hex: string): Uint8Array {
  const len = hex.length;
  const out = new Uint8Array(len / 2);
  for (let i = 0; i < len; i += 2) {
    out[i / 2] = parseInt(hex.slice(i, i + 2), 16);
  }
  return out;
}

/** Encode bytes as lowercase hex string. */
function bytesToHex(bytes: number[]): string {
  return bytes.map((b) => b.toString(16).padStart(2, "0")).join("");
}

// ── BIP32 path ───────────────────────────────────────────────────────────────

const HARDENED = 0x80000000;

/** Convert account index to the CIP-1852 account-level path array. */
function accountPath(account: number): number[] {
  return [1852 + HARDENED, 1815 + HARDENED, account + HARDENED];
}

// ── Bech32 xpub encoding ─────────────────────────────────────────────────────

/**
 * Encode a raw {publicKeyHex, chainCodeHex} pair as a bech32 xpub with HRP
 * "root_xvk". This matches Go's bip32.XPub.String() exactly:
 *   data = publicKey(32 bytes) || chainCode(32 bytes)  →  bech32(root_xvk, data)
 *
 * The bech32 package's 90-char default limit is bypassed by passing limit=1000.
 */
function encodeXpub(publicKeyHex: string, chainCodeHex: string): string {
  const pubBytes = Array.from(hexToBytes(publicKeyHex));
  const ccBytes = Array.from(hexToBytes(chainCodeHex));
  const data = new Uint8Array([...pubBytes, ...ccBytes]); // 64 bytes
  const words = bech32ToWords(data);
  return bech32Encode("root_xvk", words, 1000 /* no length limit */);
}

// ── Raw vkey-witness-array CBOR encoding ─────────────────────────────────────────────────

/**
 * Encode the raw vkey-witness array consumed by the backend's SubmitSigned.
 *
 * Format: [[pubkey_bytes, sig_bytes], ...]
 *   - each witness = [32-byte Ed25519 pubkey, 64-byte Ed25519 signature]
 */
function encodeWitnessArray(witnesses: { pubKeyHex: string; sigHex: string }[]): string {
  return bytesToHex(
    cborArray(
      witnesses.map(({ pubKeyHex, sigHex }) =>
        cborArray([cborBytes(pubKeyHex), cborBytes(sigHex)]),
      ),
    ),
  );
}

// ── Public API ────────────────────────────────────────────────────────────────

/** A live session with a Ledger device running the Cardano app. */
export interface LedgerSession {
  /**
   * Derive the account-level extended public key from the device.
   * Calls getExtendedPublicKey(m/1852'/1815'/<account>') and encodes
   * the result as a bech32 "root_xvk" string identical to what Go's
   * bip32.XPub.String() / wallet.AccountXpub() produces.
   */
  getAccountXpub(account: number): Promise<string>;

  /**
   * Sign a transaction on the device.
   * @param request - The full SignTransactionRequest for the Cardano Ledger app.
   * @returns CBOR-encoded raw vkey-witness array hex string.
   */
  signTx(request: SignTransactionRequest): Promise<string>;

  /** Close the underlying HID transport. */
  close(): Promise<void>;
}

/**
 * Open a connection to a Ledger device via WebHID and return a LedgerSession.
 *
 * @throws Error — "WebHID not available — open this in a Chromium browser"
 *   if the browser does not support the WebHID API.
 */
export async function connectLedger(): Promise<LedgerSession> {
  if (
    typeof navigator === "undefined" ||
    (navigator as Navigator & { hid?: unknown }).hid === undefined
  ) {
    throw new Error("WebHID not available — open this in a Chromium browser");
  }

  const transport = await TransportWebHID.create();
  const cardano = new Ada(transport);

  return {
    async getAccountXpub(account: number): Promise<string> {
      const path = accountPath(account);
      const { publicKeyHex, chainCodeHex } = await cardano.getExtendedPublicKey({ path });
      return encodeXpub(publicKeyHex, chainCodeHex);
    },

    async signTx(request: SignTransactionRequest): Promise<string> {
      // 1. Ask the device to sign the transaction and collect witness signatures.
      const { witnesses } = await cardano.signTransaction(request);

      // 2. Resolve each signing path → public key (needed for each vkey witness).
      //    We fetch the pubkey for each witness path returned by the device.
      const resolved = await Promise.all(
        witnesses.map(async (w) => {
          // The device must return the path it signed with so we can fetch the
          // matching public key. A positional fallback (e.g. [0]) would pair the
          // signature with the wrong key when there is more than one signer.
          if (!w.path) {
            throw new Error(
              "Ledger returned a witness without a derivation path; cannot resolve its public key",
            );
          }
          const xpub = await cardano.getExtendedPublicKey({ path: w.path });
          return { pubKeyHex: xpub.publicKeyHex, sigHex: w.witnessSignatureHex };
        }),
      );

      // 3. Encode the raw witness array expected by SubmitSigned.
      return encodeWitnessArray(resolved);
    },

    async close(): Promise<void> {
      await transport.close();
    },
  };
}
