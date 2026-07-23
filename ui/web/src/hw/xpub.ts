/**
 * hw/xpub.ts — Account-level extended-public-key bech32 encoding, shared by
 * every hardware signer (Ledger, Trezor, …).
 *
 * Xpub encoding parity with Go:
 *   bip32.XPub.String() encodes 64 bytes (publicKey || chainCode) as bech32
 *   with HRP "root_xvk". The backend's parseAccountXpub accepts that HRP (and
 *   the account-key HRP), both carrying the same 64-byte pubkey||chaincode.
 *   Verified against the Go canonical vector for the "abandon ×11 about"
 *   test mnemonic at account 0 (see ledger.test.ts / trezor.test.ts).
 *
 * Every device MUST produce an identical xpub for identical key material, so
 * this is the single encoder both ledger.ts and trezor.ts call — a per-device
 * copy could drift and silently import a wallet the backend can't match.
 */

import { encode as bech32Encode, toWords as bech32ToWords } from "bech32";
import { hexToBytes } from "./hex";

/**
 * Encode a raw {publicKeyHex, chainCodeHex} pair as a bech32 xpub with HRP
 * "root_xvk". This matches Go's bip32.XPub.String() exactly:
 *   data = publicKey(32 bytes) || chainCode(32 bytes)  →  bech32(root_xvk, data)
 *
 * The bech32 package's 90-char default limit is bypassed by passing limit=1000.
 */
export function encodeXpub(publicKeyHex: string, chainCodeHex: string): string {
  const pubBytes = Array.from(hexToBytes(publicKeyHex));
  const ccBytes = Array.from(hexToBytes(chainCodeHex));
  const data = new Uint8Array([...pubBytes, ...ccBytes]); // 64 bytes
  const words = bech32ToWords(data);
  return bech32Encode("root_xvk", words, 1000 /* no length limit */);
}
