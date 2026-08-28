/**
 * hw/ledger.ts — Thin WebHID wrapper for the Cardano Ledger app.
 *
 * Cloud-free: uses only @ledgerhq/hw-transport-webhid,
 * @cardano-foundation/ledgerjs-hw-app-cardano, and bech32.
 * No network calls are made beyond the HID transport.
 *
 * Xpub/witness encoding parity with Go lives in the shared hw/xpub.ts and
 * hw/witness.ts helpers so every device (Ledger, Trezor, …) encodes from one
 * implementation; the parity vector is exercised in ledger.test.ts.
 */

import Ada from "@cardano-foundation/ledgerjs-hw-app-cardano";
import type {
  AssetGroup,
  SignTransactionRequest,
  Token,
  TxInput,
  TxOutput,
} from "@cardano-foundation/ledgerjs-hw-app-cardano";
import {
  AddressType,
  MessageAddressFieldType,
  TransactionSigningMode,
  TxOutputDestinationType,
  TxOutputFormat,
  TxRequiredSignerType,
} from "@cardano-foundation/ledgerjs-hw-app-cardano";
import type { HardwareSignResponse } from "../api/types";
import type {
  HardwareCapabilities,
  HardwareSignMessageRequest,
  HardwareSignMessageResult,
  HardwareSigner,
} from "./types";
import { encodeXpub } from "./xpub";
import { encodeWitnessArray } from "./witness";
import { encodeCoseSign1, encodeCoseKey } from "./cose";
import { hexToBytes } from "./hex";

// ── BIP32 path ───────────────────────────────────────────────────────────────

const HARDENED = 0x80000000;

/** Convert account index to the CIP-1852 account-level path array. */
function accountPath(account: number): number[] {
  return [1852 + HARDENED, 1815 + HARDENED, account + HARDENED];
}

// parseBip32Path converts a CIP-1852 path string to a numeric array.
// "1852'/1815'/0'/0/3" → [0x80000000+1852, 0x80000000+1815, 0x80000000+0, 0, 3]
function parseBip32Path(pathStr: string): number[] {
  return pathStr.split("/").map((seg) => {
    const hardened = seg.endsWith("'");
    const n = parseInt(hardened ? seg.slice(0, -1) : seg, 10);
    return hardened ? n + HARDENED : n;
  });
}

// ── CIP-8 message hashing threshold ───────────────────────────────────────────
//
// The Cardano Ledger app streams the CIP-8 message in chunks and REJECTS a
// non-hashed message that overflows the first chunk (SDK error
// MESSAGE_DATA_LONG_NON_HASHED_MSG). The first-chunk capacity depends on whether
// the app renders the message as ASCII text or as hex, mirroring the pinned SDK
// (@cardano-foundation/ledgerjs-hw-app-cardano 7.1.4,
// dist/interactions/signMessage.js):
//
//   MAX_CIP8_MSG_FIRST_CHUNK_ASCII_SIZE = 198  (printable-ASCII messages)
//   MAX_CIP8_MSG_FIRST_CHUNK_HEX_SIZE   =  99  (everything else)
//
// so any message strictly longer than its threshold MUST be signed with
// hashPayload:true (device hashes with Blake2b-224 before signing). We reproduce
// the SDK's own isAscii() test (dist/parsing/messageData.js) — since we pass
// preferHexDisplay:false, isAscii = isAscii(messageHex) — to pick the matching
// threshold, so our decision agrees with the app's chunker exactly.
const MAX_CIP8_MSG_FIRST_CHUNK_ASCII_SIZE = 198;
const MAX_CIP8_MSG_FIRST_CHUNK_HEX_SIZE = 99;

// isPrintableAsciiMessage mirrors the Ledger SDK's isAscii(): every byte must be
// printable ASCII (0x20–0x7e), the message must be non-empty, and it must not
// start/end with a space or contain a double space.
function isPrintableAsciiMessage(bytes: Uint8Array): boolean {
  if (bytes.length === 0) return false;
  const SPACE = 0x20;
  for (let i = 0; i < bytes.length; i++) {
    if (bytes[i] < SPACE || bytes[i] > 0x7e) return false;
  }
  if (bytes[0] === SPACE || bytes[bytes.length - 1] === SPACE) return false;
  for (let i = 0; i + 1 < bytes.length; i++) {
    if (bytes[i] === SPACE && bytes[i + 1] === SPACE) return false;
  }
  return true;
}

// needsHashedPayload returns true when the raw message is too long to be signed
// unhashed for how the device will render it (ASCII vs hex first-chunk limit).
function needsHashedPayload(messageBytes: Uint8Array): boolean {
  const threshold = isPrintableAsciiMessage(messageBytes)
    ? MAX_CIP8_MSG_FIRST_CHUNK_ASCII_SIZE
    : MAX_CIP8_MSG_FIRST_CHUNK_HEX_SIZE;
  return messageBytes.length > threshold;
}

// ── Neutral → ledgerjs mapping ────────────────────────────────────────────────

// mapTokenBundle groups a neutral output's native assets by policy id and maps
// them into the ledgerjs AssetGroup/Token shape. Without this, a multi-asset
// send would reach the device with an empty bundle and the device would sign a
// DIFFERENT transaction than the backend built (dropping the tokens entirely).
function mapTokenBundle(
  assets: NonNullable<HardwareSignResponse["outputs"][number]["assets"]>,
): AssetGroup[] {
  const byPolicy = new Map<string, Token[]>();
  for (const a of assets) {
    const tokens = byPolicy.get(a.policy_id_hex) ?? [];
    tokens.push({ assetNameHex: a.asset_name_hex, amount: BigInt(a.amount) });
    byPolicy.set(a.policy_id_hex, tokens);
  }
  return Array.from(byPolicy, ([policyIdHex, tokens]) => ({ policyIdHex, tokens }));
}

// mapToSignRequest converts a HardwareSignResponse (from the backend) to the
// SignTransactionRequest format that ledgerjs expects. This lived in Send.tsx
// as a device-specific leak; it now belongs to the Ledger signer, which is the
// only code that knows the ledgerjs shape.
function mapToSignRequest(resp: HardwareSignResponse): SignTransactionRequest {
  const inputs: TxInput[] = resp.inputs.map((inp) => ({
    txHashHex: inp.tx_hash_hex,
    outputIndex: inp.output_index,
    path: inp.path ? parseBip32Path(inp.path) : null,
  }));

  const outputs: TxOutput[] = resp.outputs.map((out) => {
    const destination = out.payment_path && out.stake_path
      ? {
          type: TxOutputDestinationType.DEVICE_OWNED as const,
          params: {
            type: AddressType.BASE_PAYMENT_KEY_STAKE_KEY as const,
            params: {
              spendingPath: parseBip32Path(out.payment_path),
              stakingPath: parseBip32Path(out.stake_path),
            },
          },
        }
      : {
          type: TxOutputDestinationType.THIRD_PARTY as const,
          params: { addressHex: out.address_hex },
        };

    return {
      format: TxOutputFormat.ARRAY_LEGACY,
      destination,
      amount: BigInt(out.lovelace),
      // Carry any native assets grouped by policy so the device signs the same
      // tx the backend built. ledgerjs iterates this field even when the output
      // is ADA-only, so an empty array is the correct no-asset value.
      tokenBundle: out.assets && out.assets.length > 0 ? mapTokenBundle(out.assets) : [],
    };
  });

  return {
    tx: {
      network: {
        protocolMagic: resp.protocol_magic,
        networkId: resp.network_id,
      },
      inputs,
      outputs,
      fee: BigInt(resp.fee),
      ttl: resp.ttl ? BigInt(resp.ttl) : null,
      requiredSigners: resp.required_signers.map((hashHex) => ({
        type: TxRequiredSignerType.HASH,
        hashHex,
      })),
      includeNetworkId: resp.include_network_id || null,
    },
    signingMode: TransactionSigningMode.ORDINARY_TRANSACTION,
    options: {
      tagCborSets: resp.body_set_tag_policy === "tagged",
    },
  };
}

// ── Public API ────────────────────────────────────────────────────────────────

// Ledger signs send (ordinary) transactions and CIP-8 messages on-device; the
// other tx flows are declared unsupported until their neutral→ledgerjs mappings
// land.
const LEDGER_CAPABILITIES: HardwareCapabilities = {
  send: true,
  staking: false,
  governance: false,
  multisig: false,
  poolReg: false,
  signMessage: true,
};

/**
 * Open a connection to a Ledger device via WebHID and return a HardwareSigner.
 *
 * @throws Error — "WebHID not available — open this in a Chromium browser"
 *   if the browser does not support the WebHID API.
 */
export async function connectLedger(): Promise<HardwareSigner> {
  if (
    typeof navigator === "undefined" ||
    (navigator as Navigator & { hid?: unknown }).hid === undefined
  ) {
    throw new Error("WebHID not available — open this in a Chromium browser");
  }

  // Loaded on demand, as trezor.ts and keystone.ts load their transports: this
  // keeps the WebHID transport (and the Node-shaped globals it reaches for) out
  // of the initial bundle, so a user who never touches a Ledger never pays for
  // it and a fault in it cannot take down app startup.
  const { default: TransportWebHID } = await import("@ledgerhq/hw-transport-webhid");
  const transport = await TransportWebHID.create();
  const cardano = new Ada(transport);

  return {
    kind: "ledger",
    capabilities: LEDGER_CAPABILITIES,

    async getAccountXpub(account: number): Promise<string> {
      const path = accountPath(account);
      const { publicKeyHex, chainCodeHex } = await cardano.getExtendedPublicKey({ path });
      return encodeXpub(publicKeyHex, chainCodeHex);
    },

    async signTx(req: HardwareSignResponse): Promise<string> {
      // 0. Shape the neutral request into what the Cardano Ledger app expects.
      const request = mapToSignRequest(req);

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

    async signMessage(req: HardwareSignMessageRequest): Promise<HardwareSignMessageResult> {
      // The device signs the CIP-8 Sig_structure and returns the raw pieces
      // (signature + public key + the address field it put in the protected
      // header); hw/cose.ts assembles them into the COSE_Sign1 / COSE_Key the
      // backend verifier and dApps expect. The DEVICE_OWNED base address mirrors
      // the software path (bursa.SignData).
      //
      // hashPayload: the Ledger app refuses a non-hashed message that overflows
      // its first streaming chunk, so a normal login/proof message can be too
      // long to sign unhashed. For those we set hashPayload:true (device hashes
      // with Blake2b-224 before signing) and record it in the COSE "hashed"
      // header; the bursa verifier re-hashes the raw payload, so the raw message
      // still goes in the COSE payload field either way. Short messages keep
      // hashPayload:false — byte-identical to the software path.
      const messageBytes = hexToBytes(req.messageHex);
      const hashPayload = needsHashedPayload(messageBytes);
      const signingPath = parseBip32Path(req.signingPath);
      const { signatureHex, signingPublicKeyHex, addressFieldHex } =
        await cardano.signMessage({
          messageHex: req.messageHex,
          signingPath,
          hashPayload,
          preferHexDisplay: false,
          addressFieldType: MessageAddressFieldType.ADDRESS,
          address: {
            type: AddressType.BASE_PAYMENT_KEY_STAKE_KEY,
            params: {
              spendingPath: signingPath,
              stakingPath: parseBip32Path(req.stakePath),
            },
          },
          network: {
            networkId: req.networkId,
            protocolMagic: req.protocolMagic,
          },
        });
      return {
        signature: encodeCoseSign1(addressFieldHex, req.messageHex, signatureHex, hashPayload),
        key: encodeCoseKey(signingPublicKeyHex),
      };
    },

    async close(): Promise<void> {
      await transport.close();
    },
  };
}
