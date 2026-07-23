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

import TransportWebHID from "@ledgerhq/hw-transport-webhid";
import Ada from "@cardano-foundation/ledgerjs-hw-app-cardano";
import type {
  SignTransactionRequest,
  TxInput,
  TxOutput,
} from "@cardano-foundation/ledgerjs-hw-app-cardano";
import {
  AddressType,
  TransactionSigningMode,
  TxOutputDestinationType,
  TxOutputFormat,
  TxRequiredSignerType,
} from "@cardano-foundation/ledgerjs-hw-app-cardano";
import type { HardwareSignResponse } from "../api/types";
import type { HardwareCapabilities, HardwareSigner } from "./types";
import { encodeXpub } from "./xpub";
import { encodeWitnessArray } from "./witness";

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

// ── Neutral → ledgerjs mapping ────────────────────────────────────────────────

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
      // ledgerjs iterates this field even when the output contains ADA only.
      tokenBundle: [],
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
  };
}

// ── Public API ────────────────────────────────────────────────────────────────

// Ledger currently signs send (ordinary) transactions on-device; the other
// flows are declared unsupported until their neutral→ledgerjs mappings land.
const LEDGER_CAPABILITIES: HardwareCapabilities = {
  send: true,
  staking: false,
  governance: false,
  multisig: false,
  poolReg: false,
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

    async close(): Promise<void> {
      await transport.close();
    },
  };
}
