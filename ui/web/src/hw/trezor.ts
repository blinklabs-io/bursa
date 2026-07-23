/**
 * hw/trezor.ts — Trezor Connect wrapper for the Cardano app (send-parity).
 *
 * CONSENT-LAW GATE: @trezor/connect-web talks to connect.trezor.io. Unlike the
 * Ledger path (WebHID, fully local), a Trezor connection LEAVES the user's
 * node. So:
 *   - the SDK is imported dynamically, only inside connectTrezor(), never at
 *     module load — importing it eagerly would pull the cloud bundle into the
 *     initial page and is easy to accidentally init;
 *   - TrezorConnect.init() (which loads the connect.trezor.io iframe) is called
 *     ONLY after the caller's requestExternalConsent() resolves true.
 *
 * Xpub/witness encoding parity is guaranteed by reusing the shared hw/xpub.ts
 * and hw/witness.ts encoders (identical output to the Ledger path for the same
 * key material — see trezor.test.ts).
 */

import type { HardwareSignResponse } from "../api/types";
import type { ConnectOptions, HardwareCapabilities, HardwareSigner } from "./types";
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
// Passed to Trezor as an explicit number[] rather than the "m/…" string form so
// the derivation is unambiguous regardless of the SDK's string-path parsing.
function parseBip32Path(pathStr: string): number[] {
  return pathStr.split("/").map((seg) => {
    const hardened = seg.endsWith("'");
    const n = parseInt(hardened ? seg.slice(0, -1) : seg, 10);
    return hardened ? n + HARDENED : n;
  });
}

// ── Trezor Connect manifest / init ────────────────────────────────────────────

// Trezor requires a manifest identifying the calling app so it can reach out if
// an integration misbehaves. This is the local Bursa wallet's identity; appUrl
// is the wallet's own origin when running in a browser context.
// NOTE (human follow-up): confirm the contact email before shipping.
const TREZOR_MANIFEST = {
  appName: "Bursa Wallet",
  email: "wallet@blinklabs.io",
  appUrl:
    typeof window !== "undefined" && window.location?.origin
      ? window.location.origin
      : "https://blinklabs.io",
};

// init() loads the connect.trezor.io iframe once per page; a second call throws
// "already initialized". Track it so repeated connects (and reconnect after a
// close/dispose) behave, without re-loading the iframe unnecessarily.
let trezorInitialized = false;

// ── Capabilities ──────────────────────────────────────────────────────────────

// Trezor currently signs send (ordinary) transactions on-device; the other
// flows are declared unsupported until their neutral→Trezor mappings land.
const TREZOR_CAPABILITIES: HardwareCapabilities = {
  send: true,
  staking: false,
  governance: false,
  multisig: false,
  poolReg: false,
};

// ── Public API ────────────────────────────────────────────────────────────────

/**
 * Connect to a Trezor device via Trezor Connect and return a HardwareSigner.
 *
 * @param opts.requestExternalConsent - REQUIRED in practice: it must resolve
 *   true before any connect.trezor.io contact is made. If it is absent or
 *   resolves false, no SDK is loaded, init() is never called, and this throws.
 */
export async function connectTrezor(opts?: ConnectOptions): Promise<HardwareSigner> {
  // CONSENT-LAW GATE — nothing external happens before this resolves true.
  const approved = opts?.requestExternalConsent ? await opts.requestExternalConsent() : false;
  if (!approved) {
    throw new Error(
      "Connecting a Trezor contacts connect.trezor.io; approval is required before proceeding.",
    );
  }

  // Import the SDK only now, after consent — keeps the cloud bundle out of the
  // initial load and makes it impossible to init() it before approval.
  const { default: TrezorConnect, PROTO } = await import("@trezor/connect-web");

  if (!trezorInitialized) {
    await TrezorConnect.init({ manifest: TREZOR_MANIFEST, lazyLoad: true });
    trezorInitialized = true;
  }

  return {
    kind: "trezor",
    capabilities: TREZOR_CAPABILITIES,

    async getAccountXpub(account: number): Promise<string> {
      const res = await TrezorConnect.cardanoGetPublicKey({
        path: accountPath(account),
        showOnTrezor: false,
      });
      if (!res.success) {
        throw new Error(res.payload.error);
      }
      // The extended public key is carried as node.public_key || node.chain_code
      // (32 + 32 bytes). Re-encode through the shared helper so the bech32
      // "root_xvk" string is byte-for-byte identical to the Ledger/Go output.
      const { public_key, chain_code } = res.payload.node;
      return encodeXpub(public_key, chain_code);
    },

    async signTx(req: HardwareSignResponse): Promise<string> {
      // Map the neutral request to Trezor's ORDINARY signing shape. Only the
      // payment inputs/outputs needed for send-parity are populated here.
      const inputs = req.inputs.map((inp) => ({
        path: inp.path ? parseBip32Path(inp.path) : undefined,
        prev_hash: inp.tx_hash_hex,
        prev_index: inp.output_index,
      }));

      const outputs = req.outputs.map((out) =>
        out.payment_path && out.stake_path
          ? {
              // Wallet-owned change: describe it by path so the device can
              // recognise it as its own and not prompt as an external send.
              addressParameters: {
                addressType: PROTO.CardanoAddressType.BASE,
                path: parseBip32Path(out.payment_path),
                stakingPath: parseBip32Path(out.stake_path),
              },
              amount: out.lovelace,
            }
          : {
              // Third-party recipient: the bech32 address as displayed.
              address: out.address_bech32,
              amount: out.lovelace,
            },
      );

      const res = await TrezorConnect.cardanoSignTransaction({
        signingMode: PROTO.CardanoTxSigningMode.ORDINARY_TRANSACTION,
        inputs,
        outputs,
        fee: req.fee,
        ...(req.ttl ? { ttl: req.ttl } : {}),
        protocolMagic: req.protocol_magic,
        networkId: req.network_id,
        ...(req.include_network_id ? { includeNetworkId: true } : {}),
      });
      if (!res.success) {
        throw new Error(res.payload.error);
      }

      // Trezor returns one witness per signer as {pubKey, signature}; the shared
      // encoder turns those into the canonical [[pubkey, sig], …] CBOR array.
      const resolved = res.payload.witnesses.map((w) => ({
        pubKeyHex: w.pubKey,
        sigHex: w.signature,
      }));
      return encodeWitnessArray(resolved);
    },

    async close(): Promise<void> {
      // Release the iframe/popup transport. A fresh connect re-inits it.
      TrezorConnect.dispose();
      trezorInitialized = false;
    },
  };
}
