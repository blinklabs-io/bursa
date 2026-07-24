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
import type { ExternalConnectOptions, HardwareCapabilities, HardwareSigner } from "./types";
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

// Contact advertised in the Trezor Connect manifest so Trezor can reach the
// maintainers about integration issues.
const TREZOR_MANIFEST_CONTACT_EMAIL = "support@blinklabs.io";

// Trezor requires a manifest identifying the calling app so it can reach out if
// an integration misbehaves. This is the local Bursa wallet's identity; appUrl
// is the wallet's own origin when running in a browser context.
const TREZOR_MANIFEST = {
  appName: "Bursa Wallet",
  email: TREZOR_MANIFEST_CONTACT_EMAIL,
  appUrl:
    typeof window !== "undefined" && window.location?.origin
      ? window.location.origin
      : "https://blinklabs.io",
};

// init() loads the connect.trezor.io iframe once per page; a second call throws
// "already initialized". A SHARED init promise makes the lifecycle safe under
// concurrent connectTrezor() calls: two callers (e.g. a double-click) await the
// same in-flight init instead of both racing to init(). A failed init clears
// the promise so a later connect can retry.
let trezorInitPromise: Promise<void> | null = null;

// The connect.trezor.io transport is module-wide (one iframe per page), so it
// is shared by every live signer. Reference-count the live signers and dispose
// the transport (and clear the shared init) only when the LAST one closes —
// otherwise closing one of two concurrent sessions would tear the transport out
// from under the other, breaking its getAccountXpub/signTx.
let activeSignerCount = 0;

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

// ── Neutral → Trezor token-bundle mapping ─────────────────────────────────────

// A Trezor cardanoSignTransaction output token bundle: assets grouped by policy
// id, each carrying an asset-name + decimal amount (both hex/string). Typed
// locally to avoid importing the SDK's schema types at module load.
type TrezorAssetGroup = {
  policyId: string;
  tokenAmounts: { assetNameBytes: string; amount: string }[];
};

// mapTokenBundle groups a neutral output's native assets by policy id into the
// Trezor token-bundle shape, or returns undefined for an ADA-only output.
function mapTokenBundle(
  assets: HardwareSignResponse["outputs"][number]["assets"],
): TrezorAssetGroup[] | undefined {
  if (!assets || assets.length === 0) return undefined;
  const byPolicy = new Map<string, { assetNameBytes: string; amount: string }[]>();
  for (const a of assets) {
    const tokens = byPolicy.get(a.policy_id_hex) ?? [];
    tokens.push({ assetNameBytes: a.asset_name_hex, amount: a.amount });
    byPolicy.set(a.policy_id_hex, tokens);
  }
  return Array.from(byPolicy, ([policyId, tokenAmounts]) => ({ policyId, tokenAmounts }));
}

// ── Public API ────────────────────────────────────────────────────────────────

/**
 * Connect to a Trezor device via Trezor Connect and return a HardwareSigner.
 *
 * @param opts.requestExternalConsent - MANDATORY (enforced by the type and at
 *   runtime): it must resolve true before any connect.trezor.io contact is
 *   made. If it is absent or resolves false, no SDK is loaded, init() is never
 *   called, and this throws.
 */
export async function connectTrezor(opts: ExternalConnectOptions): Promise<HardwareSigner> {
  // CONSENT-LAW GATE — nothing external happens before this resolves true.
  // The consent callback is mandatory for this external-network connector; a
  // missing callback (e.g. an untyped JS caller) is rejected, never treated as
  // implicit approval.
  const consent = opts?.requestExternalConsent;
  if (typeof consent !== "function") {
    throw new Error(
      "Connecting a Trezor contacts connect.trezor.io; a consent callback is required before proceeding.",
    );
  }
  const approved = await consent();
  if (!approved) {
    throw new Error(
      "Connecting a Trezor contacts connect.trezor.io; approval is required before proceeding.",
    );
  }

  // Import the SDK only now, after consent — keeps the cloud bundle out of the
  // initial load and makes it impossible to init() it before approval.
  const { default: TrezorConnect, PROTO } = await import("@trezor/connect-web");

  // Guard init with a shared promise so concurrent connects can't both init().
  if (!trezorInitPromise) {
    trezorInitPromise = TrezorConnect.init({ manifest: TREZOR_MANIFEST, lazyLoad: true }).catch(
      (err: unknown) => {
        // A failed init must not poison future attempts — clear the shared
        // promise so a later connect can retry from a clean slate.
        trezorInitPromise = null;
        throw err;
      },
    );
  }
  await trezorInitPromise;

  // Init succeeded: this signer now shares the module-wide transport. Counted
  // here (after the await) so a failed init never leaves a phantom reference.
  activeSignerCount += 1;

  // Guards against a double close() double-decrementing the shared count.
  let closed = false;

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

      const outputs = req.outputs.map((out) => {
        // Carry any native assets grouped by policy id so the device signs the
        // same tx the backend built; without this a multi-asset send would sign
        // an ADA-only output that drops the tokens.
        const tokenBundle = mapTokenBundle(out.assets);
        return out.payment_path && out.stake_path
          ? {
              // Wallet-owned change: describe it by path so the device can
              // recognise it as its own and not prompt as an external send.
              addressParameters: {
                addressType: PROTO.CardanoAddressType.BASE,
                path: parseBip32Path(out.payment_path),
                stakingPath: parseBip32Path(out.stake_path),
              },
              amount: out.lovelace,
              ...(tokenBundle ? { tokenBundle } : {}),
            }
          : {
              // Third-party recipient: the bech32 address as displayed.
              address: out.address_bech32,
              amount: out.lovelace,
              ...(tokenBundle ? { tokenBundle } : {}),
            };
      });

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
      // Idempotent: a second close() on the same signer must not decrement the
      // shared count again.
      if (closed) return;
      closed = true;
      activeSignerCount -= 1;
      // Only the LAST live signer tears down the shared transport, so a
      // concurrent session stays usable. A fresh connect re-inits afterwards.
      if (activeSignerCount <= 0) {
        activeSignerCount = 0;
        TrezorConnect.dispose();
        trezorInitPromise = null;
      }
    },
  };
}
