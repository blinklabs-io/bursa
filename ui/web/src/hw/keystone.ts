/**
 * hw/keystone.ts — Keystone hardware-wallet signer (air-gapped QR + USB).
 *
 * Keystone is fully LOCAL on BOTH transports, so — unlike the Trezor path — no
 * external-consent gate applies (see the consent-law note in hw/types.ts):
 *   - QR  (primary): fully offline. An animated QR carries a `cardano-sign-request`
 *          UR to the device; the device signs on-screen and shows a
 *          `cardano-signature` UR the user scans back through the webcam. Only
 *          the local camera (getUserMedia) is touched — no network egress.
 *   - USB (secondary, best-effort): @keystonehq/hw-app-ada over WebUSB. The
 *          vendor SDK is young (v0.1.1) and firmware coverage is unverified, so
 *          failures are surfaced plainly and capabilities stay conservative.
 *
 * Every heavy dependency (@keystonehq/*, buffer) is loaded through a dynamic
 * import inside the connect path so it is CODE-SPLIT out of the initial bundle.
 *
 * Xpub/witness encoding parity with Ledger/Trezor/Go is guaranteed by reusing
 * the SHARED hw/xpub.ts and hw/witness.ts encoders: the account-sync xpub and
 * the assembled witness array are byte-for-byte identical for identical key
 * material (exercised in keystone.test.ts).
 */

import type { HardwareSignResponse } from "../api/types";
import type {
  HardwareCapabilities,
  HardwareSignMessageResult,
  HardwareSigner,
  KeystoneConnectOptions,
  KeystoneQRConnectOptions,
  KeystoneScannedUR,
} from "./types";
import { encodeXpub } from "./xpub";
import { encodeWitnessArray } from "./witness";
import { decodeCbor, type CborValue } from "./qr/cbor";
import { ensureBuffer, encodeUR } from "./qr/ur";
import { isValidXfp } from "./qr/xfp";
import { newRequestId, assertUuidRequestIdMatches } from "./requestId";

// signMessage is not yet implemented for Keystone: CIP-8 over the air-gapped QR
// transport needs the shared QR modal that lands with the SeedSigner work. The
// method rejects (rather than being absent) so callers that skip the
// capabilities.signMessage check still fail loudly instead of silently. It takes
// no argument (a narrower signature is still assignable to the interface's
// signMessage) so the unused request parameter is not carried.
function keystoneSignMessageUnsupported(): Promise<HardwareSignMessageResult> {
  return Promise.reject(
    new Error("Message signing is not supported on Keystone yet."),
  );
}

// ── BIP32 path helpers ───────────────────────────────────────────────────────

const HARDENED = 0x80000000;

/** CIP-1852 account-level path string, e.g. account 0 → "1852'/1815'/0'". */
function accountPathStr(account: number): string {
  return `1852'/1815'/${account}'`;
}

/** CIP-1852 account-level path array, e.g. [1852', 1815', account']. */
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

/** Normalise a path to the "1852'/1815'/0'" form (drop any leading "m/"). */
function normalizePath(path: string): string {
  return path.replace(/^m\//, "").trim();
}

// ── Capabilities ───────────────────────────────────────────────────────────

// QR is a "sign a raw tx body + witness these paths" model. Today only the
// payment inputs are mapped into the request's `utxos`; stake-key signer paths
// are NOT yet mapped into `extraSigners`, so a certificate tx would be witnessed
// incompletely. Staking is therefore advertised as UNSUPPORTED until those
// signer paths are wired in — don't flip this back to `true` without also
// populating `extraSigners` with the stake path(s). Structured multisig /
// pool-reg / governance are likewise not expressible here and stay gated off.
const KEYSTONE_QR_CAPABILITIES: HardwareCapabilities = {
  send: true,
  staking: false,
  governance: false,
  multisig: false,
  poolReg: false,
  // CIP-8 message signing over the air-gapped QR transport (the
  // cardano-cip8-sig-req/res UR flow) needs the shared QR modal that lands with
  // the SeedSigner work; gated off until then.
  signMessage: false,
};

// USB rides a young, unverified vendor SDK. We do not claim more than the
// send-parity baseline every implemented device already meets.
const KEYSTONE_USB_CAPABILITIES: HardwareCapabilities = {
  send: true,
  staking: false,
  governance: false,
  multisig: false,
  poolReg: false,
  signMessage: false,
};

// UR animated-QR fragment size (bytes of CBOR per frame). Small enough that each
// frame stays a low-density, reliably-scannable QR; larger txs simply animate
// across more frames, which the receiver reassembles.
const UR_MAX_FRAGMENT_LEN = 200;

// ── Witness-set extraction ────────────────────────────────────────────────────
//
// Keystone's `cardano-signature` UR carries a serialized TransactionWitnessSet,
// but the backend's submit endpoint wants the RAW vkey-witness array
// ([[pubkey, sig], …]) that hw/witness.ts produces. We use the shared CBOR reader
// (hw/qr/cbor.ts) to pull the vkey witnesses (map key 0) out of the witness set
// and re-encode them through the shared encoder, so Keystone's witness output is
// byte-identical to Ledger's and Trezor's.

function toHex(bytes: Uint8Array): string {
  let out = "";
  for (const b of bytes) out += b.toString(16).padStart(2, "0");
  return out;
}

/**
 * Extract {pubKeyHex, sigHex} pairs from a serialized TransactionWitnessSet.
 *
 * Accepts either the full witness set (a CBOR map whose key 0 is the vkey-witness
 * array) or, defensively, a bare vkey-witness array. Each vkey witness is
 * [pubkey_bytes, sig_bytes]. Some firmwares attach the 64-byte extended vkey
 * (pubkey || chaincode); only the leading 32-byte Ed25519 public key belongs in
 * a Cardano vkey witness, so we trim it to keep parity with the other devices.
 */
export function witnessSetToPairs(
  witnessSetBytes: Uint8Array,
): { pubKeyHex: string; sigHex: string }[] {
  const { value } = decodeCbor(witnessSetBytes, 0);
  let vkeyWitnesses: CborValue;
  if (value instanceof Map) {
    const w = value.get(0);
    if (!w) throw new Error("Keystone witness set has no vkey witnesses (map key 0 absent)");
    vkeyWitnesses = w;
  } else if (Array.isArray(value)) {
    vkeyWitnesses = value;
  } else {
    throw new Error("Keystone witness set is neither a map nor an array");
  }
  if (!Array.isArray(vkeyWitnesses)) {
    throw new Error("Keystone vkey-witness field is not an array");
  }
  return vkeyWitnesses.map((w) => {
    if (!Array.isArray(w) || w.length < 2) {
      throw new Error("Keystone vkey witness is not a [pubkey, sig] pair");
    }
    const [pub, sig] = w;
    if (!(pub instanceof Uint8Array) || !(sig instanceof Uint8Array)) {
      throw new Error("Keystone vkey witness fields are not byte strings");
    }
    // Trim an extended (pubkey||chaincode) vkey down to the 32-byte public key.
    const pubKey = pub.length > 32 ? pub.slice(0, 32) : pub;
    // A truncated/malformed frame can decode to a wrong-length key or signature;
    // reject it here rather than emit an invalid witness that fails at submission.
    if (pubKey.length !== 32) {
      throw new Error(`Keystone vkey witness public key is ${pubKey.length} bytes, expected 32`);
    }
    if (sig.length !== 64) {
      throw new Error(`Keystone vkey witness signature is ${sig.length} bytes, expected 64`);
    }
    return { pubKeyHex: toHex(pubKey), sigHex: toHex(sig) };
  });
}

// ── Account-sync (crypto-multi-accounts) parsing ─────────────────────────────

export interface KeystoneAccountSync {
  /** Bech32 "root_xvk" account xpub, byte-identical to Ledger/Trezor/Go. */
  xpub: string;
  /** Device master fingerprint (hex) — needed to sign later over QR. */
  xfp: string;
  /** The CIP-1852 account index the key was found at. */
  account: number;
}

/**
 * Parse a scanned `crypto-multi-accounts` UR into the CIP-1852 account xpub for
 * the requested account. The device exports one or more account keys; we select
 * the one whose derivation origin is m/1852'/1815'/<account>' and re-encode it
 * through the shared hw/xpub.ts helper so it matches every other device.
 */
async function decodeAccountSync(scanned: KeystoneScannedUR) {
  if (scanned.type !== "crypto-multi-accounts") {
    throw new Error(
      `Expected a Keystone account-sync QR (crypto-multi-accounts), got "${scanned.type}". ` +
        "On the Keystone, open the Cardano account and choose Sync / Connect Software Wallet.",
    );
  }
  await ensureBuffer();
  const { CryptoMultiAccounts, Buffer: B } = await import("@keystonehq/bc-ur-registry-cardano");
  // The registry's Buffer (from the `buffer` package) and @types/node's Buffer
  // are structurally different in TS though identical at runtime; bridge with a
  // cast at each library boundary.
  const accounts = CryptoMultiAccounts.fromCBOR(B.from(scanned.cborHex, "hex") as unknown as Buffer);
  const xfp = toHex(new Uint8Array(accounts.getMasterFingerprint()));
  return { accounts, xfp };
}

/**
 * Read ONLY the device master fingerprint (xfp) from a scanned account-sync UR.
 *
 * The fingerprint is account-independent, so — unlike {@link parseAccountSyncUR}
 * — this needs no account index and does not require a specific account key to be
 * present. Used by Send's recovery flow to re-learn the xfp of an
 * already-added wallet whose local hint was lost, without re-deriving its xpub.
 */
export async function parseAccountSyncXfp(scanned: KeystoneScannedUR): Promise<string> {
  const { xfp } = await decodeAccountSync(scanned);
  return xfp;
}

export async function parseAccountSyncUR(
  scanned: KeystoneScannedUR,
  account: number,
): Promise<KeystoneAccountSync> {
  const { accounts, xfp } = await decodeAccountSync(scanned);
  const wantHardened = accountPathStr(account); // "1852'/1815'/0'"
  const wantPlain = wantHardened.replace(/'/g, "h"); // some encoders render as "1852h/1815h/0h"

  for (const key of accounts.getKeys()) {
    const origin = key.getOrigin?.();
    const rawPath = origin ? normalizePath(origin.getPath()) : "";
    const path = rawPath.toLowerCase();
    if (path !== wantHardened && path !== wantPlain.toLowerCase()) continue;
    const pubKey = toHex(new Uint8Array(key.getKey()));
    const chainCode = toHex(new Uint8Array(key.getChainCode()));
    return { xpub: encodeXpub(pubKey, chainCode), xfp, account };
  }
  throw new Error(
    `This Keystone account-sync QR does not contain account ${account} ` +
      `(m/${wantHardened}). Re-export the sync QR for that account on the device.`,
  );
}

// ── QR sign-request assembly ─────────────────────────────────────────────────

/** A Keystone CardanoUtxoData record (mirrors the registry's constructor input). */
export interface KeystoneUtxo {
  transactionHash: string;
  index: number;
  amount: string;
  xfp: string;
  hdPath: string;
  address: string;
}

/**
 * Map the neutral request's wallet inputs into Keystone UTxO records.
 *
 * Each record carries the input's REAL lovelace amount and address so the device
 * can display the inputs and compute the fee (sum(inputs) − sum(outputs)) — the
 * whole reason to tolerate the air-gapped QR dance is to confirm, on hardware the
 * host cannot influence, exactly what is being approved.
 *
 * Every input in a send tx is wallet-owned and must therefore carry a derivation
 * path AND a resolved value. A missing path or value is a wrong-shape request
 * (an input the device could not witness, or could only partially describe), so
 * we throw NAMING the offending input rather than silently drop it or pad it with
 * a placeholder — either of which would let the device sign what it cannot show.
 */
export function buildKeystoneUtxos(req: HardwareSignResponse, xfp: string): KeystoneUtxo[] {
  const utxos = req.inputs.map((inp) => {
    const ref = `${inp.tx_hash_hex}#${inp.output_index}`;
    if (!inp.path) {
      throw new Error(
        `Keystone cannot sign input ${ref}: it has no derivation path (not recognised as ` +
          "wallet-owned), so the device could not witness it.",
      );
    }
    if (!inp.lovelace || !inp.address_bech32) {
      throw new Error(
        `Keystone input ${ref} is missing its resolved amount/address, so the device could ` +
          "not display it or compute the fee. This is a backend inconsistency; do not sign.",
      );
    }
    return {
      transactionHash: inp.tx_hash_hex,
      index: inp.output_index,
      // The Keystone UTxO registry carries lovelace + address only (no native
      // assets), which is sufficient for ADA-only sends and for the fee display.
      amount: inp.lovelace,
      xfp,
      hdPath: normalizePath(inp.path),
      address: inp.address_bech32,
    };
  });
  if (utxos.length === 0) {
    throw new Error("Keystone sign request has no inputs to witness.");
  }
  return utxos;
}

// ── Public API ───────────────────────────────────────────────────────────────

/**
 * Connect a Keystone via the air-gapped QR transport. Fully offline: the only
 * capability touched is the local webcam (through the UI bridge). No consent
 * gate — nothing leaves the node.
 */
export async function connectKeystoneQR(
  opts: KeystoneQRConnectOptions,
): Promise<HardwareSigner> {
  const { bridge } = opts;
  if (!bridge) {
    throw new Error("Keystone QR transport requires a UI bridge (animated-QR display + webcam scanner).");
  }

  return {
    kind: "keystone",
    capabilities: KEYSTONE_QR_CAPABILITIES,

    async getAccountXpub(account: number): Promise<string> {
      // The account xpub arrives on a SEPARATE account-sync QR, not the sign
      // registry — the caller scans it and we extract the CIP-1852 key.
      const scanned = await bridge.scanResponse();
      try {
        const sync = await parseAccountSyncUR(scanned, account);
        return sync.xpub;
      } finally {
        bridge.close();
      }
    },

    async signTx(req: HardwareSignResponse): Promise<string> {
      await ensureBuffer();
      const { CardanoSignRequest, CardanoSignature, Buffer: B } = await import(
        "@keystonehq/bc-ur-registry-cardano"
      );

      // The device master fingerprint is mandatory: it is how the Keystone
      // recognises the witness paths as its own. It is learned only at
      // account-sync and remembered as a local hint, so it CAN go missing (e.g.
      // a browser-data wipe). Never FABRICATE a zero fingerprint — a synthesized
      // all-zero xfp would silently produce a request the device cannot match, so
      // signing would appear to run but fail on-device. Block instead and steer
      // the user to re-scan the account-sync QR (which yields the fingerprint
      // again). Note: this blocks the ABSENCE of a fingerprint — a genuine
      // all-zero xfp reported by a real device is a valid (1-in-2^32) value and
      // is intentionally accepted (see isValidXfp in hw/qr/xfp.ts).
      const xfp = opts.xfp;
      if (!isValidXfp(xfp)) {
        throw new Error(
          "This Keystone wallet's device fingerprint is missing. Re-scan the account-sync QR " +
            "(open the Cardano account on the device and choose Sync / Connect Software Wallet) to recover it, then try again.",
        );
      }
      // Map the neutral request → a Keystone CardanoSignRequest:
      //   signData    = the unsigned tx body the device signs;
      //   utxos       = the wallet-owned inputs, each carrying its REAL lovelace
      //                 amount + address so the device displays the inputs and
      //                 computes the fee (sum(inputs) − sum(outputs)) on its own
      //                 screen — the security control for an air-gapped signer;
      //   extraSigners= none (send + simple witnessing only; structured
      //                 multisig/cert signers are gated off by capabilities).
      const signData = B.from(req.unsigned_tx_cbor, "hex") as unknown as Buffer;
      const utxos = buildKeystoneUtxos(req, xfp);

      // Retained so the reply's echoed identifier can be checked against THIS
      // request below — a stale scan (an earlier reply still on-screen) must
      // not be accepted as the answer to it.
      const requestId = newRequestId();
      const signRequest = CardanoSignRequest.constructCardanoSignRequest(
        signData,
        utxos,
        [],
        requestId,
        "bursa-wallet",
      );

      // Show the animated request QR, then wait for the user to scan the reply.
      // The BC-UR2 transport (hw/qr/ur.ts) turns the request's {UR type, CBOR}
      // into the animated-QR part strings.
      const reqUR = signRequest.toUR();
      const fragments = await encodeUR(
        reqUR.type,
        new Uint8Array(reqUR.cbor),
        UR_MAX_FRAGMENT_LEN,
      );
      bridge.displayRequest(fragments);
      try {
        const scanned = await bridge.scanResponse();
        if (scanned.type !== "cardano-signature") {
          throw new Error(
            `Expected a Keystone signature QR (cardano-signature), got "${scanned.type}".`,
          );
        }
        const signature = CardanoSignature.fromCBOR(
          B.from(scanned.cborHex, "hex") as unknown as Buffer,
        );
        const receivedId = signature.getRequestId();
        assertUuidRequestIdMatches(
          requestId,
          receivedId ? new Uint8Array(receivedId) : undefined,
          "Keystone signature reply",
        );
        const witnessSet = new Uint8Array(signature.getWitnessSet());
        return encodeWitnessArray(witnessSetToPairs(witnessSet));
      } finally {
        bridge.close();
      }
    },

    signMessage: keystoneSignMessageUnsupported,

    async close(): Promise<void> {
      // No persistent transport for QR; make sure any open modal/camera is torn
      // down (idempotent — bridge.close guards its own state).
      bridge.close();
    },
  };
}

/**
 * Connect a Keystone over USB (WebUSB).
 *
 * NOT USER-SELECTABLE: this rides a young vendor SDK (@keystonehq/hw-app-ada,
 * pre-1.0) whose firmware coverage has never been exercised against real
 * hardware. Until that validation lands, neither AddWallet nor Send offers a USB
 * transport for Keystone — the device is air-gapped-QR-only. The code is kept
 * (and unit-tested against SDK mocks) so wiring it back up is a one-line UI
 * change once it can be validated on a device; it must not be re-exposed before.
 *
 * @throws Error — "WebUSB not available …" when the browser lacks WebUSB.
 */
export async function connectKeystoneUSB(): Promise<HardwareSigner> {
  if (
    typeof navigator === "undefined" ||
    (navigator as Navigator & { usb?: unknown }).usb === undefined
  ) {
    throw new Error("WebUSB not available — open this in a Chromium browser to use Keystone over USB");
  }

  const { TransportWebUSB } = await import("@keystonehq/hw-transport-webusb");
  const AdaModule = await import("@keystonehq/hw-app-ada");
  const Ada = AdaModule.default;
  const {
    AddressType,
    TransactionSigningMode,
    TxOutputDestinationType,
    TxOutputFormat,
    TxRequiredSignerType,
  } = AdaModule;

  // requestPermission must run while the click's user-activation is still live.
  await TransportWebUSB.requestPermission();
  const transport = await TransportWebUSB.connect();
  // The signing app needs the wallet master fingerprint; read it once, then
  // build the app instance bound to it.
  const bootstrap = new Ada(transport);
  const { mfp } = await bootstrap.getAppConfig();
  const cardano = new Ada(transport, mfp);

  type LedgerLikeAssets = NonNullable<HardwareSignResponse["outputs"][number]["assets"]>;
  function mapTokenBundle(assets: LedgerLikeAssets) {
    const byPolicy = new Map<string, { assetNameHex: string; amount: bigint }[]>();
    for (const a of assets) {
      const tokens = byPolicy.get(a.policy_id_hex) ?? [];
      tokens.push({ assetNameHex: a.asset_name_hex, amount: BigInt(a.amount) });
      byPolicy.set(a.policy_id_hex, tokens);
    }
    return Array.from(byPolicy, ([policyIdHex, tokens]) => ({ policyIdHex, tokens }));
  }

  function mapToSignRequest(resp: HardwareSignResponse) {
    const inputs = resp.inputs.map((inp) => ({
      txHashHex: inp.tx_hash_hex,
      outputIndex: inp.output_index,
      path: inp.path ? parseBip32Path(inp.path) : null,
    }));

    const outputs = resp.outputs.map((out) => {
      const destination =
        out.payment_path && out.stake_path
          ? {
              type: TxOutputDestinationType.DEVICE_OWNED,
              params: {
                type: AddressType.BASE_PAYMENT_KEY_STAKE_KEY,
                params: {
                  spendingPath: parseBip32Path(out.payment_path),
                  stakingPath: parseBip32Path(out.stake_path),
                },
              },
            }
          : {
              type: TxOutputDestinationType.THIRD_PARTY,
              params: { addressHex: out.address_hex },
            };
      return {
        format: TxOutputFormat.ARRAY_LEGACY,
        destination,
        amount: BigInt(out.lovelace),
        tokenBundle: out.assets && out.assets.length > 0 ? mapTokenBundle(out.assets) : [],
      };
    });

    return {
      tx: {
        network: { protocolMagic: resp.protocol_magic, networkId: resp.network_id },
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

  return {
    kind: "keystone",
    capabilities: KEYSTONE_USB_CAPABILITIES,

    async getAccountXpub(account: number): Promise<string> {
      const [xpub] = await cardano.getExtendedPublicKeys({ paths: [accountPath(account)] });
      return encodeXpub(xpub.publicKeyHex, xpub.chainCodeHex);
    },

    async signTx(req: HardwareSignResponse): Promise<string> {
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      const request = mapToSignRequest(req) as any;
      const { witnesses } = await cardano.signTransaction(request);
      const resolved = await Promise.all(
        witnesses.map(async (w) => {
          if (!w.path) {
            throw new Error(
              "Keystone returned a witness without a derivation path; cannot resolve its public key",
            );
          }
          const [xpub] = await cardano.getExtendedPublicKeys({ paths: [w.path] });
          return { pubKeyHex: xpub.publicKeyHex, sigHex: w.witnessSignatureHex };
        }),
      );
      return encodeWitnessArray(resolved);
    },

    signMessage: keystoneSignMessageUnsupported,

    async close(): Promise<void> {
      await transport.close();
    },
  };
}

/**
 * Connect a Keystone with the given transport. Both transports are fully local,
 * so no consent callback is involved.
 */
export function connectKeystone(opts: KeystoneConnectOptions): Promise<HardwareSigner> {
  switch (opts.transport) {
    case "qr":
      return connectKeystoneQR(opts);
    case "usb":
      return connectKeystoneUSB();
    default: {
      const never: never = opts;
      throw new Error(`Unknown Keystone transport: ${String((never as { transport?: string }).transport)}`);
    }
  }
}
