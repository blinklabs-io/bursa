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
  HardwareSigner,
  KeystoneConnectOptions,
  KeystoneQRConnectOptions,
  KeystoneScannedUR,
} from "./types";
import { encodeXpub } from "./xpub";
import { encodeWitnessArray } from "./witness";
import { isValidKeystoneXfp } from "./deviceKind";

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
};

// USB rides a young, unverified vendor SDK. We do not claim more than the
// send-parity baseline every implemented device already meets.
const KEYSTONE_USB_CAPABILITIES: HardwareCapabilities = {
  send: true,
  staking: false,
  governance: false,
  multisig: false,
  poolReg: false,
};

// UR animated-QR fragment size (bytes of CBOR per frame). Small enough that each
// frame stays a low-density, reliably-scannable QR; larger txs simply animate
// across more frames, which the receiver reassembles.
const UR_MAX_FRAGMENT_LEN = 200;

// ── buffer polyfill (lazy) ───────────────────────────────────────────────────

/**
 * The @keystonehq CBOR libraries read a global `Buffer`, which browsers do not
 * provide. We install one lazily — only when a Keystone flow actually runs — so
 * the `buffer` shim rides the code-split Keystone chunk and never bloats the
 * initial bundle. Exported so the QR scanner component (which decodes URs with
 * @ngraveio/bc-ur) can share the exact same guarantee.
 */
export async function ensureBuffer(): Promise<void> {
  const g = globalThis as unknown as { Buffer?: unknown };
  if (typeof g.Buffer === "undefined") {
    const mod = await import("buffer");
    g.Buffer = mod.Buffer;
  }
}

// ── Minimal CBOR reader (witness-set extraction only) ────────────────────────
//
// Keystone's `cardano-signature` UR carries a serialized TransactionWitnessSet,
// but the backend's submit endpoint wants the RAW vkey-witness array
// ([[pubkey, sig], …]) that hw/witness.ts produces. We therefore decode just
// enough CBOR to pull the vkey witnesses (map key 0) out of the witness set and
// re-encode them through the shared encoder, so Keystone's witness output is
// byte-identical to Ledger's and Trezor's.

type CborValue = number | Uint8Array | string | CborValue[] | Map<number, CborValue>;

/** Decode one CBOR data item at `offset`; returns the value and the next offset. */
function decodeCbor(buf: Uint8Array, offset: number): { value: CborValue; next: number } {
  const first = buf[offset];
  const major = first >> 5;
  const info = first & 0x1f;
  let len = info;
  let pos = offset + 1;
  if (info === 24) {
    len = buf[pos];
    pos += 1;
  } else if (info === 25) {
    len = (buf[pos] << 8) | buf[pos + 1];
    pos += 2;
  } else if (info === 26) {
    len = (buf[pos] * 0x1000000) + (buf[pos + 1] << 16) + (buf[pos + 2] << 8) + buf[pos + 3];
    pos += 4;
  } else if (info === 27) {
    // 64-bit length: witness sets never approach 2^53, so a Number is safe here.
    len = 0;
    for (let i = 0; i < 8; i++) len = len * 256 + buf[pos + i];
    pos += 8;
  } else if (info > 27) {
    throw new Error(`CBOR: unsupported additional-info ${info}`);
  }

  switch (major) {
    case 0: // unsigned int
      return { value: len, next: pos };
    case 2: { // byte string
      const value = buf.slice(pos, pos + len);
      return { value, next: pos + len };
    }
    case 3: { // text string
      const value = new TextDecoder().decode(buf.slice(pos, pos + len));
      return { value, next: pos + len };
    }
    case 4: { // array
      const arr: CborValue[] = [];
      let p = pos;
      for (let i = 0; i < len; i++) {
        const r = decodeCbor(buf, p);
        arr.push(r.value);
        p = r.next;
      }
      return { value: arr, next: p };
    }
    case 5: { // map
      const map = new Map<number, CborValue>();
      let p = pos;
      for (let i = 0; i < len; i++) {
        const k = decodeCbor(buf, p);
        const v = decodeCbor(buf, k.next);
        map.set(k.value as number, v.value);
        p = v.next;
      }
      return { value: map, next: p };
    }
    case 6: { // tag — unwrap (e.g. the Conway set tag 258 around the witness array)
      const r = decodeCbor(buf, pos);
      return { value: r.value, next: r.next };
    }
    default:
      throw new Error(`CBOR: unsupported major type ${major}`);
  }
}

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

// A random-enough request id; the device echoes it back on the signature so a
// stale scan can be detected. crypto.randomUUID is available in every target
// (secure-context browsers); fall back to a fixed nil UUID if it is missing.
function newRequestId(): string {
  const c = (globalThis as { crypto?: { randomUUID?: () => string } }).crypto;
  return c?.randomUUID ? c.randomUUID() : "00000000-0000-0000-0000-000000000000";
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
      // a browser-data wipe). Never fall back to a zero fingerprint — that would
      // silently produce a request the device cannot match, so signing would
      // appear to run but fail on-device. Block instead and steer the user to
      // re-scan the account-sync QR (which yields the fingerprint again).
      const xfp = opts.xfp;
      if (!isValidKeystoneXfp(xfp)) {
        throw new Error(
          "This Keystone wallet's device fingerprint is missing. Re-scan the account-sync QR " +
            "(open the Cardano account on the device and choose Sync / Connect Software Wallet) to recover it, then try again.",
        );
      }
      // Map the neutral request → a Keystone CardanoSignRequest:
      //   signData    = the unsigned tx body the device signs;
      //   utxos       = the wallet-owned inputs (path → which key witnesses);
      //   extraSigners= none (send + simple witnessing only; structured
      //                 multisig/cert signers are gated off by capabilities).
      const signData = B.from(req.unsigned_tx_cbor, "hex") as unknown as Buffer;
      const utxos = req.inputs
        .filter((inp) => inp.path)
        .map((inp) => ({
          transactionHash: inp.tx_hash_hex,
          index: inp.output_index,
          // Per-input amount/address are not carried by the neutral request;
          // they are display-only for the device (the signature is over
          // signData), so empty/zero placeholders are used. See the human
          // follow-up note in keystone.test.ts / the PR body.
          amount: "0",
          xfp,
          hdPath: normalizePath(inp.path as string),
          address: "",
        }));

      const signRequest = CardanoSignRequest.constructCardanoSignRequest(
        signData,
        utxos,
        [],
        newRequestId(),
        "bursa-wallet",
      );

      // Show the animated request QR, then wait for the user to scan the reply.
      const fragments = signRequest.toUREncoder(UR_MAX_FRAGMENT_LEN).encodeWhole();
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
        const witnessSet = new Uint8Array(signature.getWitnessSet());
        return encodeWitnessArray(witnessSetToPairs(witnessSet));
      } finally {
        bridge.close();
      }
    },

    async close(): Promise<void> {
      // No persistent transport for QR; make sure any open modal/camera is torn
      // down (idempotent — bridge.close guards its own state).
      bridge.close();
    },
  };
}

/**
 * Connect a Keystone over USB (WebUSB). Best-effort: the vendor SDK is young and
 * firmware coverage is unverified, so this is offered as a secondary transport
 * and any device/SDK error is surfaced to the caller rather than masked.
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
