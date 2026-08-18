/**
 * hw/seedsigner.ts — SeedSigner air-gapped QR hardware-wallet signer.
 *
 * SeedSigner is a fully AIR-GAPPED device: it has no cable, no radio, and no
 * network — every byte in and out travels as an animated QR through the local
 * webcam. It is therefore local like Keystone (see the consent-law note in
 * hw/types.ts): NO external-consent gate applies.
 *
 * Unlike Keystone (which ships a vendor UR/CBOR registry), SeedSigner speaks a
 * BESPOKE, untagged, integer-keyed CBOR dialect carried over the standard BC-UR2
 * transport. Those payloads are built/parsed here with the SHARED, dependency-free
 * codec (hw/qr/cbor.ts encodeCbor/decodeCbor) and the SHARED transport
 * (hw/qr/ur.ts). The UR `type` string is the message discriminator:
 *
 *   account import (two-way):
 *     display  cardano-account-req  {1:request_id, 2:origin, 3:account_indices, 4:key_purpose}
 *     scan     cardano-account      {1:request_id, 2:xfp(4B), 3:[{1:idx, 2:xpub64, 3:path}], 4:device_label}
 *
 *   sign (send + staking + governance + multisig — all an ordinary Conway tx):
 *     display  cardano-tx-sig-req   {1:request_id, 2:origin, 3:sign_data, 4:inputs[{1:tx_hash,2:index,3:xfp,4:path}],
 *                                     5:change_outputs[{1:index,2:path}], 6:extra_signers[[xfp,path]], 7:network}
 *     scan     cardano-tx-sig-res   {1:request_id, 2:witness_set (tag 258 [[vkey32, sig64]])}
 *
 * Xpub/witness encoding parity with every other device is guaranteed by reusing
 * the SHARED hw/xpub.ts and hw/witness.ts encoders, so the account-import xpub and
 * the assembled witness array are byte-for-byte identical for identical key
 * material (exercised in seedsigner.test.ts).
 *
 * NOTE on CIP-8 message signing: `signMessage` rejects here (capabilities
 * reports `signMessage: false`). The bespoke SeedSigner CIP-8 payloads
 * (cardano-cip8-sig-req/res) are a follow-up; this device is treated the same
 * as Keystone in the Sign screen until then.
 */

import type { HardwareSignResponse } from "../api/types";
import type {
  AirGapQRBridge,
  ScannedUR,
} from "./qr/types";
import type {
  HardwareCapabilities,
  HardwareSignMessageResult,
  HardwareSigner,
  SeedSignerConnectOptions,
} from "./types";
import { encodeXpub } from "./xpub";
import { encodeWitnessArray } from "./witness";
import { hexToBytes } from "./hex";
import { decodeCbor, encodeCbor, type CborValue, type CborWritable } from "./qr/cbor";
import { encodeUR } from "./qr/ur";
import { isValidXfp } from "./qr/xfp";

// ── UR type discriminators (SeedSigner's bespoke dialect) ─────────────────────

export const UR_ACCOUNT_REQ = "cardano-account-req";
export const UR_ACCOUNT = "cardano-account";
export const UR_TX_SIG_REQ = "cardano-tx-sig-req";
export const UR_TX_SIG_RES = "cardano-tx-sig-res";

// CIP-1852 is the "purpose" every Cardano wallet key derives under; SeedSigner
// echoes it back in the account response so a request states the key family it
// wants.
const KEY_PURPOSE_CIP1852 = 1852;

// The origin string stamped on every request so the device can show the user
// which software asked. It is display-only, not a security control.
const DEFAULT_ORIGIN = "bursa-wallet";

// UR animated-QR fragment size (bytes of CBOR per frame). Small enough that each
// frame stays a low-density, reliably-scannable QR; larger payloads simply
// animate across more frames, which the device reassembles.
const UR_MAX_FRAGMENT_LEN = 200;

// ── Capabilities ──────────────────────────────────────────────────────────────
//
// SeedSigner signs an arbitrary Conway tx body and witnesses every wallet-owned
// key whose path we hand it (inputs + extra_signers). Certificates, withdrawals,
// governance votes, and native-multisig participation are all just ordinary
// Conway txs with the relevant key supplied via an input path or extra_signers,
// so all four are supported. poolReg (cold-key op-cert issuance) is not.
const SEEDSIGNER_CAPABILITIES: HardwareCapabilities = {
  send: true,
  staking: true,
  governance: true,
  multisig: true,
  poolReg: false,
  // signMessage (CIP-8) over the air-gapped QR transport is not wired yet.
  signMessage: false,
};

// signMessage is not yet implemented for SeedSigner: CIP-8 over the air-gapped
// QR transport needs its own UR message-signing request/response encoding.
// The method rejects (rather than being absent) so callers that skip the
// capabilities.signMessage check still fail loudly instead of silently. It
// takes no argument (a narrower signature is still assignable to the
// interface's signMessage) so the unused request parameter is not carried.
function seedSignerSignMessageUnsupported(): Promise<HardwareSignMessageResult> {
  return Promise.reject(
    new Error("Message signing is not supported on SeedSigner yet."),
  );
}

// ── small helpers ─────────────────────────────────────────────────────────────

function toHex(bytes: Uint8Array): string {
  let out = "";
  for (const b of bytes) out += b.toString(16).padStart(2, "0");
  return out;
}

/** Normalise a path to the "1852'/1815'/0'/0/0" form (drop any leading "m/"). */
function normalizePath(path: string): string {
  return path.replace(/^m\//, "").trim();
}

// A random-enough request id; the device echoes it back on the reply so a stale
// scan can be detected. crypto.randomUUID is available in every target
// (secure-context browsers); fall back to a fixed nil UUID if it is missing.
function newRequestId(): string {
  const c = (globalThis as { crypto?: { randomUUID?: () => string } }).crypto;
  return c?.randomUUID ? c.randomUUID() : "00000000-0000-0000-0000-000000000000";
}

// ── cardano-account-req (display) ─────────────────────────────────────────────

export interface AccountRequestOptions {
  /** Which CIP-1852 account indices to export (usually a single account). */
  accounts: number[];
  /** Display-only origin string. */
  origin?: string;
  /** CIP-1852 key purpose (defaults to 1852). */
  keyPurpose?: number;
}

/**
 * Build the bespoke `cardano-account-req` CBOR payload:
 *   {1:request_id, 2:origin, 3:account_indices, 4:key_purpose}
 * Untagged, integer-keyed, keys emitted in ascending order for byte stability.
 */
export function encodeAccountRequest(opts: AccountRequestOptions, requestId: string): Uint8Array {
  const map = new Map<number, CborWritable>();
  map.set(1, requestId);
  map.set(2, opts.origin ?? DEFAULT_ORIGIN);
  map.set(3, opts.accounts);
  map.set(4, opts.keyPurpose ?? KEY_PURPOSE_CIP1852);
  return encodeCbor(map);
}

// ── cardano-account (scan) ────────────────────────────────────────────────────

export interface SeedSignerAccount {
  /** Bech32 "root_xvk" account xpub, byte-identical to Ledger/Trezor/Go. */
  xpub: string;
  /** Device master fingerprint (hex) — needed to sign later over QR. */
  xfp: string;
  /** The CIP-1852 account index the key was found at. */
  account: number;
}

function decodeAccountMap(scanned: ScannedUR): Map<number, CborValue> {
  if (scanned.type !== UR_ACCOUNT) {
    throw new Error(
      `Expected a SeedSigner account QR (${UR_ACCOUNT}), got "${scanned.type}". ` +
        "On the SeedSigner, choose Export account and scan the code it shows.",
    );
  }
  const { value } = decodeCbor(hexToBytes(scanned.cborHex), 0);
  if (!(value instanceof Map)) {
    throw new Error("SeedSigner account payload is not a CBOR map");
  }
  return value;
}

function xfpFromAccountMap(map: Map<number, CborValue>): string {
  const raw = map.get(2);
  if (!(raw instanceof Uint8Array)) {
    throw new Error("SeedSigner account payload has no master fingerprint (key 2)");
  }
  const xfp = toHex(raw);
  if (!isValidXfp(xfp)) {
    throw new Error(`SeedSigner reported a malformed master fingerprint (${xfp})`);
  }
  return xfp;
}

/**
 * Read ONLY the master fingerprint (xfp) from a scanned `cardano-account` UR.
 * Account-independent — used by the Send recovery flow to re-learn the xfp of an
 * already-added wallet whose local hint was lost, without re-deriving its xpub.
 */
export function parseAccountXfp(scanned: ScannedUR): string {
  return xfpFromAccountMap(decodeAccountMap(scanned));
}

/**
 * Parse a scanned `cardano-account` UR into the CIP-1852 account xpub + xfp for
 * the requested account. The device exports one or more account records
 * ({1:idx, 2:xpub64, 3:path}); we pick the one matching `account`, split its
 * 64-byte xpub (pubkey || chaincode) and re-encode it through the shared
 * hw/xpub.ts helper so it matches every other device byte-for-byte.
 */
export function parseAccountResponse(scanned: ScannedUR, account: number): SeedSignerAccount {
  const map = decodeAccountMap(scanned);
  const xfp = xfpFromAccountMap(map);

  const records = map.get(3);
  if (!Array.isArray(records)) {
    throw new Error("SeedSigner account payload has no account records (key 3)");
  }
  for (const rec of records) {
    if (!(rec instanceof Map)) continue;
    if (rec.get(1) !== account) continue;
    const xpub64 = rec.get(2);
    if (!(xpub64 instanceof Uint8Array) || xpub64.length !== 64) {
      throw new Error(
        `SeedSigner account ${account} record has a malformed xpub (expected 64 bytes)`,
      );
    }
    const pubKey = xpub64.slice(0, 32);
    const chainCode = xpub64.slice(32, 64);
    return { xpub: encodeXpub(toHex(pubKey), toHex(chainCode)), xfp, account };
  }
  throw new Error(
    `This SeedSigner account QR does not contain account ${account}. ` +
      "Re-export the account on the device and scan again.",
  );
}

// ── cardano-tx-sig-req (display) ──────────────────────────────────────────────

export interface TxSigRequestOptions {
  /** Device master fingerprint (hex, 8 chars) stamped on every signer. */
  xfp: string;
  /** Echoed request id so a stale reply scan can be detected. */
  requestId: string;
  /** Display-only origin string. */
  origin?: string;
}

/**
 * Aggregate every wallet-owned key that must witness the tx but is NOT already
 * covered by an input path into `extra_signers` — each an [xfp(4B), path] tuple.
 *
 * PR-A's neutral request carries these as separate typed lists (certificate,
 * withdrawal, vote, and explicit extra signers); a Conway staking / governance /
 * multisig tx is signed by the device the same way — supply the key path and it
 * witnesses. They are all THIS wallet's keys, so they carry the device xfp
 * (an HWExtraSigner may carry its own, which we honour when present).
 */
export function buildExtraSigners(req: HardwareSignResponse, xfp: string): [Uint8Array, string][] {
  const out: [Uint8Array, string][] = [];
  const push = (path: string | undefined, signerXfp?: string) => {
    if (!path) return;
    out.push([hexToBytes(signerXfp ?? xfp), normalizePath(path)]);
  };
  for (const s of req.certificate_signers ?? []) push(s.path);
  for (const s of req.withdrawal_signers ?? []) push(s.path);
  for (const s of req.vote_signers ?? []) push(s.path);
  for (const s of req.extra_signers ?? []) push(s.path, s.xfp);
  return out;
}

/**
 * Build the bespoke `cardano-tx-sig-req` CBOR payload:
 *   {1:request_id, 2:origin, 3:sign_data, 4:inputs, 5:change_outputs,
 *    6:extra_signers, 7:network}
 *
 *   - sign_data     = the unsigned Conway tx bytes the device signs;
 *   - inputs        = one map per input: {1:tx_hash, 2:index, 3:xfp, 4:path}.
 *                     A wallet-owned input carries its xfp + derivation path; a
 *                     multisig SCRIPT-LOCKED input carries no path (keys 3/4 are
 *                     omitted) so the device knows not to witness it with a key.
 *   - change_outputs= {1:index, 2:path} so the device verifies change returns home;
 *   - extra_signers = the aggregated cert/withdrawal/vote/multisig key paths;
 *   - network       = the network id (0 testnet, 1 mainnet).
 *
 * All seven keys are always emitted, in ascending order, for byte stability.
 */
export function encodeTxSigRequest(req: HardwareSignResponse, opts: TxSigRequestOptions): Uint8Array {
  const xfpBytes = hexToBytes(opts.xfp);

  const inputs: CborWritable[] = req.inputs.map((inp) => {
    const m = new Map<number, CborWritable>();
    m.set(1, hexToBytes(inp.tx_hash_hex));
    m.set(2, inp.output_index);
    // A script-locked (multisig) input has no derivation path; omit the key +
    // xfp so the device does not attempt a key witness for it.
    if (inp.path) {
      m.set(3, xfpBytes);
      m.set(4, normalizePath(inp.path));
    }
    return m;
  });

  const changeOutputs: CborWritable[] = (req.change_outputs ?? []).map((c) => {
    const m = new Map<number, CborWritable>();
    m.set(1, c.index);
    m.set(2, normalizePath(c.path));
    return m;
  });

  const extraSigners: CborWritable[] = buildExtraSigners(req, opts.xfp).map(
    ([xfpB, path]) => [xfpB, path] as CborWritable[],
  );

  const map = new Map<number, CborWritable>();
  map.set(1, opts.requestId);
  map.set(2, opts.origin ?? DEFAULT_ORIGIN);
  map.set(3, hexToBytes(req.unsigned_tx_cbor));
  map.set(4, inputs);
  map.set(5, changeOutputs);
  map.set(6, extraSigners);
  map.set(7, req.network_id);
  return encodeCbor(map);
}

// ── cardano-tx-sig-res (scan) ─────────────────────────────────────────────────

/**
 * Extract {pubKeyHex, sigHex} pairs from a decoded witness-set value. Accepts
 * either the Conway set-tagged array [[vkey, sig], …] (the shared decoder unwraps
 * tag 258) or, defensively, a witness-set map whose key 0 is that array. Each
 * vkey witness is [pubkey_bytes, sig_bytes]; an extended (pubkey||chaincode) key
 * is trimmed to the leading 32-byte Ed25519 public key for parity with the other
 * devices, and wrong-length fields are rejected rather than emitted.
 */
function witnessPairsFromValue(value: CborValue): { pubKeyHex: string; sigHex: string }[] {
  let vkeyWitnesses: CborValue;
  if (value instanceof Map) {
    const w = value.get(0);
    if (!w) throw new Error("SeedSigner witness set has no vkey witnesses (map key 0 absent)");
    vkeyWitnesses = w;
  } else if (Array.isArray(value)) {
    vkeyWitnesses = value;
  } else {
    throw new Error("SeedSigner witness set is neither a map nor an array");
  }
  if (!Array.isArray(vkeyWitnesses)) {
    throw new Error("SeedSigner vkey-witness field is not an array");
  }
  return vkeyWitnesses.map((w) => {
    if (!Array.isArray(w) || w.length < 2) {
      throw new Error("SeedSigner vkey witness is not a [pubkey, sig] pair");
    }
    const [pub, sig] = w;
    if (!(pub instanceof Uint8Array) || !(sig instanceof Uint8Array)) {
      throw new Error("SeedSigner vkey witness fields are not byte strings");
    }
    const pubKey = pub.length > 32 ? pub.slice(0, 32) : pub;
    if (pubKey.length !== 32) {
      throw new Error(`SeedSigner vkey witness public key is ${pubKey.length} bytes, expected 32`);
    }
    if (sig.length !== 64) {
      throw new Error(`SeedSigner vkey witness signature is ${sig.length} bytes, expected 64`);
    }
    return { pubKeyHex: toHex(pubKey), sigHex: toHex(sig) };
  });
}

/**
 * Parse a scanned `cardano-tx-sig-res` UR into the standard vkey-witness-array
 * CBOR hex the backend's submit endpoint expects — byte-identical to every other
 * device's output (via the shared hw/witness.ts encoder).
 */
export function parseTxSigResponse(scanned: ScannedUR): string {
  if (scanned.type !== UR_TX_SIG_RES) {
    throw new Error(
      `Expected a SeedSigner signature QR (${UR_TX_SIG_RES}), got "${scanned.type}".`,
    );
  }
  const { value } = decodeCbor(hexToBytes(scanned.cborHex), 0);
  if (!(value instanceof Map)) {
    throw new Error("SeedSigner signature payload is not a CBOR map");
  }
  const witnessSet = value.get(2);
  if (witnessSet === undefined) {
    throw new Error("SeedSigner signature payload has no witness set (key 2)");
  }
  return encodeWitnessArray(witnessPairsFromValue(witnessSet));
}

// ── Account import (display request → scan response) ──────────────────────────

async function displayAccountRequest(bridge: AirGapQRBridge, account: number): Promise<void> {
  const cbor = encodeAccountRequest({ accounts: [account] }, newRequestId());
  const fragments = await encodeUR(UR_ACCOUNT_REQ, cbor, UR_MAX_FRAGMENT_LEN);
  bridge.displayRequest(fragments);
}

/**
 * Drive the two-way account import: show the `cardano-account-req` QR, scan the
 * device's `cardano-account` reply, and return the account xpub + master
 * fingerprint. Used by AddWallet (which needs both the xpub to store and the xfp
 * to remember for later QR signing).
 */
export async function importSeedSignerAccount(
  bridge: AirGapQRBridge,
  account: number,
): Promise<SeedSignerAccount> {
  await displayAccountRequest(bridge, account);
  try {
    const scanned = await bridge.scanResponse();
    return parseAccountResponse(scanned, account);
  } finally {
    bridge.close();
  }
}

/**
 * Recover ONLY the master fingerprint by re-running the account exchange. The
 * fingerprint is account-independent, so any account request suffices; used by
 * Send's recovery flow to re-learn a lost xfp without re-deriving the xpub.
 */
export async function recoverSeedSignerXfp(bridge: AirGapQRBridge, account = 0): Promise<string> {
  await displayAccountRequest(bridge, account);
  try {
    const scanned = await bridge.scanResponse();
    return parseAccountXfp(scanned);
  } finally {
    bridge.close();
  }
}

// ── Public API ────────────────────────────────────────────────────────────────

/**
 * Connect a SeedSigner over its air-gapped QR transport. Fully offline: the only
 * capability touched is the local webcam (through the UI bridge). No consent
 * gate — nothing leaves the node.
 */
export async function connectSeedSigner(
  opts: SeedSignerConnectOptions,
): Promise<HardwareSigner> {
  const { bridge } = opts;
  if (!bridge) {
    throw new Error(
      "SeedSigner requires a UI bridge (animated-QR display + webcam scanner).",
    );
  }

  return {
    kind: "seedsigner",
    capabilities: SEEDSIGNER_CAPABILITIES,

    async getAccountXpub(account: number): Promise<string> {
      const acct = await importSeedSignerAccount(bridge, account);
      return acct.xpub;
    },

    async signTx(req: HardwareSignResponse): Promise<string> {
      // The device master fingerprint is mandatory: it is how the SeedSigner
      // recognises the witness paths as its own. It is learned only at account
      // import and remembered as a local hint, so it CAN go missing (e.g. a
      // browser-data wipe). Never FABRICATE a zero fingerprint — a synthesized
      // all-zero xfp would silently build a request the device cannot match, so
      // signing would appear to run but fail on-device. Block instead and steer
      // the user to re-import the account (which yields the fingerprint again).
      // A genuine device-reported all-zero xfp is a valid (1-in-2^32) value and
      // is intentionally accepted — this blocks only the ABSENCE of one.
      const xfp = opts.xfp;
      if (!isValidXfp(xfp)) {
        throw new Error(
          "This SeedSigner wallet's device fingerprint is missing. Re-import the account " +
            "(Export account on the device and scan its QR) to recover it, then try again.",
        );
      }

      const cbor = encodeTxSigRequest(req, { xfp, requestId: newRequestId() });
      const fragments = await encodeUR(UR_TX_SIG_REQ, cbor, UR_MAX_FRAGMENT_LEN);
      bridge.displayRequest(fragments);
      try {
        const scanned = await bridge.scanResponse();
        return parseTxSigResponse(scanned);
      } finally {
        bridge.close();
      }
    },

    signMessage: seedSignerSignMessageUnsupported,

    async close(): Promise<void> {
      // No persistent transport for QR; make sure any open modal/camera is torn
      // down (idempotent — bridge.close guards its own state).
      bridge.close();
    },
  };
}
