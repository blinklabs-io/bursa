/**
 * hw/types.ts — Device-agnostic hardware-signer abstraction.
 *
 * The backend already speaks in NEUTRAL, device-agnostic terms: it emits a
 * `HardwareSignResponse` (structured tx fields, CIP-1852 paths) and accepts a
 * standard vkey-witness-array CBOR back. This interface mirrors that contract
 * on the client so the UI (AddWallet, Send) never names a specific device —
 * each signer implementation owns its own neutral→device→neutral mapping.
 */

import type { HardwareSignResponse } from "../api/types";
import type { AirGapQRBridge, ScannedUR } from "./qr/types";

/** Which hardware device a signer talks to. */
export type HardwareKind = "ledger" | "trezor" | "keystone" | "seedsigner";

/**
 * What a given device can sign today. Send-parity is the current baseline for
 * every implemented device; staking/governance/multisig/poolReg are declared
 * so the UI can gate those flows per-device as they land, without a new type.
 */
export interface HardwareCapabilities {
  send: boolean;
  staking: boolean;
  governance: boolean;
  multisig: boolean;
  poolReg: boolean;
  // signMessage is CIP-8 / CIP-30 signData message signing (COSE_Sign1 +
  // COSE_Key). It is a distinct on-device operation from tx signing, so it has
  // its own flag: a device may sign sends but not messages (or vice-versa).
  signMessage: boolean;
}

/**
 * Neutral request to sign a CIP-8 / CIP-30 message on a hardware device. Mirrors
 * the backend's HardwareSignDataRequest plus the payload the user entered: the
 * device-specific shaping (Ledger MessageData, Trezor cardanoSignMessage) is
 * internal to each signer. The address is described BY PATH (payment + stake) so
 * the device derives and recognises it as its own; `networkId`/`protocolMagic`
 * let the device render the address it signs for.
 */
export interface HardwareSignMessageRequest {
  /** The raw message bytes to sign, hex-encoded (the COSE payload). */
  messageHex: string;
  /** CIP-1852 payment-key path of the signing address ("1852'/1815'/0'/0/0"). */
  signingPath: string;
  /** CIP-1852 stake-key path of the account ("1852'/1815'/0'/2/0"). */
  stakePath: string;
  /** 1 = mainnet, 0 = testnets. */
  networkId: number;
  /** mainnet 764824073, preprod 1, preview 2. */
  protocolMagic: number;
}

/**
 * The CIP-8 / CIP-30 signData result: a hex COSE_Sign1 signature and hex
 * COSE_Key. Byte-compatible with the software wallet's SignDataResult so the UI
 * renders both identically and the backend verifier accepts either.
 */
export interface HardwareSignMessageResult {
  signature: string; // COSE_Sign1, hex
  key: string; // COSE_Key, hex
}

/**
 * A live session with a connected hardware device.
 *
 * `signTx` takes the backend's neutral request and returns the standard
 * witness-array CBOR hex the submit endpoint expects — the device-specific
 * request/response shaping is entirely internal to each implementation.
 */
export interface HardwareSigner {
  readonly kind: HardwareKind;
  readonly capabilities: HardwareCapabilities;

  /**
   * Derive the account-level extended public key (m/1852'/1815'/<account>')
   * from the device, encoded as the bech32 "root_xvk" string the backend
   * accepts (see hw/xpub.ts for the canonical encoding).
   */
  getAccountXpub(account: number): Promise<string>;

  /**
   * Sign a transaction on the device.
   * @param req - The backend's neutral HardwareSignResponse.
   * @returns CBOR-encoded raw vkey-witness array hex string.
   */
  signTx(req: HardwareSignResponse): Promise<string>;

  /**
   * Sign a CIP-8 / CIP-30 message on the device, returning the COSE_Sign1
   * signature + COSE_Key. Implementations whose {@link HardwareCapabilities}
   * report `signMessage: false` MUST reject rather than pretend to sign, so a
   * caller that skips the capability check still fails loudly.
   * @param req - The neutral message-signing request.
   */
  signMessage(req: HardwareSignMessageRequest): Promise<HardwareSignMessageResult>;

  /** Release the device connection / dispose of any external transport. */
  close(): Promise<void>;
}

/**
 * Options for a fully-local connector (Ledger via WebHID). No external
 * network is contacted, so no consent gate applies; the field is forbidden
 * so a local connector is never accidentally handed a cloud consent callback.
 */
export interface LocalConnectOptions {
  requestExternalConsent?: never;
}

/**
 * Options for an external-network connector (Trezor loads connect.trezor.io).
 *
 * `requestExternalConsent` is the CONSENT-LAW gate: it is MANDATORY here so a
 * cloud-reaching device can NEVER be connected without a consent callback.
 * The connector MUST await it and only proceed once it resolves `true`,
 * rejecting when it is absent or resolves `false`.
 */
export interface ExternalConnectOptions {
  requestExternalConsent: () => Promise<boolean>;
}

/**
 * Options passed to a device connector. A union of the two option shapes; the
 * per-kind contract is enforced by {@link ConnectOptionsByKind} at the
 * connectDevice factory boundary, not by this union on its own.
 */
export type ConnectOptions = LocalConnectOptions | ExternalConnectOptions;

// ── Keystone (air-gapped QR + USB) ───────────────────────────────────────────
//
// Keystone is fully LOCAL for both transports — QR is offline paper/camera and
// USB is a direct cable — so NO external-consent gate applies (unlike Trezor).
// The QR transport needs a UI bridge because signing is a two-way, user-driven
// exchange (show an animated QR → user scans it with the device → user scans the
// device's reply back through the webcam). The bridge below is that seam: the UI
// owns pixels + camera; hw/keystone.ts owns all UR/CBOR. Everything stays local.

/**
 * A single Uniform Resource decoded from a scanned QR. Keystone-named alias of
 * the shared {@link ScannedUR}; hw/keystone.ts decodes it into the concrete
 * Keystone registry item.
 */
export type KeystoneScannedUR = ScannedUR;

/**
 * UI bridge for the air-gapped QR transport. Keystone-named alias of the shared
 * {@link AirGapQRBridge}: implemented by the screen (the modal that renders the
 * animated QR and the webcam scanner) and consumed by the Keystone signer.
 * Purely local — no method contacts the network.
 */
export type KeystoneQRBridge = AirGapQRBridge;

/**
 * Air-gapped QR transport options. `xfp` is the device master fingerprint
 * captured during account-sync (needed so the device recognises the witness
 * paths as its own); the screen sources it from its per-wallet local store.
 */
export interface KeystoneQRConnectOptions {
  transport: "qr";
  bridge: KeystoneQRBridge;
  xfp?: string;
}

/** Direct-USB transport options (best-effort; young vendor SDK). */
export interface KeystoneUSBConnectOptions {
  transport: "usb";
}

/**
 * Options for connecting a Keystone. A discriminated union on `transport`:
 * "qr" (primary, air-gapped) or "usb" (secondary). Both are local, so — unlike
 * {@link ExternalConnectOptions} — neither carries a consent callback.
 */
export type KeystoneConnectOptions =
  | KeystoneQRConnectOptions
  | KeystoneUSBConnectOptions;

// ── SeedSigner (air-gapped QR only) ──────────────────────────────────────────
//
// SeedSigner is fully AIR-GAPPED: no cable, no radio, no network — every byte
// travels as an animated QR through the local webcam. Like Keystone's QR
// transport it needs a UI bridge (the modal that shows the animated QR and runs
// the scanner) and, being fully local, carries NO external-consent gate. Unlike
// Keystone it has no USB transport at all — QR is its only transport.

/**
 * A single Uniform Resource decoded from a scanned QR. SeedSigner-named alias of
 * the shared {@link ScannedUR}; hw/seedsigner.ts decodes it into the concrete
 * bespoke SeedSigner payload.
 */
export type SeedSignerScannedUR = ScannedUR;

/**
 * UI bridge for the SeedSigner air-gapped QR transport. SeedSigner-named alias
 * of the shared {@link AirGapQRBridge}. Purely local — no method contacts the
 * network.
 */
export type SeedSignerQRBridge = AirGapQRBridge;

/**
 * Options for connecting a SeedSigner. `bridge` drives the animated-QR + webcam
 * exchange; `xfp` is the device master fingerprint captured at account import
 * (needed so the device recognises the witness paths as its own — the screen
 * sources it from its per-wallet local store). No consent callback: SeedSigner
 * is local on its only transport.
 */
export interface SeedSignerConnectOptions {
  bridge: SeedSignerQRBridge;
  xfp?: string;
}

/**
 * Ties each {@link HardwareKind} to the connect-options it accepts, so the
 * factory can discriminate at compile time: a local device (Ledger) can NEVER
 * be handed a cloud-consent callback, and an external device (Trezor) can NEVER
 * be connected without one. Enforced via the kind-specific `connectDevice`
 * overloads in hw/index.ts. Keystone is local on both transports (QR and USB),
 * so it takes {@link KeystoneConnectOptions} — a transport choice, never a
 * cloud-consent callback. SeedSigner is air-gapped QR only, so it takes a
 * {@link SeedSignerConnectOptions} bridge, likewise never a consent callback.
 */
export interface ConnectOptionsByKind {
  ledger: LocalConnectOptions;
  trezor: ExternalConnectOptions;
  keystone: KeystoneConnectOptions;
  seedsigner: SeedSignerConnectOptions;
}
