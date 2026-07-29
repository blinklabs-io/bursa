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

/** Which hardware device a signer talks to. */
export type HardwareKind = "ledger" | "trezor" | "keystone";

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
 * A single Uniform Resource decoded from a scanned QR (or QR animation). `type`
 * is the UR type (e.g. "cardano-signature", "crypto-multi-accounts") and
 * `cborHex` is its raw CBOR payload as hex. hw/keystone.ts decodes it into the
 * concrete Keystone registry item.
 */
export interface KeystoneScannedUR {
  type: string;
  cborHex: string;
}

/**
 * UI bridge for the air-gapped QR transport. Implemented by the screen (a modal
 * that renders the animated QR and the webcam scanner); consumed by the Keystone
 * signer. Purely local — no method contacts the network.
 */
export interface KeystoneQRBridge {
  /**
   * Display the request to the user as an animated QR. `fragments` are the UR
   * part strings the UI cycles through as QR frames. For account-sync (no
   * request to show) this is never called.
   */
  displayRequest(fragments: string[]): void;
  /**
   * Prompt the user to scan the device's reply through the webcam and resolve
   * with the decoded UR. Rejects if the user cancels or the camera is denied.
   */
  scanResponse(): Promise<KeystoneScannedUR>;
  /** Tear down the modal + camera. Always invoked in a finally. */
  close(): void;
}

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

/**
 * Ties each {@link HardwareKind} to the connect-options it accepts, so the
 * factory can discriminate at compile time: a local device (Ledger) can NEVER
 * be handed a cloud-consent callback, and an external device (Trezor) can NEVER
 * be connected without one. Enforced via the kind-specific `connectDevice`
 * overloads in hw/index.ts. Keystone is local on both transports (QR and USB),
 * so it takes {@link KeystoneConnectOptions} — a transport choice, never a
 * cloud-consent callback.
 */
export interface ConnectOptionsByKind {
  ledger: LocalConnectOptions;
  trezor: ExternalConnectOptions;
  keystone: KeystoneConnectOptions;
}
