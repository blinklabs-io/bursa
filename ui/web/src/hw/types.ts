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
 * Options passed to a device connector.
 *
 * `requestExternalConsent` is the CONSENT-LAW gate for devices that reach a
 * cloud service (Trezor loads connect.trezor.io). The connector MUST await it
 * and only proceed with the external connection when it resolves `true`.
 * Fully-local devices (Ledger via WebHID) ignore it.
 */
export interface ConnectOptions {
  requestExternalConsent?: () => Promise<boolean>;
}
