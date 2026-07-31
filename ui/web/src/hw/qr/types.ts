/**
 * hw/qr/types.ts — Device-agnostic types for the air-gapped-QR transport.
 *
 * These describe the seam between a screen (which owns pixels + camera) and an
 * air-gapped signer (which owns UR/CBOR): the signer shows an animated QR and
 * awaits the device's scanned reply. Everything here is purely local — no method
 * contacts the network — so, unlike a cloud device, no consent gate applies.
 */

/**
 * A single Uniform Resource decoded from a scanned QR (or QR animation). `type`
 * is the UR type (e.g. "cardano-signature", "crypto-multi-accounts") and
 * `cborHex` is its raw CBOR payload as hex. Each device decodes it into its own
 * concrete registry item.
 */
export interface ScannedUR {
  type: string;
  cborHex: string;
}

/**
 * UI bridge for the air-gapped QR transport. Implemented by the screen (a modal
 * that renders the animated QR and the webcam scanner); consumed by an
 * air-gapped signer. Purely local — no method contacts the network.
 */
export interface AirGapQRBridge {
  /**
   * Display the request to the user as an animated QR. `fragments` are the UR
   * part strings the UI cycles through as QR frames. For an exchange with no
   * request to show (e.g. account-sync) this is never called.
   */
  displayRequest(fragments: string[]): void;
  /**
   * Prompt the user to scan the device's reply through the webcam and resolve
   * with the decoded UR. Rejects if the user cancels or the camera is denied.
   */
  scanResponse(): Promise<ScannedUR>;
  /** Tear down the modal + camera. Always invoked in a finally. */
  close(): void;
}
