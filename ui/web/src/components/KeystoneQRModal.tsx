import { useAirGapQRBridge } from "../hw/qr/AirGapQRModal";

/**
 * Keystone air-gapped QR modal bridge.
 *
 * The show-QR/scan-QR modal is now the device-agnostic {@link useAirGapQRBridge}
 * (hw/qr/AirGapQRModal); this is the Keystone-labelled binding of it, kept at its
 * original import path so the Send/AddWallet screens are unchanged. The returned
 * `{bridge, element}` and its behaviour are identical to before.
 */
export function useKeystoneQRBridge() {
  return useAirGapQRBridge("Keystone");
}
