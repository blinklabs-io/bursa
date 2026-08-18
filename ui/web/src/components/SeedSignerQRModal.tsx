import { useAirGapQRBridge } from "../hw/qr/AirGapQRModal";

/**
 * SeedSigner air-gapped QR modal bridge.
 *
 * The show-QR/scan-QR modal is the device-agnostic {@link useAirGapQRBridge}
 * (hw/qr/AirGapQRModal); this is its SeedSigner-labelled binding, so the
 * on-screen copy names the SeedSigner while the returned `{bridge, element}`
 * behaves exactly like every other air-gapped-QR device's.
 */
export function useSeedSignerQRBridge() {
  return useAirGapQRBridge("SeedSigner");
}
