/**
 * hw/index.ts — Hardware-signer factory.
 *
 * The UI (AddWallet, Send) asks for a device by kind and gets back a neutral
 * HardwareSigner; it never imports a device module directly. This is the one
 * place that knows which concrete connector implements each kind.
 */

import type { ConnectOptions, HardwareKind, HardwareSigner } from "./types";
import { connectLedger } from "./ledger";
import { connectTrezor } from "./trezor";

export type { HardwareKind, HardwareCapabilities, HardwareSigner, ConnectOptions } from "./types";

/**
 * Connect to a hardware device of the given kind.
 *
 * @param opts - forwarded to the connector; carries the external-connection
 *   consent gate that cloud-reaching devices (Trezor) require.
 * @throws Error for an unimplemented kind (Keystone is not supported yet).
 */
export function connectDevice(
  kind: HardwareKind,
  opts?: ConnectOptions,
): Promise<HardwareSigner> {
  switch (kind) {
    case "ledger":
      return connectLedger();
    case "trezor":
      return connectTrezor(opts);
    case "keystone":
      throw new Error("Keystone hardware wallets are not yet supported");
    default: {
      // Exhaustiveness guard: a new HardwareKind must add a case above.
      const never: never = kind;
      throw new Error(`Unknown hardware device kind: ${String(never)}`);
    }
  }
}
