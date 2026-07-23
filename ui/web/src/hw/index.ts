/**
 * hw/index.ts — Hardware-signer factory.
 *
 * The UI (AddWallet, Send) asks for a device by kind and gets back a neutral
 * HardwareSigner; it never imports a device module directly. This is the one
 * place that knows which concrete connector implements each kind.
 */

import type {
  ConnectOptionsByKind,
  ExternalConnectOptions,
  HardwareKind,
  HardwareSigner,
  LocalConnectOptions,
} from "./types";
import { connectLedger } from "./ledger";
import { connectTrezor } from "./trezor";

export type {
  HardwareKind,
  HardwareCapabilities,
  HardwareSigner,
  ConnectOptions,
  ConnectOptionsByKind,
  LocalConnectOptions,
  ExternalConnectOptions,
} from "./types";

/**
 * Connect to a hardware device of the given kind.
 *
 * The kind-specific overloads discriminate the options at compile time:
 *   - Ledger (local, WebHID) accepts only {@link LocalConnectOptions}, which
 *     FORBIDS a consent callback — a local device can never be handed one.
 *   - Trezor (reaches connect.trezor.io) REQUIRES {@link ExternalConnectOptions}
 *     with the consent callback.
 *
 * The missing-consent runtime policy lives in exactly one place —
 * {@link connectTrezor} — so this factory only narrows types and forwards; it
 * does not re-implement the consent gate.
 *
 * @throws Error for an unimplemented kind (Keystone is not supported yet).
 */
export function connectDevice(
  kind: "ledger",
  opts?: ConnectOptionsByKind["ledger"],
): Promise<HardwareSigner>;
export function connectDevice(
  kind: "trezor",
  opts: ConnectOptionsByKind["trezor"],
): Promise<HardwareSigner>;
export function connectDevice(
  kind: "keystone",
  opts?: ConnectOptionsByKind["keystone"],
): Promise<HardwareSigner>;
export function connectDevice(
  kind: HardwareKind,
  opts?: LocalConnectOptions | ExternalConnectOptions,
): Promise<HardwareSigner> {
  switch (kind) {
    case "ledger":
      return connectLedger();
    case "trezor":
      // The consent gate (mandatory callback, must resolve true) is enforced
      // once, inside connectTrezor; the overload above guarantees `opts` is
      // present and typed here.
      return connectTrezor(opts as ExternalConnectOptions);
    case "keystone":
      throw new Error("Keystone hardware wallets are not yet supported");
    default: {
      // Exhaustiveness guard: a new HardwareKind must add a case above.
      const never: never = kind;
      throw new Error(`Unknown hardware device kind: ${String(never)}`);
    }
  }
}

/**
 * Connect a device whose kind is only known at runtime (driven by a picker or a
 * stored hint), wiring the consent callback external-network devices require.
 *
 * This is the ONE boundary that narrows a dynamic {@link HardwareKind} to the
 * typed {@link connectDevice} overloads, so a UI caller that legitimately
 * cannot know the kind at compile time does not re-derive which kinds need
 * consent. `requestExternalConsent` is consulted ONLY for external-network
 * devices (Trezor); local devices (Ledger) ignore it.
 */
export function connectHardware(
  kind: HardwareKind,
  requestExternalConsent: () => Promise<boolean>,
): Promise<HardwareSigner> {
  switch (kind) {
    case "ledger":
      return connectDevice("ledger");
    case "trezor":
      return connectDevice("trezor", { requestExternalConsent });
    case "keystone":
      return connectDevice("keystone");
    default: {
      const never: never = kind;
      throw new Error(`Unknown hardware device kind: ${String(never)}`);
    }
  }
}
