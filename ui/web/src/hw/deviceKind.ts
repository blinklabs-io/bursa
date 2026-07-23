/**
 * hw/deviceKind.ts — Client-only record of which hardware device backs each
 * hardware wallet.
 *
 * The backend's WalletView is device-agnostic (it stores only the account
 * xpub, which is identical whatever device produced it), so it does NOT tell
 * us whether a hardware wallet is a Ledger or a Trezor. Send needs that to
 * reconnect the right device for on-device signing.
 *
 * This is a purely local hint, keyed by wallet id in localStorage. It carries
 * no secret (the device kind is not sensitive) and is safe to lose: any
 * hardware wallet with no stored hint — including every one added before this
 * feature existed — defaults to "ledger" for backward compatibility.
 *
 * If device-kind ever needs to survive a browser-data wipe or move between
 * machines, it should become a server-side WalletView field instead; see the
 * design doc's "human follow-up" note.
 */

import type { HardwareKind } from "./types";

const STORAGE_KEY = "bursa.hw.deviceKind";

// Kinds we persist. Keystone is intentionally omitted until it is supported.
const KNOWN_KINDS: readonly HardwareKind[] = ["ledger", "trezor", "keystone"];

type DeviceKindMap = Record<string, HardwareKind>;

function readMap(): DeviceKindMap {
  if (typeof localStorage === "undefined") return {};
  try {
    const raw = localStorage.getItem(STORAGE_KEY);
    if (!raw) return {};
    const parsed = JSON.parse(raw) as unknown;
    if (parsed && typeof parsed === "object") {
      return parsed as DeviceKindMap;
    }
    return {};
  } catch {
    // Corrupt/unavailable storage must never break the wallet — fall back to
    // the empty map (every wallet then defaults to "ledger").
    return {};
  }
}

function writeMap(map: DeviceKindMap): void {
  if (typeof localStorage === "undefined") return;
  try {
    localStorage.setItem(STORAGE_KEY, JSON.stringify(map));
  } catch {
    // Best-effort: a full/blocked localStorage just means the hint is not
    // remembered; the wallet still works (defaults to "ledger" on read).
  }
}

/**
 * Record the device kind for a hardware wallet id. Call this right after a
 * hardware wallet is added, before it is used for signing.
 */
export function setDeviceKind(walletId: string, kind: HardwareKind): void {
  const map = readMap();
  map[walletId] = kind;
  writeMap(map);
}

/**
 * Look up the device kind for a hardware wallet id. Defaults to "ledger" when
 * no hint is stored (pre-existing hardware wallets predate this feature) or
 * when the stored value is not a kind we recognise.
 */
export function getDeviceKind(walletId: string): HardwareKind {
  const stored = readMap()[walletId];
  return stored && KNOWN_KINDS.includes(stored) ? stored : "ledger";
}
