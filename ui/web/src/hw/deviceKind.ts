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
 * no secret (the device kind is not sensitive) and is safe to lose. When no
 * hint is stored, {@link getStoredDeviceKind} returns `undefined` so callers
 * can PROMPT for the device; only the non-interactive {@link getDeviceKind}
 * falls back to "ledger". The fallback belongs to that function alone — do NOT
 * reintroduce it into the stored-hint read, or a Trezor wallet with a lost hint
 * would silently reconnect as a Ledger (the wrong signer).
 *
 * If device-kind ever needs to survive a browser-data wipe or move between
 * machines, it should become a server-side WalletView field instead; see the
 * design doc's "human follow-up" note.
 */

import type { HardwareKind } from "./types";

// The localStorage key the device-kind hint map lives under. Exported so tests
// read/write the SAME key as this module (one source of truth).
export const STORAGE_KEY = "bursa.hw.deviceKind";

// Kinds we accept from storage. All implemented signers are listed; an
// unrecognised value falls back to the documented "ledger" default.
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
 * Look up the stored device-kind hint for a hardware wallet id, or `undefined`
 * when no recognised hint is stored — e.g. after a browser-data wipe, on
 * another browser, or for a wallet added before this feature existed.
 *
 * Callers MUST treat `undefined` as "unknown, ask the user which device backs
 * this wallet" rather than silently assuming one: a wrong assumption would try
 * to reconnect the wrong signer (e.g. open WebHID for what is really a Trezor).
 */
export function getStoredDeviceKind(walletId: string): HardwareKind | undefined {
  const stored = readMap()[walletId];
  return stored && KNOWN_KINDS.includes(stored) ? stored : undefined;
}

/**
 * Look up the device kind for a hardware wallet id, defaulting to "ledger" when
 * no recognised hint is stored. Prefer {@link getStoredDeviceKind} where the
 * caller can prompt the user; this default exists only for non-interactive
 * call sites that must pick something.
 */
export function getDeviceKind(walletId: string): HardwareKind {
  return getStoredDeviceKind(walletId) ?? "ledger";
}

// ── Keystone master fingerprint (xfp) ────────────────────────────────────────
//
// A Keystone signing over QR must stamp its wallet master fingerprint on the
// sign-request so the device recognises the witness paths as its own. That
// fingerprint is learned only during account-sync (it rides the
// crypto-multi-accounts QR), so it is remembered here — a purely local,
// non-secret hint keyed by wallet id, exactly like the device-kind hint above.

// localStorage key for the wallet-id → xfp map.
export const KEYSTONE_XFP_KEY = "bursa.hw.keystoneXfp";

function readXfpMap(): Record<string, string> {
  if (typeof localStorage === "undefined") return {};
  try {
    const raw = localStorage.getItem(KEYSTONE_XFP_KEY);
    if (!raw) return {};
    const parsed = JSON.parse(raw) as unknown;
    if (parsed && typeof parsed === "object") return parsed as Record<string, string>;
    return {};
  } catch {
    return {};
  }
}

/** Record the Keystone master fingerprint (hex) for a hardware wallet id. */
export function setKeystoneXfp(walletId: string, xfp: string): void {
  if (typeof localStorage === "undefined") return;
  try {
    const map = readXfpMap();
    map[walletId] = xfp;
    localStorage.setItem(KEYSTONE_XFP_KEY, JSON.stringify(map));
  } catch {
    // Best-effort: a full/blocked store just means the fingerprint is not
    // remembered and the QR sign flow falls back to a zero xfp.
  }
}

/** Look up the stored Keystone master fingerprint, or `undefined` if unknown. */
export function getKeystoneXfp(walletId: string): string | undefined {
  return readXfpMap()[walletId];
}
