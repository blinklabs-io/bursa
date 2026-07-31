/**
 * hw/qr/xfp.ts — Per-wallet master-fingerprint (xfp) store + validator, shared
 * by air-gapped-QR devices.
 *
 * An air-gapped device signing over QR must stamp its wallet master fingerprint
 * on the sign-request so the device recognises the witness paths as its own.
 * That fingerprint is learned only during account-sync (it rides the sync QR),
 * so it is remembered here — a purely local, NON-SECRET hint keyed by wallet id,
 * exactly like the device-kind hint in deviceKind.ts. It is safe to lose: when
 * absent, the signer must steer the user to re-scan the account-sync QR rather
 * than fabricate a zero fingerprint (which would silently build a request the
 * device cannot match).
 */

// localStorage key for the wallet-id → xfp map. The value is preserved verbatim
// so previously-stored fingerprints keep resolving after this refactor.
export const XFP_STORAGE_KEY = "bursa.hw.keystoneXfp";

function readXfpMap(): Record<string, string> {
  if (typeof localStorage === "undefined") return {};
  try {
    const raw = localStorage.getItem(XFP_STORAGE_KEY);
    if (!raw) return {};
    const parsed = JSON.parse(raw) as unknown;
    if (parsed && typeof parsed === "object") return parsed as Record<string, string>;
    return {};
  } catch {
    return {};
  }
}

/** Record the master fingerprint (hex) for a hardware wallet id. */
export function setWalletXfp(walletId: string, xfp: string): void {
  if (typeof localStorage === "undefined") return;
  try {
    const map = readXfpMap();
    map[walletId] = xfp;
    localStorage.setItem(XFP_STORAGE_KEY, JSON.stringify(map));
  } catch {
    // Best-effort: a full/blocked store just means the fingerprint is not
    // remembered. The QR sign flow then treats the hint as absent and blocks
    // signing (prompting an account-sync re-scan) rather than fabricating a zero.
  }
}

/**
 * A Cardano/BIP32 master fingerprint is exactly 4 bytes → 8 hex digits. Anything
 * else in local storage is corrupt (e.g. a truncated write, a hand-edited value,
 * or a non-string smuggled in by a malformed JSON blob) and MUST NOT be forwarded
 * into a sign-request, where it would make the device fail to match its paths.
 *
 * "00000000" is deliberately VALID: a genuine all-zero fingerprint reported by a
 * real device is a legitimate (1-in-2^32) value, and this guard blocks the
 * ABSENCE of a fingerprint (undefined / corrupt storage), never a real one. A QR
 * signer only refuses to FABRICATE a zero when the hint is missing — it does not
 * reject a device-reported zero.
 */
export function isValidXfp(value: unknown): value is string {
  return typeof value === "string" && /^[0-9a-f]{8}$/i.test(value);
}

/**
 * Look up the stored master fingerprint, or `undefined` if unknown or malformed.
 * Corrupt local state (a non-string, or a non-8-hex-digit value) is treated as
 * unknown so it can never be forwarded into a QR signing request — the caller
 * must then re-scan the account-sync QR to recover it.
 */
export function getWalletXfp(walletId: string): string | undefined {
  const xfp = readXfpMap()[walletId];
  return isValidXfp(xfp) ? xfp : undefined;
}
