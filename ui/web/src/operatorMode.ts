// Whether to show the stake-pool operator tooling in the nav.
//
// Running a pool is a minority activity, and Operate carried a permanent nav
// entry for everyone who does not. This is a display preference rather than
// wallet state — nothing about the wallet changes — so it lives in the browser
// alongside the other view choices, not in the vault.

const KEY = "bursa.operatorMode";

export function operatorModeEnabled(): boolean {
  try {
    return window.localStorage.getItem(KEY) === "1";
  } catch {
    // Private browsing and locked-down storage both throw. Defaulting to off
    // matches the majority case and is recoverable from Settings.
    return false;
  }
}

export function setOperatorMode(enabled: boolean): void {
  try {
    if (enabled) window.localStorage.setItem(KEY, "1");
    else window.localStorage.removeItem(KEY);
  } catch {
    // Nothing to do: the toggle simply will not persist across reloads.
  }
}
