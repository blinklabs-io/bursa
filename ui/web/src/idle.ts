// Pure decision logic for the idle auto-lock feature. Kept separate from the
// DOM-attached hook (useIdleLock.ts) so the "should we lock now?" question can
// be unit-tested without simulating browser events or timers.

// How often useIdleLock polls the clock against the last-activity timestamp.
// Small enough that the lock fires promptly after the timeout elapses; large
// enough to be a non-issue for battery/CPU.
export const AUTO_LOCK_CHECK_INTERVAL_MS = 1000;

/**
 * isIdleTimeoutElapsed reports whether at least `timeoutMinutes` have passed
 * since `lastActivityMs`, as of `nowMs`. A `timeoutMinutes` of 0 or less means
 * auto-lock is "Off" and this always returns false, regardless of how much
 * time has passed.
 */
export function isIdleTimeoutElapsed(
  lastActivityMs: number,
  nowMs: number,
  timeoutMinutes: number,
): boolean {
  if (timeoutMinutes <= 0) return false;
  return nowMs - lastActivityMs >= timeoutMinutes * 60_000;
}
