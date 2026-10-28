import { useLayoutEffect, useRef } from "react";
import { AUTO_LOCK_CHECK_INTERVAL_MS, isIdleTimeoutElapsed } from "./idle";

// Activity events that reset the idle timer. Pointer and keyboard input cover
// mouse/touch/stylus and typing. Visibility changes are handled separately
// because returning to a long-idle tab must lock before it can count as
// activity.
const ACTIVITY_EVENTS: (keyof WindowEventMap)[] = ["pointerdown", "keydown"];
const ACTIVITY_REPORT_INTERVAL_MS = 1000;

/**
 * useIdleLock calls `onIdle` once after `timeoutMinutes` of no user activity
 * and reports qualifying input through `onActivity` so the server-owned vault
 * deadline follows the same clock (pointer and keyboard activity restart the
 * countdown; the tab regaining visibility only restarts it if the idle timeout
 * has not already elapsed). It
 * is a no-op — no listeners, no timer — when `enabled` is false or
 * `timeoutMinutes` is 0 or less ("Off"), so callers can pass the raw persisted
 * setting straight through.
 *
 * `onIdle` only ever fires once per idle period; pointer or keyboard activity
 * after it fires re-arms it for the next period.
 */
export function useIdleLock(
  timeoutMinutes: number,
  onIdle: () => void,
  enabled: boolean,
  onActivity: () => void = () => {},
): void {
  const lastActivity = useRef(Date.now());
  const fired = useRef(false);
  // Keep the latest onIdle in a ref so the effect below doesn't need to
  // re-subscribe every time the caller passes a new function identity.
  const onIdleRef = useRef(onIdle);
  onIdleRef.current = onIdle;
  const onActivityRef = useRef(onActivity);
  onActivityRef.current = onActivity;

  // A layout effect attaches the listeners in the same commit that enables the
  // lock. A passive effect runs later, and input landing on the freshly
  // rendered unlocked UI before then would be dropped without reaching the
  // server.
  useLayoutEffect(() => {
    if (!enabled || timeoutMinutes <= 0) return;

    lastActivity.current = Date.now();
    fired.current = false;
    let lastActivityReport = 0;
    let pendingActivityReport: number | null = null;

    const reportActivity = () => {
      const now = Date.now();
      const elapsed = now - lastActivityReport;
      if (elapsed >= ACTIVITY_REPORT_INTERVAL_MS) {
        if (pendingActivityReport !== null) {
          window.clearTimeout(pendingActivityReport);
          pendingActivityReport = null;
        }
        lastActivityReport = now;
        onActivityRef.current();
        return;
      }
      if (pendingActivityReport === null) {
        pendingActivityReport = window.setTimeout(() => {
          pendingActivityReport = null;
          lastActivityReport = Date.now();
          onActivityRef.current();
        }, ACTIVITY_REPORT_INTERVAL_MS - elapsed);
      }
    };

    const markActive = () => {
      lastActivity.current = Date.now();
      fired.current = false;
      reportActivity();
    };

    const fireIfIdle = (): boolean => {
      if (fired.current) return true;
      if (!isIdleTimeoutElapsed(lastActivity.current, Date.now(), timeoutMinutes)) {
        return false;
      }

      fired.current = true;
      onIdleRef.current();
      return true;
    };

    // Only returning to the tab can count as activity. Gating on visibleState
    // here (rather than reacting to every visibilitychange, hidden or visible)
    // matters: without it, merely switching away re-armed the timer at the
    // moment of leaving, so idle time accrued beforehand was discarded. On the
    // return path we first check whether the idle period already elapsed while
    // the tab was away; if so, lock immediately instead of erasing the timeout.
    const onVisibilityChange = () => {
      if (document.visibilityState !== "visible") return;
      if (!fireIfIdle()) markActive();
    };

    ACTIVITY_EVENTS.forEach((evt) => window.addEventListener(evt, markActive));
    document.addEventListener("visibilitychange", onVisibilityChange);

    const id = window.setInterval(() => {
      fireIfIdle();
    }, AUTO_LOCK_CHECK_INTERVAL_MS);

    return () => {
      ACTIVITY_EVENTS.forEach((evt) => window.removeEventListener(evt, markActive));
      document.removeEventListener("visibilitychange", onVisibilityChange);
      window.clearInterval(id);
      if (pendingActivityReport !== null) window.clearTimeout(pendingActivityReport);
    };
  }, [timeoutMinutes, enabled]);
}
