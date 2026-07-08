import { useEffect, useRef } from "react";
import { AUTO_LOCK_CHECK_INTERVAL_MS, isIdleTimeoutElapsed } from "./idle";

// Activity events that reset the idle timer. Pointer and keyboard input cover
// mouse/touch/stylus and typing. Visibility changes are handled separately
// because returning to a long-idle tab must lock before it can count as
// activity.
const ACTIVITY_EVENTS: (keyof WindowEventMap)[] = ["pointerdown", "keydown"];

/**
 * useIdleLock calls `onIdle` once after `timeoutMinutes` of no user activity
 * (pointer and keyboard activity restart the countdown; the tab regaining
 * visibility only restarts it if the idle timeout has not already elapsed). It
 * is a no-op — no listeners, no timer — when `enabled` is false or
 * `timeoutMinutes` is 0 or less ("Off"), so callers can pass the raw persisted
 * setting straight through.
 *
 * `onIdle` only ever fires once per idle period; pointer or keyboard activity
 * after it fires re-arms it for the next period.
 */
export function useIdleLock(timeoutMinutes: number, onIdle: () => void, enabled: boolean): void {
  const lastActivity = useRef(Date.now());
  const fired = useRef(false);
  // Keep the latest onIdle in a ref so the effect below doesn't need to
  // re-subscribe every time the caller passes a new function identity.
  const onIdleRef = useRef(onIdle);
  onIdleRef.current = onIdle;

  useEffect(() => {
    if (!enabled || timeoutMinutes <= 0) return;

    lastActivity.current = Date.now();
    fired.current = false;

    const markActive = () => {
      lastActivity.current = Date.now();
      fired.current = false;
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
    };
  }, [timeoutMinutes, enabled]);
}
