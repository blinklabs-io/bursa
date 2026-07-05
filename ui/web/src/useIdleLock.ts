import { useEffect, useRef } from "react";
import { AUTO_LOCK_CHECK_INTERVAL_MS, isIdleTimeoutElapsed } from "./idle";

// Activity events that reset the idle timer. Pointer and keyboard input cover
// mouse/touch/stylus and typing; visibilitychange additionally resets it on
// tab/window focus changes (switching back to this tab counts as the user
// having returned).
const ACTIVITY_EVENTS: (keyof WindowEventMap)[] = ["pointerdown", "keydown"];

/**
 * useIdleLock calls `onIdle` once after `timeoutMinutes` of no user activity
 * (pointer, keyboard, or the tab regaining visibility all count as activity
 * and restart the countdown). It is a no-op — no listeners, no timer — when
 * `enabled` is false or `timeoutMinutes` is 0 or less ("Off"), so callers can
 * pass the raw persisted setting straight through.
 *
 * `onIdle` only ever fires once per idle period; activity after it fires
 * re-arms it for the next period.
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

    // Only returning to the tab counts as activity. Gating on visibleState
    // here (rather than reacting to every visibilitychange, hidden or
    // visible) matters: without it, merely switching away re-armed the timer
    // at the moment of leaving, so idle time accrued before the switch was
    // discarded and a user who left the tab could never be auto-locked while
    // away — the opposite of what a security timeout is for.
    const onVisibilityChange = () => {
      if (document.visibilityState === "visible") markActive();
    };

    ACTIVITY_EVENTS.forEach((evt) => window.addEventListener(evt, markActive));
    document.addEventListener("visibilitychange", onVisibilityChange);

    const id = window.setInterval(() => {
      if (fired.current) return;
      if (isIdleTimeoutElapsed(lastActivity.current, Date.now(), timeoutMinutes)) {
        fired.current = true;
        onIdleRef.current();
      }
    }, AUTO_LOCK_CHECK_INTERVAL_MS);

    return () => {
      ACTIVITY_EVENTS.forEach((evt) => window.removeEventListener(evt, markActive));
      document.removeEventListener("visibilitychange", onVisibilityChange);
      window.clearInterval(id);
    };
  }, [timeoutMinutes, enabled]);
}
