import { renderHook, act } from "@testing-library/react";
import { useIdleLock } from "./useIdleLock";

function setVisibilityState(value: "hidden" | "visible"): void {
  Object.defineProperty(document, "visibilityState", {
    value,
    configurable: true,
  });
}

afterEach(() => {
  vi.useRealTimers();
  setVisibilityState("visible");
});

test("calls onIdle after the timeout elapses with no activity", () => {
  vi.useFakeTimers();
  const onIdle = vi.fn();
  renderHook(() => useIdleLock(1, onIdle, true)); // 1 minute
  act(() => {
    vi.advanceTimersByTime(60_000);
  });
  expect(onIdle).toHaveBeenCalledTimes(1);
});

test("pointer activity resets the timer", () => {
  vi.useFakeTimers();
  const onIdle = vi.fn();
  renderHook(() => useIdleLock(1, onIdle, true));
  act(() => {
    vi.advanceTimersByTime(50_000);
  });
  act(() => {
    window.dispatchEvent(new Event("pointerdown"));
  });
  // 50s more since the reset (100s total) must not fire — only 50s has
  // elapsed since the last activity.
  act(() => {
    vi.advanceTimersByTime(50_000);
  });
  expect(onIdle).not.toHaveBeenCalled();
  act(() => {
    vi.advanceTimersByTime(10_000); // now 60s since the reset
  });
  expect(onIdle).toHaveBeenCalledTimes(1);
});

test("keyboard activity resets the timer", () => {
  vi.useFakeTimers();
  const onIdle = vi.fn();
  renderHook(() => useIdleLock(1, onIdle, true));
  act(() => {
    vi.advanceTimersByTime(50_000);
  });
  act(() => {
    window.dispatchEvent(new Event("keydown"));
  });
  act(() => {
    vi.advanceTimersByTime(50_000);
  });
  expect(onIdle).not.toHaveBeenCalled();
});

test("visibilitychange resets the timer", () => {
  vi.useFakeTimers();
  const onIdle = vi.fn();
  renderHook(() => useIdleLock(1, onIdle, true));
  act(() => {
    vi.advanceTimersByTime(50_000);
  });
  act(() => {
    document.dispatchEvent(new Event("visibilitychange"));
  });
  act(() => {
    vi.advanceTimersByTime(50_000);
  });
  expect(onIdle).not.toHaveBeenCalled();
});

test("visibilitychange to visible fires immediately when already idle", () => {
  vi.useFakeTimers();
  vi.setSystemTime(0);
  const onIdle = vi.fn();
  renderHook(() => useIdleLock(1, onIdle, true));
  act(() => {
    setVisibilityState("hidden");
    document.dispatchEvent(new Event("visibilitychange"));
  });
  act(() => {
    vi.setSystemTime(60_000);
    setVisibilityState("visible");
    document.dispatchEvent(new Event("visibilitychange"));
  });
  expect(onIdle).toHaveBeenCalledTimes(1);
});

// Regression test: visibilitychange used to reset the idle clock on EVERY
// transition, including the tab becoming hidden. That let leaving the tab
// erase idle time accrued beforehand instead of counting toward the lock,
// so a user who walked away could never be auto-locked while gone — the
// opposite of the intended behaviour. Only a transition back to "visible"
// should count as activity.
test("visibilitychange while the tab becomes hidden does NOT reset the timer", () => {
  vi.useFakeTimers();
  const onIdle = vi.fn();
  setVisibilityState("hidden");
  renderHook(() => useIdleLock(1, onIdle, true)); // 1 minute
  act(() => {
    vi.advanceTimersByTime(50_000);
  });
  act(() => {
    document.dispatchEvent(new Event("visibilitychange"));
  });
  act(() => {
    // 100s total: had the "hidden" visibilitychange reset the clock (the
    // bug), only 50s would have elapsed since the reset and this would not
    // fire yet.
    vi.advanceTimersByTime(50_000);
  });
  expect(onIdle).toHaveBeenCalledTimes(1);
});

test("re-arms with the new timeout when timeoutMinutes changes", () => {
  vi.useFakeTimers();
  const onIdle = vi.fn();
  const { rerender } = renderHook(
    ({ timeoutMinutes }) => useIdleLock(timeoutMinutes, onIdle, true),
    { initialProps: { timeoutMinutes: 1 } },
  );
  act(() => {
    vi.advanceTimersByTime(30_000);
  });
  rerender({ timeoutMinutes: 2 });
  act(() => {
    vi.advanceTimersByTime(60_000);
  });
  expect(onIdle).not.toHaveBeenCalled();
  act(() => {
    vi.advanceTimersByTime(60_000);
  });
  expect(onIdle).toHaveBeenCalledTimes(1);
});

test("Off (0 minutes) never fires no matter how long idle", () => {
  vi.useFakeTimers();
  const onIdle = vi.fn();
  renderHook(() => useIdleLock(0, onIdle, true));
  act(() => {
    vi.advanceTimersByTime(10 * 60_000);
  });
  expect(onIdle).not.toHaveBeenCalled();
});

test("disabled (enabled=false) never fires even past the timeout", () => {
  vi.useFakeTimers();
  const onIdle = vi.fn();
  renderHook(() => useIdleLock(1, onIdle, false));
  act(() => {
    vi.advanceTimersByTime(2 * 60_000);
  });
  expect(onIdle).not.toHaveBeenCalled();
});

test("fires only once even if the interval keeps running", () => {
  vi.useFakeTimers();
  const onIdle = vi.fn();
  renderHook(() => useIdleLock(1, onIdle, true));
  act(() => {
    vi.advanceTimersByTime(5 * 60_000); // well past the 1-minute timeout
  });
  expect(onIdle).toHaveBeenCalledTimes(1);
});

test("unmounting clears listeners and timer (no calls after unmount)", () => {
  vi.useFakeTimers();
  const onIdle = vi.fn();
  const { unmount } = renderHook(() => useIdleLock(1, onIdle, true));
  unmount();
  act(() => {
    vi.advanceTimersByTime(5 * 60_000);
  });
  expect(onIdle).not.toHaveBeenCalled();
});
