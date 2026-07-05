import { renderHook, waitFor, act } from "@testing-library/react";
import { useStatus, useAsync } from "./hooks";
import * as client from "./client";

afterEach(() => {
  vi.restoreAllMocks();
  vi.useRealTimers();
  // Restore navigator.onLine and document.hidden defaults
  Object.defineProperty(navigator, "onLine", { value: true, configurable: true, writable: true });
  Object.defineProperty(document, "hidden", { value: false, configurable: true, writable: true });
});

test("useStatus loads then polls", async () => {
  vi.useFakeTimers({ shouldAdvanceTime: true });
  const spy = vi.spyOn(client, "getStatus")
    .mockResolvedValueOnce({ state: "syncing", tip: 1, caughtUp: false } as never)
    .mockResolvedValueOnce({ state: "ready", tip: 2, caughtUp: true } as never);
  const { result } = renderHook(() => useStatus());
  await waitFor(() => expect(result.current.data?.state).toBe("syncing"));
  await act(async () => { await vi.advanceTimersByTimeAsync(2000); });
  await waitFor(() => expect(result.current.data?.state).toBe("ready"));
  expect(spy).toHaveBeenCalledTimes(2);
});

// --- Online-aware polling tests ----------------------------------------------

test("poll is suspended when navigator.onLine is false — interval fires but fetch is skipped", async () => {
  Object.defineProperty(navigator, "onLine", { value: false, configurable: true, writable: true });
  vi.useFakeTimers({ shouldAdvanceTime: true });

  let calls = 0;
  const fn = vi.fn(async () => {
    calls++;
    return { state: "ready", tip: calls, caughtUp: true } as never;
  });

  const { result } = renderHook(() => useAsync(fn, { pollMs: 500 }));
  // Initial fetch fires regardless of online state
  await waitFor(() => expect(result.current.loading).toBe(false));
  const callsAfterInit = calls;

  // Advance time — poll should NOT fire extra calls while offline
  await act(async () => { await vi.advanceTimersByTimeAsync(2000); });
  expect(calls).toBe(callsAfterInit);
});

test("poll is suspended when document.hidden is true — fetch is skipped while hidden", async () => {
  Object.defineProperty(document, "hidden", { value: true, configurable: true, writable: true });
  vi.useFakeTimers({ shouldAdvanceTime: true });

  let calls = 0;
  const fn = vi.fn(async () => {
    calls++;
    return { state: "syncing", tip: calls, caughtUp: false } as never;
  });

  const { result } = renderHook(() => useAsync(fn, { pollMs: 500 }));
  await waitFor(() => expect(result.current.loading).toBe(false));
  const callsAfterInit = calls;

  await act(async () => { await vi.advanceTimersByTimeAsync(2000); });
  expect(calls).toBe(callsAfterInit);
});

// --- Visibility-change (resume) refetch tests --------------------------------
// These tests use shouldAdvanceTime: true but a very long poll interval (10 s)
// so only the visibilitychange event itself can trigger the extra refetch
// within the tight timing window we measure.

test("a visibilitychange to visible triggers an immediate refetch", async () => {
  // Start hidden; poll is long so the timer alone cannot fire the extra call.
  Object.defineProperty(document, "hidden", { value: true, configurable: true, writable: true });
  vi.useFakeTimers({ shouldAdvanceTime: true });

  let calls = 0;
  const fn = vi.fn(async () => {
    calls++;
    return { state: "ready", tip: calls, caughtUp: true } as never;
  });

  const { result } = renderHook(() => useAsync(fn, { pollMs: 10000 }));
  await waitFor(() => expect(result.current.loading).toBe(false));
  const callsAfterInit = calls; // == 1

  // Become visible and dispatch — only the visibilitychange listener can
  // produce the extra call within this 20 ms window (interval is 10 000 ms).
  Object.defineProperty(document, "hidden", { value: false, configurable: true, writable: true });
  await act(async () => {
    document.dispatchEvent(new Event("visibilitychange"));
    await vi.advanceTimersByTimeAsync(20);
  });

  expect(calls).toBeGreaterThan(callsAfterInit);
});

test("a visibilitychange to hidden does NOT trigger a refetch", async () => {
  Object.defineProperty(document, "hidden", { value: false, configurable: true, writable: true });
  vi.useFakeTimers({ shouldAdvanceTime: true });

  let calls = 0;
  const fn = vi.fn(async () => {
    calls++;
    return { state: "ready", tip: calls, caughtUp: true } as never;
  });

  const { result } = renderHook(() => useAsync(fn, { pollMs: 10000 }));
  await waitFor(() => expect(result.current.loading).toBe(false));
  const callsAfterInit = calls;

  // Go hidden — must NOT fire an extra refetch.
  Object.defineProperty(document, "hidden", { value: true, configurable: true, writable: true });
  await act(async () => {
    document.dispatchEvent(new Event("visibilitychange"));
    await vi.advanceTimersByTimeAsync(20);
  });

  expect(calls).toBe(callsAfterInit);
});

test("visibilitychange listener is removed on unmount (no refetch after cleanup)", async () => {
  Object.defineProperty(document, "hidden", { value: true, configurable: true, writable: true });
  vi.useFakeTimers({ shouldAdvanceTime: true });

  let calls = 0;
  const fn = vi.fn(async () => {
    calls++;
    return { state: "ready", tip: calls, caughtUp: true } as never;
  });

  const { result, unmount } = renderHook(() => useAsync(fn, { pollMs: 10000 }));
  await waitFor(() => expect(result.current.loading).toBe(false));

  unmount();
  const callsAtUnmount = calls;

  // Become visible after unmount — removed listener must not fire.
  Object.defineProperty(document, "hidden", { value: false, configurable: true, writable: true });
  await act(async () => {
    document.dispatchEvent(new Event("visibilitychange"));
    await vi.advanceTimersByTimeAsync(20);
  });

  expect(calls).toBe(callsAtUnmount);
});

test("an 'online' window event triggers an immediate refetch", async () => {
  Object.defineProperty(navigator, "onLine", { value: false, configurable: true, writable: true });
  vi.useFakeTimers({ shouldAdvanceTime: true });

  let calls = 0;
  const fn = vi.fn(async () => {
    calls++;
    return { state: "ready", tip: calls, caughtUp: true } as never;
  });

  const { result } = renderHook(() => useAsync(fn, { pollMs: 500 }));
  await waitFor(() => expect(result.current.loading).toBe(false));
  const callsAfterInit = calls;

  // Come back online — fire the 'online' event
  Object.defineProperty(navigator, "onLine", { value: true, configurable: true, writable: true });
  await act(async () => {
    window.dispatchEvent(new Event("online"));
    // Small tick for the async refetch to settle
    await vi.advanceTimersByTimeAsync(50);
  });

  await waitFor(() => expect(calls).toBeGreaterThan(callsAfterInit));
});
