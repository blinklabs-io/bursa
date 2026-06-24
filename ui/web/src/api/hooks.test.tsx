import { renderHook, waitFor, act } from "@testing-library/react";
import { useStatus } from "./hooks";
import * as client from "./client";

afterEach(() => {
  vi.restoreAllMocks();
  vi.useRealTimers();
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
