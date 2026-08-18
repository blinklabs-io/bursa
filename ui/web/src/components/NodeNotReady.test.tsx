import { act, render, screen } from "@testing-library/react";
import * as hooks from "../api/hooks";
import { NodeNotReady } from "./NodeNotReady";

afterEach(() => {
  vi.useRealTimers();
  vi.restoreAllMocks();
});

test("refreshes the failed query while the node is starting", () => {
  vi.useFakeTimers();
  vi.spyOn(hooks, "useStatus").mockReturnValue({
    data: { state: "bootstrapping", tip: 0, caughtUp: false, network: "preview" },
    error: null,
    loading: false,
    refresh: vi.fn(),
  } as never);
  const refresh = vi.fn();

  render(<NodeNotReady what="Your balance" refresh={refresh} />);

  act(() => vi.advanceTimersByTime(2000));

  expect(refresh).toHaveBeenCalledTimes(1);
  expect(screen.getByText(/waiting for the node/i)).toBeInTheDocument();
});

test("reports a supervisor error", () => {
  vi.spyOn(hooks, "useStatus").mockReturnValue({
    data: { state: "error", error: "node failed to start", tip: 0, caughtUp: false, network: "preview" },
    error: null,
    loading: false,
    refresh: vi.fn(),
  } as never);

  render(<NodeNotReady what="Your balance" />);

  expect(screen.getByRole("alert")).toHaveTextContent(/node failed to start/i);
  expect(screen.queryByText(/nothing is wrong/i)).not.toBeInTheDocument();
});
