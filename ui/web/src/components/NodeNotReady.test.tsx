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

test("reports a failed status request", () => {
  vi.spyOn(hooks, "useStatus").mockReturnValue({
    data: null,
    error: new Error("status unavailable"),
    loading: false,
    refresh: vi.fn(),
  } as never);

  render(<NodeNotReady what="Your balance" />);

  expect(screen.getByRole("alert")).toHaveTextContent(/status unavailable/i);
  expect(screen.queryByText(/nothing is wrong/i)).not.toBeInTheDocument();
});

// The live phase + percent readout is the difference between "still starting"
// and a dead end, so the branch that renders it needs its own case rather than
// riding on the no-bootstrap fallback above.
test("shows the bootstrap phase and percent while a snapshot is importing", () => {
  vi.spyOn(hooks, "useStatus").mockReturnValue({
    data: {
      state: "bootstrapping",
      tip: 0,
      caughtUp: false,
      network: "preview",
      bootstrap: { phase: "immutable_copy", percent: 41.25 },
    },
    error: null,
    loading: false,
    refresh: vi.fn(),
  } as never);

  render(<NodeNotReady what="Your balance" />);

  expect(screen.getByText("Copy chain history · 41.3%")).toBeInTheDocument();
  // The raw dingo phase key must not reach the screen.
  expect(screen.queryByText(/immutable_copy/)).not.toBeInTheDocument();
  expect(screen.getByText(/nothing is lost/i)).toBeInTheDocument();
});

// The retry rides on the same terms as useAsync's own polling: a hidden tab or a
// dead network gets no requests.
test("does not retry while the tab is hidden", () => {
  vi.useFakeTimers();
  vi.spyOn(hooks, "useStatus").mockReturnValue({
    data: { state: "bootstrapping", tip: 0, caughtUp: false, network: "preview" },
    error: null,
    loading: false,
    refresh: vi.fn(),
  } as never);
  const hidden = vi.spyOn(document, "hidden", "get").mockReturnValue(true);
  const refresh = vi.fn();

  render(<NodeNotReady what="Your balance" refresh={refresh} />);
  act(() => vi.advanceTimersByTime(6000));
  expect(refresh).not.toHaveBeenCalled();

  // ...and it resumes once the tab is visible again.
  hidden.mockReturnValue(false);
  act(() => vi.advanceTimersByTime(2000));
  expect(refresh).toHaveBeenCalledTimes(1);
});

test("does not retry while the browser is offline", () => {
  vi.useFakeTimers();
  vi.spyOn(hooks, "useStatus").mockReturnValue({
    data: { state: "bootstrapping", tip: 0, caughtUp: false, network: "preview" },
    error: null,
    loading: false,
    refresh: vi.fn(),
  } as never);
  vi.spyOn(navigator, "onLine", "get").mockReturnValue(false);
  const refresh = vi.fn();

  render(<NodeNotReady what="Your balance" refresh={refresh} />);
  act(() => vi.advanceTimersByTime(6000));

  expect(refresh).not.toHaveBeenCalled();
});
