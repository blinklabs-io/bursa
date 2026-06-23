import { render, screen } from "@testing-library/react";
import { App } from "./app";
import * as hooks from "./api/hooks";

test("renders the app shell", () => {
  vi.spyOn(hooks, "useStatus").mockReturnValue({
    data: { state: "ready", tip: 0, caughtUp: true },
    error: null,
    loading: false,
    refresh: vi.fn(),
  } as never);
  render(<App />);
  // Sidebar nav items are always present
  expect(screen.getByText("Portfolio")).toBeInTheDocument();
});
