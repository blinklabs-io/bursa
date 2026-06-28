import { render, screen, fireEvent } from "@testing-library/react";
import { Button } from "./Button";
import { StatusPill } from "./StatusPill";
import { CopyButton } from "./CopyButton";
import { SyncBanner } from "./SyncBanner";

const originalClipboard = navigator.clipboard;
afterEach(() => {
  // Restore the global clipboard the CopyButton test stubs, to avoid leakage.
  Object.assign(navigator, { clipboard: originalClipboard });
});

test("Button fires onClick", () => {
  let clicked = false;
  render(<Button onClick={() => (clicked = true)}>Go</Button>);
  fireEvent.click(screen.getByText("Go"));
  expect(clicked).toBe(true);
});

test("StatusPill shows its tone + label", () => {
  render(<StatusPill tone="ok">ready</StatusPill>);
  expect(screen.getByText("ready")).toBeInTheDocument();
});

test("CopyButton copies its value and shows feedback on success", async () => {
  const writeText = vi.fn().mockResolvedValue(undefined);
  Object.assign(navigator, { clipboard: { writeText } });
  render(<CopyButton value="addr_test1abc" />);
  fireEvent.click(screen.getByRole("button"));
  expect(writeText).toHaveBeenCalledWith("addr_test1abc");
  // "Copied" appears only after the async write resolves.
  expect(await screen.findByText("Copied")).toBeInTheDocument();
});

test("SyncBanner shows error detail ahead of retained bootstrap diagnostics", () => {
  render(
    <SyncBanner
      status={{
        state: "error",
        tip: 0,
        caughtUp: false,
        error: "mithril bootstrap: download failed",
        bootstrap: { phase: "bootstrap", percent: 40 },
      }}
    />,
  );
  expect(screen.getByText("error")).toBeInTheDocument();
  expect(screen.getByText("mithril bootstrap: download failed")).toBeInTheDocument();
  expect(screen.queryByText("bootstrap 40.0%")).not.toBeInTheDocument();
});

test("SyncBanner does NOT show stale error detail when state is not error", () => {
  // A node that recovered from an error to syncing should not surface the
  // stale error string — the SyncBanner must guard on state === "error".
  render(
    <SyncBanner
      status={{
        state: "syncing",
        tip: 0,
        caughtUp: false,
        error: "stale mithril error from previous attempt",
      }}
    />,
  );
  expect(screen.getByText("syncing")).toBeInTheDocument();
  expect(
    screen.queryByText("stale mithril error from previous attempt"),
  ).not.toBeInTheDocument();
});
