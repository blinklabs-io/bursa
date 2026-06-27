import { render, screen, fireEvent, within } from "@testing-library/react";
import { Syncing } from "./Syncing";

const noop = () => {};

test("(a) bootstrap download phase shows bytes, ETA, percent and the progress bar", () => {
  render(
    <Syncing
      status={{
        state: "bootstrapping",
        tip: 0,
        caughtUp: false,
        bootstrap: {
          phase: "bootstrap",
          percent: 42.5,
          bytes_downloaded: 1024 * 1024 * 1024, // 1.0 GB
          total_bytes: 4 * 1024 * 1024 * 1024, // 4.0 GB
          bytes_per_second: 18 * 1024 * 1024, // 18.0 MB/s
        },
      }}
      onLoadAnyway={noop}
    />,
  );
  expect(screen.getByText("42.5%")).toBeInTheDocument();
  expect(screen.getByText(/1\.0 GB \/ 4\.0 GB/)).toBeInTheDocument();
  expect(screen.getByText(/min left/)).toBeInTheDocument();
  expect(screen.getByRole("progressbar")).toHaveAttribute("aria-valuenow", "43");
});

test("(b) block-replay phase shows block count, slot range and the era label", () => {
  render(
    <Syncing
      status={{
        state: "bootstrapping",
        tip: 0,
        caughtUp: false,
        bootstrap: {
          phase: "backfill",
          percent: 71,
          count: 18432,
          total: 25900,
          current_slot: 97740,
          tip_slot: 132000,
          description: "Conway",
        },
      }}
      onLoadAnyway={noop}
    />,
  );
  expect(screen.getByText(/18,432 \/ 25,900 blocks/)).toBeInTheDocument();
  expect(screen.getByText(/slot 97,740 → 132,000/)).toBeInTheDocument();
  expect(screen.getByText(/Conway/)).toBeInTheDocument();
});

test("(c) the phase stepper marks earlier phases done and the current one active", () => {
  render(
    <Syncing
      status={{
        state: "bootstrapping",
        tip: 0,
        caughtUp: false,
        bootstrap: { phase: "immutable_copy", percent: 10 },
      }}
      onLoadAnyway={noop}
    />,
  );
  // The active phase's label also appears in the panel head, so scope to the
  // stepper list to assert on the steps themselves.
  const steps = screen.getByRole("list");
  expect(within(steps).getByText("Copy chain history").closest("li")).toHaveClass("sync-step-active");
  expect(within(steps).getByText("Download snapshot").closest("li")).toHaveClass("sync-step-done");
  expect(within(steps).getByText("Backfill blocks").closest("li")).toHaveClass("sync-step-pending");
});

test("(d) chain sync shows how far behind the tip and the block slot", () => {
  const threeDaysAgo = new Date(Date.now() - 3 * 86400 * 1000).toISOString();
  render(
    <Syncing
      status={{ state: "syncing", tip: 115748244, caughtUp: false, latestBlockTime: threeDaysAgo }}
      onLoadAnyway={noop}
    />,
  );
  expect(screen.getByText(/behind/)).toBeInTheDocument();
  expect(screen.getByText("115,748,244")).toBeInTheDocument();
});

test("(e) error state surfaces the node error in an alert", () => {
  render(
    <Syncing
      status={{ state: "error", tip: 0, caughtUp: false, error: "genesis import failed" }}
      onLoadAnyway={noop}
    />,
  );
  expect(screen.getByRole("alert")).toHaveTextContent("genesis import failed");
});

test("(f) the escape hatch invokes onLoadAnyway", () => {
  const onLoadAnyway = vi.fn();
  render(
    <Syncing status={{ state: "syncing", tip: 0, caughtUp: false }} onLoadAnyway={onLoadAnyway} />,
  );
  fireEvent.click(screen.getByRole("button", { name: /load wallet anyway/i }));
  expect(onLoadAnyway).toHaveBeenCalled();
});
