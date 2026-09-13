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
        network: "preview",
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
        network: "preview",
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

// Position in the list is not evidence: the node runs some phases concurrently
// and may skip one, so "everything above the active phase must be done" was an
// inference the pipeline does not support. With only one report to go on, the
// stepper claims exactly what that report says.
test("(c) the phase stepper claims only what the node has reported", () => {
  render(
    <Syncing
      status={{
        state: "bootstrapping",
        tip: 0,
        caughtUp: false,
        network: "preview",
        bootstrap: { phase: "immutable_copy", percent: 10 },
      }}
      onLoadAnyway={noop}
    />,
  );
  // The active phase's label also appears in the panel head, so scope to the
  // stepper list to assert on the steps themselves.
  const steps = screen.getByRole("list");
  expect(within(steps).getByText("Copy chain history").closest("li")).toHaveClass("sync-step-active");
  expect(within(steps).getByText("Download snapshot").closest("li")).toHaveClass("sync-step-pending");
  expect(within(steps).getByText("Backfill blocks").closest("li")).toHaveClass("sync-step-pending");
});

test("(d) chain sync shows how far behind the tip and the block slot", () => {
  const threeDaysAgo = new Date(Date.now() - 3 * 86400 * 1000).toISOString();
  render(
    <Syncing
      status={{ state: "syncing", tip: 115748244, caughtUp: false, network: "preview", latestBlockTime: threeDaysAgo }}
      onLoadAnyway={noop}
    />,
  );
  expect(screen.getByText(/behind/)).toBeInTheDocument();
  expect(screen.getByText("115,748,244")).toBeInTheDocument();
});

test("(e) indeterminate sync progress is announced to assistive technology", () => {
  render(
    <Syncing
      status={{ state: "starting", tip: 0, caughtUp: false, network: "preview" }}
      onLoadAnyway={noop}
    />,
  );
  const bar = screen.getByRole("progressbar", { name: "Syncing…" });
  expect(bar).not.toHaveAttribute("aria-valuenow");
});

test("(f) error state surfaces the node error in an alert", () => {
  render(
    <Syncing
      status={{ state: "error", tip: 0, caughtUp: false, network: "preview", error: "genesis import failed" }}
      onLoadAnyway={noop}
    />,
  );
  expect(screen.getByRole("alert")).toHaveTextContent("genesis import failed");
});

test("(g) retained bootstrap diagnostics do not override an error state", () => {
  render(
    <Syncing
      status={{
        state: "error",
        tip: 0,
        caughtUp: false,
        network: "preview",
        error: "mithril bootstrap: download failed",
        bootstrap: { phase: "bootstrap", percent: 40 },
      }}
      onLoadAnyway={noop}
    />,
  );
  expect(screen.getByRole("heading", { name: "Your node stopped" })).toBeInTheDocument();
  expect(screen.getByRole("alert")).toHaveTextContent("mithril bootstrap: download failed");
  expect(screen.queryByText("40.0%")).not.toBeInTheDocument();
});

test("(h) the escape hatch invokes onLoadAnyway", () => {
  const onLoadAnyway = vi.fn();
  render(
    <Syncing status={{ state: "syncing", tip: 0, caughtUp: false, network: "preview" }} onLoadAnyway={onLoadAnyway} />,
  );
  fireEvent.click(screen.getByRole("button", { name: /load wallet anyway/i }));
  expect(onLoadAnyway).toHaveBeenCalled();
});

const errorStatus = {
  state: "error" as const,
  tip: 0,
  caughtUp: false,
  network: "preview",
  error: "failed to open listening socket: bind: invalid argument",
};

// The subtitle used to be the raw error, which the panel below already shows —
// so the same sentence appeared twice on one screen.
test("the raw error is shown once, not repeated as the subtitle", () => {
  render(<Syncing status={errorStatus} onLoadAnyway={noop} />);

  const occurrences = screen.queryAllByText(errorStatus.error);
  expect(occurrences).toHaveLength(1);
});

// "Sync interrupted" implied it would resume. This state does not resume on its
// own, and a title that says otherwise leaves someone waiting on nothing.
test("the error state does not describe itself as a resumable interruption", () => {
  render(<Syncing status={errorStatus} onLoadAnyway={noop} />);

  expect(screen.getByRole("heading", { name: /your node stopped/i })).toBeInTheDocument();
  expect(screen.queryByText(/interrupted/i)).not.toBeInTheDocument();
});

// The escape hatch promised "until syncing finishes" in every state. In the
// error state syncing is not going to finish, so it must not say so.
test("the escape hatch does not promise a sync that will finish", () => {
  render(<Syncing status={errorStatus} onLoadAnyway={noop} />);

  expect(screen.queryByText(/until syncing finishes/i)).not.toBeInTheDocument();
  // Addresses are read through the node as well (the next-unused lookup hits the
  // chain), so the copy must not offer them as something still available here.
  // Asserted positively and in one phrase: rejecting the old wording alone would
  // pass again the moment new copy offered addresses in different words.
  expect(
    screen.getByText(/addresses are all read through the node and need it running/i),
  ).toBeInTheDocument();
});

// A dead end with no next step is the thing that made this screen feel broken.
test("the error state says what to do next", () => {
  render(<Syncing status={errorStatus} onLoadAnyway={noop} />);

  expect(screen.getByText(/restarting the wallet will try again/i)).toBeInTheDocument();
  expect(screen.getByText(/keys are in the vault/i)).toBeInTheDocument();
});

// The syncing state keeps its original promise, which is accurate there.
test("a syncing node still says balances fill in when the sync finishes", () => {
  render(<Syncing status={{ state: "syncing", tip: 5, caughtUp: false, network: "preview" }} onLoadAnyway={noop} />);

  expect(screen.getByText(/until syncing finishes/i)).toBeInTheDocument();
});

// The node imports the ledger state and copies the immutable chain AT THE SAME
// TIME (dingo runs them as two goroutines in one errgroup), and both report
// through a single progress field. Rendering only the newest report made one
// bar alternate between two unrelated percentages — measured on preview:
// immutable_copy 75.1%, then ledger_import 52.3%, then immutable_copy 79.0%.
// These pin each phase keeping its own number.

const concurrent = {
  state: "bootstrapping" as const,
  tip: 0,
  caughtUp: false,
  network: "preview",
  bootstrap: { phase: "immutable_copy", percent: 79 },
  bootstrap_phases: [
    { phase: "immutable_copy", percent: 79, count: 3785300, tip_slot: 122592950, current_slot: 96863246 },
    { phase: "ledger_import", percent: 52.3, description: "utxo" },
  ],
};

test("two phases running at once each show their own progress", () => {
  render(<Syncing status={concurrent} onLoadAnyway={noop} />);

  expect(screen.getByText("79.0%")).toBeInTheDocument();
  expect(screen.getByText("52.3%")).toBeInTheDocument();
  const bars = screen.getAllByRole("progressbar");
  expect(bars).toHaveLength(2);
  expect(bars[0]).toHaveAttribute("aria-valuenow", "79");
  expect(bars[1]).toHaveAttribute("aria-valuenow", "52");
});

test("each concurrent bar says which phase it measures", () => {
  render(<Syncing status={concurrent} onLoadAnyway={noop} />);

  expect(screen.getByRole("progressbar", { name: /copy chain history/i })).toBeInTheDocument();
  expect(screen.getByRole("progressbar", { name: /import ledger state/i })).toBeInTheDocument();
});

// The bug this replaced: a single number that jumps from 79% to 52.3% and back
// every poll, with nothing saying they measure different work.
test("a report from one phase leaves the other phase's number alone", () => {
  const { rerender } = render(<Syncing status={concurrent} onLoadAnyway={noop} />);

  rerender(
    <Syncing
      status={{
        ...concurrent,
        bootstrap: { phase: "ledger_import", percent: 78.1 },
        bootstrap_phases: [
          concurrent.bootstrap_phases[0],
          { phase: "ledger_import", percent: 78.1, description: "utxo" },
        ],
      }}
      onLoadAnyway={noop}
    />,
  );

  expect(screen.getByText("79.0%")).toBeInTheDocument();
  expect(screen.getByText("78.1%")).toBeInTheDocument();
});

// A finished phase stays on screen as finished. That is what keeps the NEXT
// phase starting at 0.1% from reading as an hour of work thrown away.
test("a finished phase reads as done, not as a percent that fell back to zero", () => {
  render(
    <Syncing
      status={{
        state: "bootstrapping",
        tip: 0,
        caughtUp: false,
        network: "preview",
        bootstrap: { phase: "immutable_copy", percent: 0.1 },
        bootstrap_phases: [
          { phase: "bootstrap", percent: 100, done: true },
          { phase: "immutable_copy", percent: 0.1 },
        ],
      }}
      onLoadAnyway={noop}
    />,
  );

  const download = screen.getByRole("progressbar", { name: /download snapshot/i });
  expect(download).toHaveAttribute("aria-valuenow", "100");
  expect(screen.getByText(/^done$/i)).toBeInTheDocument();
  expect(screen.getByText("0.1%")).toBeInTheDocument();
});

// The checklist used to derive done/pending from a phase's position in a fixed
// list, so a phase running concurrently with an earlier-listed one was drawn as
// "pending" while it sat at 79%.
test("the checklist marks a running phase active even when a phase above it has not finished", () => {
  render(<Syncing status={concurrent} onLoadAnyway={noop} />);

  const items = screen.getAllByRole("listitem");
  const copy = items.find((li) => li.textContent?.includes("Copy chain history"));
  const importLedger = items.find((li) => li.textContent?.includes("Import ledger state"));
  const gap = items.find((li) => li.textContent?.includes("Fetch gap blocks"));

  expect(copy?.className).toContain("sync-step-active");
  expect(importLedger?.className).toContain("sync-step-active");
  expect(gap?.className).toContain("sync-step-pending");
});

test("the checklist marks a finished phase done", () => {
  render(
    <Syncing
      status={{
        state: "bootstrapping",
        tip: 0,
        caughtUp: false,
        network: "preview",
        bootstrap: { phase: "immutable_copy", percent: 0.1 },
        bootstrap_phases: [
          { phase: "bootstrap", percent: 100, done: true },
          { phase: "immutable_copy", percent: 0.1 },
        ],
      }}
      onLoadAnyway={noop}
    />,
  );

  const items = screen.getAllByRole("listitem");
  const download = items.find((li) => li.textContent?.includes("Download snapshot"));
  expect(download?.className).toContain("sync-step-done");
});

// An older node sends only the single latest report; the screen must still work.
test("falls back to the single progress report when the node sends no phase list", () => {
  render(
    <Syncing
      status={{
        state: "bootstrapping",
        tip: 0,
        caughtUp: false,
        network: "preview",
        bootstrap: { phase: "backfill", percent: 12.5, count: 27300, tip_slot: 122592180, current_slot: 546272 },
      }}
      onLoadAnyway={noop}
    />,
  );

  expect(screen.getByText("12.5%")).toBeInTheDocument();
  expect(screen.getByRole("progressbar", { name: /backfill blocks/i })).toBeInTheDocument();
});
