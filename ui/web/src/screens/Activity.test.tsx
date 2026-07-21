import { render, screen, fireEvent, waitFor, within } from "@testing-library/react";
import { Activity } from "./Activity";
import * as hooks from "../api/hooks";
import * as client from "../api/client";
import type { Tx, TxDetail } from "../api/types";

const TX1: Tx = {
  tx_hash: "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2",
  tx_index: 0,
  block_height: 12345,
  block_time: 1700000000,
  direction: "received",
  net_lovelace: "3000000",
  asset_deltas: [],
  fee: "170000",
  confirmations: 10,
  pending: false,
};

const TX2: Tx = {
  tx_hash: "f1e2d3c4b5a6f1e2d3c4b5a6f1e2d3c4b5a6f1e2d3c4b5a6f1e2d3c4b5a6f1e2",
  tx_index: 1,
  block_height: 12300,
  block_time: 1699000000,
  direction: "sent",
  net_lovelace: "-1500000",
  asset_deltas: [{ unit: "tokenA", quantity: "-4" }],
  fee: "180000",
  confirmations: 0,
  pending: true,
};

// A transaction pruned under lean-node history-expiry: the node no longer has
// a record of it, so enrichTx (backend) leaves Direction/NetLovelace/Fee at
// their Go zero values and never sets AssetDeltas at all — the Go nil slice
// zero value serializes to JSON `null`, not `[]`, which is why the TS type
// declares `AssetDelta[] | null`. block_height/block_time/confirmations still
// hold, since those come from the address-history call, not enrichment.
const TX_PRUNED: Tx = {
  tx_hash: "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
  tx_index: 0,
  block_height: 500,
  block_time: 1600000000,
  direction: "",
  net_lovelace: "",
  asset_deltas: null,
  fee: "",
  confirmations: 200,
  pending: false,
};

function mockTransactions(txs: Tx[]) {
  vi.spyOn(hooks, "useTransactions").mockReturnValue({
    data: txs,
    error: null,
    loading: false,
    refresh: vi.fn(),
  } as never);
}

/**
 * Stubs URL.createObjectURL/revokeObjectURL for the CSV-export tests via
 * vi.spyOn, so the afterEach's vi.restoreAllMocks() actually cleans them up
 * (a plain `Object.assign(URL, ...)` would mutate the global URL constructor
 * permanently, since restoreAllMocks only reverts vi.spyOn/vi.mock wrappers).
 * jsdom doesn't implement either method, so a no-op is installed first —
 * vi.spyOn requires the property to already be a function to spy on it.
 */
function stubUrlObjectMethods() {
  const target = URL as unknown as {
    createObjectURL?: (obj: Blob) => string;
    revokeObjectURL?: (url: string) => void;
  };
  target.createObjectURL ??= () => "";
  target.revokeObjectURL ??= () => {};
  return {
    createObjectURL: vi.spyOn(URL, "createObjectURL").mockReturnValue("blob:mock-url"),
    revokeObjectURL: vi.spyOn(URL, "revokeObjectURL").mockImplementation(() => {}),
  };
}

afterEach(() => {
  vi.restoreAllMocks();
});

test("(a) renders block heights for each transaction", () => {
  mockTransactions([TX1, TX2]);
  render(<Activity />);

  expect(screen.getByText("12345")).toBeInTheDocument();
  expect(screen.getByText("12300")).toBeInTheDocument();
});

test("(b) renders truncated tx hash with a CopyButton that copies the FULL hash", async () => {
  const writeText = vi.fn().mockResolvedValue(undefined);
  Object.assign(navigator, { clipboard: { writeText } });
  mockTransactions([TX1]);
  render(<Activity />);

  // The copy button must copy the full hash, not the truncated display value.
  const copyButtons = screen.getAllByRole("button", { name: /copy/i });
  expect(copyButtons.length).toBeGreaterThanOrEqual(1);
  fireEvent.click(copyButtons[0]);
  expect(writeText).toHaveBeenCalledWith(TX1.tx_hash);
  expect(await screen.findByText("Copied")).toBeInTheDocument();

  // At least the beginning of the hash should be visible
  expect(screen.getByText(new RegExp(TX1.tx_hash.slice(0, 8)))).toBeInTheDocument();
});

test("(c) preserves API order (newest-first — TX1 row appears before TX2 row)", () => {
  mockTransactions([TX1, TX2]);
  render(<Activity />);

  const cells = screen.getAllByText(/^1[23]\d{3}$/);
  // TX1 block 12345 should come before TX2 block 12300
  expect(cells[0].textContent).toBe("12345");
  expect(cells[1].textContent).toBe("12300");
});

test("(d) empty list renders 'No transactions yet' message", () => {
  mockTransactions([]);
  render(<Activity />);

  expect(screen.getByText(/no transactions yet/i)).toBeInTheDocument();
});

test("(e) loading state renders a loading indicator", () => {
  vi.spyOn(hooks, "useTransactions").mockReturnValue({
    data: null,
    error: null,
    loading: true,
    refresh: vi.fn(),
  } as never);

  render(<Activity />);

  expect(screen.getByText(/loading/i)).toBeInTheDocument();
});

test("(f) error state renders inline error message", () => {
  vi.spyOn(hooks, "useTransactions").mockReturnValue({
    data: null,
    error: new Error("tx fetch error"),
    loading: false,
    refresh: vi.fn(),
  } as never);

  render(<Activity />);

  expect(screen.getByText(/tx fetch error/i)).toBeInTheDocument();
});

test("(g) block_time is formatted to a readable date string", () => {
  mockTransactions([TX1]);
  render(<Activity />);

  // block_time 1700000000 = 2023-11-14 (UTC) — assert year is present
  // Use a broad regex so locale doesn't matter
  const datePattern = /2023/;
  expect(screen.getByText(datePattern)).toBeInTheDocument();
});

test("(h) shows a direction indicator and signed net amount per row", () => {
  mockTransactions([TX1, TX2]);
  render(<Activity />);
  const table = within(screen.getByRole("table"));

  expect(table.getByText("Received")).toBeInTheDocument();
  expect(table.getByText("Sent")).toBeInTheDocument();
  expect(table.getByText("+3 ADA")).toBeInTheDocument();
  expect(table.getByText("-1.5 ADA")).toBeInTheDocument();
});

test("(i) shows the fee per row", () => {
  mockTransactions([TX1]);
  render(<Activity />);

  expect(screen.getByText("0.17 ADA")).toBeInTheDocument();
});

test("(j) shows a Pending pill for unconfirmed transactions and a count otherwise", () => {
  mockTransactions([TX1, TX2]);
  render(<Activity />);

  expect(screen.getByText("Pending")).toBeInTheDocument();
  expect(screen.getByText("10")).toBeInTheDocument();
});

test("(k) search filters the list by tx hash substring", () => {
  mockTransactions([TX1, TX2]);
  render(<Activity />);

  fireEvent.change(screen.getByLabelText(/search transactions/i), {
    target: { value: TX2.tx_hash.slice(0, 10) },
  });

  const table = within(screen.getByRole("table"));
  expect(table.queryByText("Sent")).toBeInTheDocument();
  expect(table.queryByText("Received")).not.toBeInTheDocument();
});

test("(l) direction filter narrows the list", () => {
  mockTransactions([TX1, TX2]);
  render(<Activity />);

  fireEvent.change(screen.getByLabelText(/filter by direction/i), {
    target: { value: "sent" },
  });

  const table = within(screen.getByRole("table"));
  expect(table.queryByText("Sent")).toBeInTheDocument();
  expect(table.queryByText("Received")).not.toBeInTheDocument();
});

test("(m) filters combine to show 'no transactions match' when nothing matches", () => {
  mockTransactions([TX1, TX2]);
  render(<Activity />);

  fireEvent.change(screen.getByLabelText(/search transactions/i), {
    target: { value: "does-not-exist" },
  });

  expect(screen.getByText(/no transactions match your filters/i)).toBeInTheDocument();
});

test("(n) clicking Details opens a drawer with the transaction breakdown", async () => {
  const detail: TxDetail = {
    ...TX1,
    inputs: [{ address: "addr_other", lovelace: "5000000", assets: [], is_mine: false }],
    outputs: [
      { address: "addr_mine", lovelace: "3000000", assets: [], is_mine: true },
      { address: "addr_other", lovelace: "1830000", assets: [], is_mine: false },
    ],
  };
  vi.spyOn(client, "getTransactionDetail").mockResolvedValue(detail);
  mockTransactions([TX1]);
  render(<Activity />);

  fireEvent.click(screen.getByRole("button", { name: /view details/i }));

  const dialog = await screen.findByRole("dialog");
  await waitFor(() => expect(client.getTransactionDetail).toHaveBeenCalledWith(TX1.tx_hash));
  const drawer = within(dialog);
  expect(await drawer.findAllByText("addr_other")).toHaveLength(2); // one input, one output
  expect(drawer.getByText("addr_mine")).toBeInTheDocument();
  expect(drawer.getByText("Mine")).toBeInTheDocument();
  expect(drawer.getAllByText("External")).toHaveLength(2);

  fireEvent.click(screen.getByRole("button", { name: /close/i }));
  expect(screen.queryByRole("dialog")).not.toBeInTheDocument();
});

test("(o) drawer shows an inline error if the detail fetch fails", async () => {
  vi.spyOn(client, "getTransactionDetail").mockRejectedValue(new Error("boom"));
  mockTransactions([TX1]);
  render(<Activity />);

  fireEvent.click(screen.getByRole("button", { name: /view details/i }));

  expect(await screen.findByText("boom")).toBeInTheDocument();
});

test("(p) CSV export builds a downloadable Blob from the visible rows, with no network call", () => {
  const { createObjectURL } = stubUrlObjectMethods();
  const fetchSpy = vi.spyOn(globalThis, "fetch");
  mockTransactions([TX1, TX2]);
  render(<Activity />);

  fireEvent.click(screen.getByRole("button", { name: /export csv/i }));

  expect(createObjectURL).toHaveBeenCalledTimes(1);
  const blob = createObjectURL.mock.calls[0][0] as Blob;
  expect(blob).toBeInstanceOf(Blob);
  expect(fetchSpy).not.toHaveBeenCalled();
});

test("(q) a pruned tx (null asset_deltas, no enrichment) renders without crashing and CSV export doesn't throw", () => {
  const { createObjectURL } = stubUrlObjectMethods();
  mockTransactions([TX1, TX_PRUNED]);

  expect(() => render(<Activity />)).not.toThrow();

  // Direction shows "Unknown" for the pruned tx; its known block height and
  // confirmations (from the history call, not enrichment) still render.
  expect(screen.getByText("Unknown")).toBeInTheDocument();
  expect(screen.getByText("500")).toBeInTheDocument();
  expect(screen.getByText("200")).toBeInTheDocument();

  // The CSV export must not throw even though asset_deltas is null — the
  // value is produced lazily by the click handler, not eagerly on render.
  expect(() =>
    fireEvent.click(screen.getByRole("button", { name: /export csv/i })),
  ).not.toThrow();
  expect(createObjectURL).toHaveBeenCalledTimes(1);
});

test("(r) drawer detail view renders a pruned tx (null asset_deltas) without crashing", async () => {
  const detail: TxDetail = {
    ...TX_PRUNED,
    inputs: [],
    outputs: [],
  };
  vi.spyOn(client, "getTransactionDetail").mockResolvedValue(detail);
  mockTransactions([TX_PRUNED]);
  render(<Activity />);

  fireEvent.click(screen.getByRole("button", { name: /view details/i }));

  const dialog = await screen.findByRole("dialog");
  expect(within(dialog).getByText("Unknown")).toBeInTheDocument();
});

test("(s) each row has an external explorer link to the FULL tx hash, scoped to the wallet's network", () => {
  mockTransactions([TX1]);
  render(<Activity network="mainnet" />);

  const link = screen.getByRole("link");
  expect(link).toHaveAttribute("href", `https://cardanoscan.io/transaction/${TX1.tx_hash}`);
  expect(link).toHaveAttribute("target", "_blank");
  expect(link).toHaveAttribute("rel", expect.stringContaining("noopener"));
});
