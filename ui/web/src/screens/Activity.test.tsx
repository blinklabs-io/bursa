import { render, screen, fireEvent } from "@testing-library/react";
import { Activity } from "./Activity";
import * as hooks from "../api/hooks";
import type { Tx } from "../api/types";

const TX1: Tx = {
  tx_hash: "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2",
  tx_index: 0,
  block_height: 12345,
  block_time: 1700000000,
};

const TX2: Tx = {
  tx_hash: "f1e2d3c4b5a6f1e2d3c4b5a6f1e2d3c4b5a6f1e2d3c4b5a6f1e2d3c4b5a6f1e2",
  tx_index: 1,
  block_height: 12300,
  block_time: 1699000000,
};

function mockTransactions(txs: Tx[]) {
  vi.spyOn(hooks, "useTransactions").mockReturnValue({
    data: txs,
    error: null,
    loading: false,
    refresh: vi.fn(),
  } as never);
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
