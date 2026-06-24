import { render, screen, fireEvent } from "@testing-library/react";
import { Settings } from "./Settings";
import * as hooks from "../api/hooks";
import type { Account } from "../api/types";

const mockAccount: Account = {
  network: "preview",
  stake_address: "stake_test1uzqxyz1234567890abcdefghijklmnopqrstuvwxyz",
  receive_addresses: ["addr_test1abc"],
};

function mockStatus(state: string, tip = 12345, caughtUp = false) {
  vi.spyOn(hooks, "useStatus").mockReturnValue({
    data: { state, tip, caughtUp },
    error: null,
    loading: false,
    refresh: vi.fn(),
  } as never);
}

afterEach(() => {
  vi.restoreAllMocks();
});

test("(a) renders network from account prop", () => {
  mockStatus("ready", 12345, true);
  render(<Settings account={mockAccount} spendingEnabled={false} />);
  expect(screen.getByText("preview")).toBeInTheDocument();
});

test("(b) renders stake address in monospace and a CopyButton for it", () => {
  const writeText = vi.fn().mockResolvedValue(undefined);
  Object.assign(navigator, { clipboard: { writeText } });
  mockStatus("ready", 12345, true);

  render(<Settings account={mockAccount} spendingEnabled={false} />);

  // The stake address should appear in the document
  expect(screen.getByText(mockAccount.stake_address)).toBeInTheDocument();
  // The copy button must copy the FULL stake address.
  fireEvent.click(screen.getByRole("button", { name: /copy/i }));
  expect(writeText).toHaveBeenCalledWith(mockAccount.stake_address);
});

test("(c) renders sync state pill from useStatus", () => {
  mockStatus("syncing", 10000, false);
  render(<Settings account={mockAccount} spendingEnabled={false} />);
  // The sync state must be visible
  expect(screen.getByText("syncing")).toBeInTheDocument();
});

test("(d) renders tip block number from useStatus", () => {
  mockStatus("ready", 99999, true);
  render(<Settings account={mockAccount} spendingEnabled={false} />);
  expect(screen.getByText("99999")).toBeInTheDocument();
});

test("(e) caughtUp=true shows a caught-up indicator", () => {
  mockStatus("ready", 12345, true);
  render(<Settings account={mockAccount} spendingEnabled={false} />);
  expect(screen.getByText(/caught.?up/i)).toBeInTheDocument();
});

test("(f) caughtUp=false does NOT show caught-up indicator", () => {
  mockStatus("syncing", 12345, false);
  render(<Settings account={mockAccount} spendingEnabled={false} />);
  expect(screen.queryByText(/caught.?up/i)).toBeNull();
});

test("(g) spendingEnabled=true shows 'Spending enabled'", () => {
  mockStatus("ready", 12345, true);
  render(<Settings account={mockAccount} spendingEnabled={true} />);
  expect(screen.getByText(/spending enabled/i)).toBeInTheDocument();
});

test("(h) spendingEnabled=false shows 'Read-only'", () => {
  mockStatus("ready", 12345, true);
  render(<Settings account={mockAccount} spendingEnabled={false} />);
  expect(screen.getByText(/read.?only/i)).toBeInTheDocument();
});

test("(i) loading state from useStatus renders gracefully", () => {
  vi.spyOn(hooks, "useStatus").mockReturnValue({
    data: null,
    error: null,
    loading: true,
    refresh: vi.fn(),
  } as never);
  render(<Settings account={mockAccount} spendingEnabled={false} />);
  // Should not crash; network card still shows
  expect(screen.getByText("preview")).toBeInTheDocument();
});
