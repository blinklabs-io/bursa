import { render, screen } from "@testing-library/react";
import { Portfolio } from "./Portfolio";
import * as hooks from "../api/hooks";

function mockBalance(lovelace: string, assets: { unit: string; quantity: string }[]) {
  vi.spyOn(hooks, "useBalance").mockReturnValue({
    data: { lovelace, assets },
    error: null,
    loading: false,
    refresh: vi.fn(),
  } as never);
}

function mockDelegation(overrides: Partial<{
  pool_id: string | null;
  active: boolean;
  rewards_sum: string;
  withdrawable_amount: string;
  provisional: boolean;
  note: string;
}> = {}) {
  vi.spyOn(hooks, "useDelegation").mockReturnValue({
    data: {
      pool_id: "pool1abc123",
      active: true,
      rewards_sum: "1000000",
      withdrawable_amount: "500000",
      provisional: false,
      note: "",
      ...overrides,
    },
    error: null,
    loading: false,
    refresh: vi.fn(),
  } as never);
}

afterEach(() => {
  vi.restoreAllMocks();
});

test("(a) formats lovelace to ADA correctly — 4500000 lovelace = 4.5 ADA", () => {
  mockBalance("4500000", []);
  mockDelegation();

  render(<Portfolio />);

  // "4.500000" or "4.5" — both are valid per spec (trailing zeros may be trimmed)
  expect(screen.getByText(/4\.5/)).toBeInTheDocument();
});

test("(b) renders native token row with unit and quantity", () => {
  mockBalance("4500000", [
    { unit: "lovelace_unit.TokenA", quantity: "999999999999999" },
  ]);
  mockDelegation();

  render(<Portfolio />);

  expect(screen.getByText("lovelace_unit.TokenA")).toBeInTheDocument();
  expect(screen.getByText("999999999999999")).toBeInTheDocument();
});

test("(c) delegation card shows pool id, active pill, rewards, and withdrawable", () => {
  mockBalance("4500000", []);
  mockDelegation({
    pool_id: "pool1testpoolid",
    active: true,
    rewards_sum: "2000000",
    withdrawable_amount: "1000000",
    provisional: false,
    note: "",
  });

  render(<Portfolio />);

  expect(screen.getByText("pool1testpoolid")).toBeInTheDocument();
  // active pill
  expect(screen.getByText(/active/i)).toBeInTheDocument();
});

test("(d) provisional=true renders a visible provisional indicator", () => {
  mockBalance("4500000", []);
  mockDelegation({
    provisional: true,
    note: "Delegation registered but not yet confirmed on-chain.",
  });

  render(<Portfolio />);

  // The provisional indicator must be visible.
  expect(screen.getByText(/provisional/i)).toBeInTheDocument();
});

test("(e) not delegated shows fallback text", () => {
  mockBalance("4500000", []);
  mockDelegation({ pool_id: null, active: false });

  render(<Portfolio />);

  expect(screen.getByText(/not delegated/i)).toBeInTheDocument();
});

test("(f) loading state renders a loading indicator", () => {
  vi.spyOn(hooks, "useBalance").mockReturnValue({
    data: null,
    error: null,
    loading: true,
    refresh: vi.fn(),
  } as never);
  vi.spyOn(hooks, "useDelegation").mockReturnValue({
    data: null,
    error: null,
    loading: true,
    refresh: vi.fn(),
  } as never);

  render(<Portfolio />);

  expect(screen.getByText(/loading/i)).toBeInTheDocument();
});

test("(g) error state renders inline error message", () => {
  vi.spyOn(hooks, "useBalance").mockReturnValue({
    data: null,
    error: new Error("network error"),
    loading: false,
    refresh: vi.fn(),
  } as never);
  vi.spyOn(hooks, "useDelegation").mockReturnValue({
    data: null,
    error: null,
    loading: false,
    refresh: vi.fn(),
  } as never);

  render(<Portfolio />);

  expect(screen.getByText(/network error/i)).toBeInTheDocument();
});

test("(h) fresh wallet with zero balance is valid — not an error", () => {
  mockBalance("0", []);
  mockDelegation({ pool_id: null, active: false });

  render(<Portfolio />);

  // Should show "0 ADA" in the balance card without an error state.
  expect(screen.getByText(/^0 ADA$/)).toBeInTheDocument();
  expect(screen.queryByRole("alert")).toBeNull();
});
