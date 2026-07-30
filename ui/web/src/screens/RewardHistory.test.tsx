import { render, screen } from "@testing-library/react";
import { RewardHistory } from "./RewardHistory";
import * as hooks from "../api/hooks";
import type { RewardHistory as RewardHistoryData, RewardEntry } from "../api/types";

const REWARD1: RewardEntry = {
  epoch: 500,
  amount: "1234567",
  pool_id: "pool1abcdefghijklmnopqrstuvwxyz0123456789abcdefghij",
  type: "member",
};

const REWARD2: RewardEntry = {
  epoch: 502,
  amount: "9876543",
  pool_id: "pool1abcdefghijklmnopqrstuvwxyz0123456789abcdefghij",
  type: "member",
};

function mockRewards(data: Partial<RewardHistoryData> | null, over: Partial<{ loading: boolean; error: Error | null }> = {}) {
  vi.spyOn(hooks, "useRewards").mockReturnValue({
    data: data
      ? { rewards: [], provisional: false, note: "", ...data }
      : null,
    error: over.error ?? null,
    loading: over.loading ?? false,
    refresh: vi.fn(),
    setData: vi.fn(),
  } as never);
}

afterEach(() => {
  vi.restoreAllMocks();
});

test("(a) renders an epoch row per reward, newest epoch first", () => {
  mockRewards({ rewards: [REWARD1, REWARD2], provisional: true, note: "provisional" });
  render(<RewardHistory network="preview" />);

  const cells = screen.getAllByRole("cell");
  // First data cell of the first row is the newest epoch (502).
  expect(cells[0]).toHaveTextContent("502");
  expect(screen.getByText("500")).toBeInTheDocument();
});

test("(b) formats reward amounts as ADA", () => {
  mockRewards({ rewards: [REWARD1] });
  render(<RewardHistory network="preview" />);
  // 1234567 lovelace → 1.234567 ADA. With a single reward the per-epoch row
  // and the total banner both show this value, so it appears twice.
  expect(screen.getAllByText(/1\.234567 ADA/).length).toBe(2);
});

test("(b2) sums reward amounts into the total banner", () => {
  mockRewards({ rewards: [REWARD1, REWARD2] });
  render(<RewardHistory network="preview" />);
  // 1234567 + 9876543 = 11111110 lovelace → 11.11111 ADA
  expect(screen.getByText(/11\.11111 ADA/)).toBeInTheDocument();
});

test("(c) shows the provisional note when present", () => {
  mockRewards({ rewards: [REWARD1], provisional: true, note: "rewards are provisional" });
  render(<RewardHistory network="preview" />);
  expect(screen.getByText("rewards are provisional")).toBeInTheDocument();
});

test("(d) shows an empty state when there are no rewards", () => {
  mockRewards({ rewards: [] });
  render(<RewardHistory network="preview" />);
  expect(screen.getByText("No rewards yet")).toBeInTheDocument();
});

test("(d2) shows the provisional note on an empty provisional result", () => {
  mockRewards({ rewards: [], provisional: true, note: "rewards are provisional" });
  render(<RewardHistory network="preview" />);
  expect(screen.getByText("No rewards yet")).toBeInTheDocument();
  expect(screen.getByText("rewards are provisional")).toBeInTheDocument();
});

test("(e) shows a loading state", () => {
  mockRewards(null, { loading: true });
  render(<RewardHistory network="preview" />);
  expect(screen.getByText("Loading…")).toBeInTheDocument();
});

test("(f) shows an error state", () => {
  mockRewards(null, { error: new Error("node unavailable") });
  render(<RewardHistory network="preview" />);
  expect(screen.getByRole("alert")).toHaveTextContent("node unavailable");
});
