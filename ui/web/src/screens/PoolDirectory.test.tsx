import { render, screen, fireEvent, waitFor } from "@testing-library/react";
import { PoolDirectory } from "./PoolDirectory";
import * as client from "../api/client";
import type { PoolInfo, PoolDirectoryResponse } from "../api/types";

const POOL_A: PoolInfo = {
  pool_id: "pool1aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa0001",
  hex: "aa",
  vrf_key: "",
  active_stake: "4800000000",
  live_stake: "5000000000",
  declared_pledge: "100000000",
  fixed_cost: "340000000",
  margin_cost: 0.05,
  live_saturation: 0.42,
};

const POOL_B: PoolInfo = {
  pool_id: "pool1bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb0002",
  hex: "bb",
  vrf_key: "",
  active_stake: "8800000000",
  live_stake: "9000000000",
  declared_pledge: "200000000",
  fixed_cost: "170000000",
  margin_cost: 0.02,
  live_saturation: 0.9,
};

function directory(pools: PoolInfo[], overrides?: Partial<PoolDirectoryResponse>): PoolDirectoryResponse {
  return { pools, total: pools.length, page: 1, count: 50, ...overrides };
}

afterEach(() => {
  vi.restoreAllMocks();
});

test("lists stake pools read from the node with formatted margin/pledge/saturation", async () => {
  vi.spyOn(client, "getPoolDirectory").mockResolvedValue(directory([POOL_A, POOL_B]));

  render(<PoolDirectory network="preview" />);

  // margin 0.05 → 5.0%, saturation 0.42 → 42.0%, pledge/live in ADA.
  expect(await screen.findByText("5.0%")).toBeInTheDocument();
  expect(screen.getByText("42.0%")).toBeInTheDocument();
  expect(screen.getByText("100")).toBeInTheDocument(); // 100000000 lovelace pledge → 100 ADA
  expect(screen.getByText("5,000")).toBeInTheDocument(); // 5000000000 → 5000 ADA
  // Copy affordance carries the full (untruncated) pool id.
  expect(
    screen.getByRole("button", { name: `Copy pool id ${POOL_A.pool_id}` }),
  ).toBeInTheDocument();
});

test("search box queries the node server-side with the typed term", async () => {
  const getPoolDirectory = vi
    .spyOn(client, "getPoolDirectory")
    .mockResolvedValue(directory([POOL_A, POOL_B]));

  render(<PoolDirectory network="preview" />);
  await screen.findByText("5.0%");

  getPoolDirectory.mockResolvedValue(directory([POOL_B]));
  fireEvent.change(screen.getByLabelText(/search by pool id/i), {
    target: { value: "bbb" },
  });

  await waitFor(() =>
    expect(getPoolDirectory).toHaveBeenLastCalledWith({ q: "bbb", page: 1 }),
  );
  await waitFor(() =>
    expect(
      screen.getByRole("button", { name: `Copy pool id ${POOL_B.pool_id}` }),
    ).toBeInTheDocument(),
  );
});

test("shows an empty-search message when nothing matches", async () => {
  vi.spyOn(client, "getPoolDirectory").mockResolvedValue(directory([], { total: 0 }));

  render(<PoolDirectory network="preview" />);
  // With no query typed, the generic empty state shows.
  expect(await screen.findByText(/no pools found/i)).toBeInTheDocument();
});

test("surfaces an API error", async () => {
  vi.spyOn(client, "getPoolDirectory").mockRejectedValue(
    new client.ApiError(503, "node not ready"),
  );

  render(<PoolDirectory network="preview" />);
  expect(await screen.findByRole("alert")).toHaveTextContent(/node not ready/i);
});
