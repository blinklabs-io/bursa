import { render, screen, fireEvent, waitFor } from "@testing-library/react";
import { Swap } from "./Swap";
import * as client from "../api/client";
import * as hooks from "../api/hooks";
import type { DexQuote, DexPool } from "../api/types";

const POOL: DexPool = {
  protocol: "minswap-v2",
  pool_id: "p1",
  asset_x: "lovelace",
  asset_y: "abcd1234567890abcdef1234567890abcdef1234567890abcdef1234TEST",
  reserve_x: "100000000",
  reserve_y: "200000000",
  price_xy: 2.0,
  price_yx: 0.5,
  effective_fee: 0.997,
  tx_hash: "deadbeef",
  tx_index: 0,
};

const QUOTE: DexQuote = {
  protocol: "minswap-v2",
  pool_id: "p1",
  asset_in: "lovelace",
  asset_out: "abcd1234",
  amount_in: "1000000",
  amount_out: "1980000",
  price_impact_pct: 0.4925,
  effective_fee: 0.997,
  route: "minswap-v2 lovelace→abcd1234",
};

function stubPools(pools: DexPool[]) {
  vi.spyOn(hooks, "useDexPools").mockReturnValue({
    data: { pools },
    error: null,
    loading: false,
    refresh: vi.fn(),
  } as never);
}

afterEach(() => {
  vi.restoreAllMocks();
});

test("lists pools read from the node with prices", () => {
  stubPools([POOL]);
  render(<Swap />);
  expect(screen.getByText("minswap-v2")).toBeInTheDocument();
  // effective fee 0.997 → 99.70%
  expect(screen.getByText("99.70%")).toBeInTheDocument();
});

test("gets the best quote and shows route, amount out, price impact and fee", async () => {
  stubPools([POOL]);
  const getDexQuote = vi.spyOn(client, "getDexQuote").mockResolvedValue(QUOTE);

  render(<Swap />);

  fireEvent.change(screen.getByLabelText(/receive \(asset out\)/i), {
    target: { value: "abcd1234" },
  });
  fireEvent.change(screen.getByLabelText(/amount in/i), {
    target: { value: "1000000" },
  });
  fireEvent.click(screen.getByRole("button", { name: /get quote/i }));

  await waitFor(() =>
    expect(getDexQuote).toHaveBeenCalledWith({
      asset_in: "lovelace",
      asset_out: "abcd1234",
      amount_in: "1000000",
    }),
  );

  expect(await screen.findByText(/minswap-v2 lovelace→abcd1234/)).toBeInTheDocument();
  expect(screen.getByText("1980000")).toBeInTheDocument();
  expect(screen.getByText("0.4925%")).toBeInTheDocument();
});

test("rejects a non-positive / non-integer amount before calling the API", async () => {
  stubPools([POOL]);
  const getDexQuote = vi.spyOn(client, "getDexQuote");

  render(<Swap />);
  fireEvent.change(screen.getByLabelText(/receive \(asset out\)/i), {
    target: { value: "abcd1234" },
  });
  fireEvent.change(screen.getByLabelText(/amount in/i), {
    target: { value: "1.5" },
  });
  fireEvent.click(screen.getByRole("button", { name: /get quote/i }));

  await waitFor(() =>
    expect(screen.getByText(/positive whole number/i)).toBeInTheDocument(),
  );
  expect(getDexQuote).not.toHaveBeenCalled();
});

test("surfaces the API error when no route is found", async () => {
  stubPools([POOL]);
  vi.spyOn(client, "getDexQuote").mockRejectedValue(
    new client.ApiError(404, "dex: no pool found for the requested pair"),
  );

  render(<Swap />);
  fireEvent.change(screen.getByLabelText(/receive \(asset out\)/i), {
    target: { value: "nope" },
  });
  fireEvent.change(screen.getByLabelText(/amount in/i), {
    target: { value: "1000000" },
  });
  fireEvent.click(screen.getByRole("button", { name: /get quote/i }));

  await waitFor(() =>
    expect(screen.getByText(/no pool found/i)).toBeInTheDocument(),
  );
});

test("Prepare order shows the prepared order parameters (no in-app submit)", async () => {
  stubPools([POOL]);
  vi.spyOn(client, "getDexQuote").mockResolvedValue(QUOTE);

  render(<Swap />);
  fireEvent.change(screen.getByLabelText(/receive \(asset out\)/i), {
    target: { value: "abcd1234" },
  });
  fireEvent.change(screen.getByLabelText(/amount in/i), {
    target: { value: "1000000" },
  });
  fireEvent.click(screen.getByRole("button", { name: /get quote/i }));

  fireEvent.click(await screen.findByRole("button", { name: /prepare order/i }));

  expect(screen.getByRole("heading", { name: /Prepared Order/i })).toBeInTheDocument();
  // It must be clearly labeled as NOT a submitted swap.
  expect(screen.getByText(/does not build or send swap transactions/i)).toBeInTheDocument();
  // There is no "submit"/"confirm & send" action on the prepared-order panel.
  expect(screen.queryByRole("button", { name: /confirm|submit|send swap/i })).not.toBeInTheDocument();
});

test("Get quote is disabled until an asset-out and amount are entered", () => {
  stubPools([POOL]);
  render(<Swap />);
  expect(screen.getByRole("button", { name: /get quote/i })).toBeDisabled();
});
