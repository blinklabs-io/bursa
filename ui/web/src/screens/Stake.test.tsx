import { render, screen, fireEvent, waitFor, within } from "@testing-library/react";
import { Stake } from "./Stake";
import * as hooks from "../api/hooks";
import * as client from "../api/client";
import type { PoolDirectoryResponse } from "../api/types";

const POOL_A = "pool1aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const POOL_B = "pool1bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

const DIRECTORY: PoolDirectoryResponse = {
  pools: [
    {
      pool_id: POOL_A,
      hex: "aa".repeat(28),
      vrf_key: "bb".repeat(32),
      active_stake: "62410000000000",
      live_stake: "63120000000000",
      declared_pledge: "100000000000",
      fixed_cost: "170000000",
      margin_cost: 0.019,
      live_saturation: 0.87,
    },
    {
      pool_id: POOL_B,
      hex: "cc".repeat(28),
      vrf_key: "dd".repeat(32),
      active_stake: "8900000000000",
      live_stake: "9010000000000",
      declared_pledge: "50000000000",
      fixed_cost: "340000000",
      margin_cost: 0.01,
      live_saturation: 0.12,
    },
  ],
  total: 2,
  page: 1,
  count: 2,
};

function stubDelegation(active = false) {
  vi.spyOn(hooks, "useDelegation").mockReturnValue({
    data: {
      pool_id: active ? POOL_A : null,
      active,
      rewards_sum: "0",
      withdrawable_amount: "0",
      provisional: false,
      note: "",
    },
    error: null,
    loading: false,
    refresh: vi.fn(),
  } as never);
}

beforeEach(() => {
  stubDelegation(false);
  vi.spyOn(client, "getPoolDirectory").mockResolvedValue(DIRECTORY);
  vi.spyOn(hooks, "useRewards").mockReturnValue({
    data: {
      rewards: [{ epoch: 541, amount: "4218330", pool_id: POOL_A, type: "member" }],
      provisional: false,
      note: "",
    },
    error: null,
    loading: false,
    refresh: vi.fn(),
  } as never);
});

afterEach(() => {
  vi.restoreAllMocks();
});

test("the three staking screens are tabs of one destination", () => {
  render(<Stake network="mainnet" />);

  const tablist = screen.getByRole("tablist");
  const tabs = within(tablist).getAllByRole("tab");
  expect(tabs.map((t) => t.textContent)).toEqual(["Delegation", "Rewards", "Pools"]);
});

test("opens on the tab the route asked for", async () => {
  render(<Stake network="mainnet" initialTab="pools" />);

  expect(screen.getByRole("tab", { name: "Pools" })).toHaveAttribute("aria-selected", "true");
  expect(await screen.findByText(/stake pool directory/i)).toBeInTheDocument();
});

test("choosing a pool in the directory hands it to the delegation form", async () => {
  render(<Stake network="mainnet" initialTab="pools" />);

  // The directory used to tell people to copy a pool ID and paste it into a
  // different screen. Delegating is now a single action on the row.
  const delegateButtons = await screen.findAllByRole("button", { name: "Delegate" });
  fireEvent.click(delegateButtons[0]);

  await waitFor(() =>
    expect(screen.getByRole("tab", { name: "Delegation" })).toHaveAttribute(
      "aria-selected",
      "true",
    ),
  );

  // The chosen pool arrives in the form, already filled in.
  const poolField = await screen.findByDisplayValue(POOL_A);
  expect(poolField).toBeInTheDocument();
});

test("choosing a pool works for a wallet that ALREADY delegates", async () => {
  // The regression this covers: with an active delegation the delegation tab
  // opens on its status panel ("Change delegation"), so a Delegate click that
  // only prefilled the field left the user staring at the status panel with no
  // sign anything had happened. Switching tabs unmounts the delegation screen,
  // so the intent has to survive to its next mount.
  stubDelegation(true);
  render(<Stake network="mainnet" initialTab="pools" />);

  const delegateButtons = await screen.findAllByRole("button", { name: "Delegate" });
  fireEvent.click(delegateButtons[1]);

  expect(await screen.findByDisplayValue(POOL_B)).toBeInTheDocument();
});

test("returning to the delegation tab later opens on status, not compose", async () => {
  stubDelegation(true);
  render(<Stake network="mainnet" initialTab="pools" />);

  fireEvent.click((await screen.findAllByRole("button", { name: "Delegate" }))[0]);
  expect(await screen.findByDisplayValue(POOL_A)).toBeInTheDocument();

  // The intent is consumed, so a later visit is an ordinary one.
  fireEvent.click(screen.getByRole("tab", { name: "Rewards" }));
  fireEvent.click(screen.getByRole("tab", { name: "Delegation" }));

  expect(await screen.findByRole("button", { name: /change delegation/i })).toBeInTheDocument();
});

test("a wallet that cannot delegate still gets rewards and pools", async () => {
  render(<Stake network="mainnet" canDelegate={false} />);

  // Delegation explains itself rather than the whole screen disappearing.
  expect(screen.getByText(/cannot submit a delegation/i)).toBeInTheDocument();

  fireEvent.click(screen.getByRole("tab", { name: "Pools" }));
  expect(await screen.findByText(/stake pool directory/i)).toBeInTheDocument();
});

test("the pool draft survives a trip to the directory and back", async () => {
  render(<Stake network="mainnet" />);

  const field = await screen.findByLabelText(/stake pool/i);
  fireEvent.change(field, { target: { value: "pool1typed-by-hand" } });

  fireEvent.click(screen.getByRole("tab", { name: "Pools" }));
  expect(await screen.findByText(/stake pool directory/i)).toBeInTheDocument();

  fireEvent.click(screen.getByRole("tab", { name: "Delegation" }));
  expect(await screen.findByDisplayValue("pool1typed-by-hand")).toBeInTheDocument();
});
