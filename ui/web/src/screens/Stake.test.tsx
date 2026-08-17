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

test("the compose form stays open across a trip to another tab", async () => {
  // An already-delegating wallet opens on its status panel, so if the compose
  // view were not remembered the user would come back from the directory to
  // "Change delegation" with their half-filled form hidden behind it.
  stubDelegation(true);
  render(<Stake network="mainnet" initialTab="pools" />);

  fireEvent.click((await screen.findAllByRole("button", { name: "Delegate" }))[0]);
  expect(await screen.findByDisplayValue(POOL_A)).toBeInTheDocument();

  fireEvent.click(screen.getByRole("tab", { name: "Rewards" }));
  fireEvent.click(screen.getByRole("tab", { name: "Delegation" }));

  expect(await screen.findByDisplayValue(POOL_A)).toBeInTheDocument();
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

test("changing route switches tab on an already-mounted screen", async () => {
  // #/pools -> #/rewards is the same component in the same place, so initial
  // state alone would strand the user on whichever tab they arrived at.
  const { rerender } = render(<Stake network="mainnet" initialTab="pools" />);
  expect(await screen.findByRole("tab", { name: "Pools" })).toHaveAttribute("aria-selected", "true");

  rerender(<Stake network="mainnet" initialTab="rewards" />);

  await waitFor(() =>
    expect(screen.getByRole("tab", { name: "Rewards" })).toHaveAttribute("aria-selected", "true"),
  );
});

test("a wallet that cannot delegate is not offered a Delegate action", async () => {
  render(<Stake network="mainnet" canDelegate={false} initialTab="pools" />);

  expect(await screen.findByText(/stake pool directory/i)).toBeInTheDocument();
  // The button would hand a pool to a tab that only explains why it cannot be
  // used, dropping the choice with no feedback.
  expect(screen.queryByRole("button", { name: "Delegate" })).not.toBeInTheDocument();
});

test("the whole delegation draft survives a trip to another tab", async () => {
  render(<Stake network="mainnet" />);

  const pool = await screen.findByLabelText(/stake pool/i);
  fireEvent.change(pool, { target: { value: "pool1typed" } });
  // A vote target is part of the same draft; lifting only the pool ID would
  // have thrown this away the moment the user glanced at the directory.
  fireEvent.click(screen.getByLabelText(/always abstain/i));

  fireEvent.click(screen.getByRole("tab", { name: "Pools" }));
  expect(await screen.findByText(/stake pool directory/i)).toBeInTheDocument();
  fireEvent.click(screen.getByRole("tab", { name: "Delegation" }));

  expect(await screen.findByDisplayValue("pool1typed")).toBeInTheDocument();
  expect(screen.getByLabelText(/always abstain/i)).toBeChecked();
});

test("rewards stay reachable when the node cannot answer queries", async () => {
  // The old #/rewards route had no node gate; merging the screens must not
  // quietly take reward history away from a read-only or offline-node wallet.
  render(<Stake network="mainnet" canQueryNode={false} canDelegate={false} initialTab="rewards" />);

  expect(await screen.findByRole("tab", { name: "Rewards" })).toHaveAttribute("aria-selected", "true");
  expect(screen.getByText("541")).toBeInTheDocument();

  fireEvent.click(screen.getByRole("tab", { name: "Pools" }));
  expect(await screen.findByText(/not answering queries yet/i)).toBeInTheDocument();
});
