import { render, screen, fireEvent, waitFor } from "@testing-library/react";
import { Staking } from "./Staking";
import * as client from "../api/client";
import * as hooks from "../api/hooks";
import type { DelegationPreview, TxResult, PoolInfo } from "../api/types";

const MOCK_POOL: PoolInfo = {
  pool_id: "pool1abc",
  hex: "abc",
  vrf_key: "vrf",
  active_stake: "4800000000",
  live_stake: "12410000000000",
  declared_pledge: "100000000000",
  fixed_cost: "340000000",
  margin_cost: 0.02,
};

const MOCK_PREVIEW: DelegationPreview = {
  pending_id: "del-pending-1",
  certs: [
    { kind: "stake_registration", summary: "Register stake key", deposit_lovelace: "2000000" },
    { kind: "stake_delegation", summary: "Delegate stake to pool1abc" },
    { kind: "vote_delegation", summary: "Delegate voting power to Always Abstain" },
  ],
  fee: "174000",
  deposit: "2000000",
  total: "2174000",
};

const MOCK_TX_RESULT: TxResult = {
  tx_hash: "feedfacefeedfacefeedfacefeedfacefeedfacefeedfacefeedfacefeedface",
};

// mockDelegation controls the status panel / active-vs-fresh branch.
function mockDelegation(
  overrides: Partial<{
    pool_id: string | null;
    active: boolean;
    rewards_sum: string;
    withdrawable_amount: string;
    provisional: boolean;
    note: string;
  }> = {},
) {
  vi.spyOn(hooks, "useDelegation").mockReturnValue({
    data: {
      pool_id: null,
      active: false,
      rewards_sum: "0",
      withdrawable_amount: "0",
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

// --- fresh wallet: pool paste → verified readout ---

test("(a) pasting a pool ID verifies it against the node and shows the readout", async () => {
  mockDelegation({ active: false });
  const getPool = vi.spyOn(client, "getPool").mockResolvedValue(MOCK_POOL);

  render(<Staking />);

  const poolInput = screen.getByPlaceholderText(/pool1\.\.\./i);
  fireEvent.change(poolInput, { target: { value: "pool1abc" } });
  fireEvent.blur(poolInput);

  await waitFor(() => expect(getPool).toHaveBeenCalledWith("pool1abc"));

  // Verified readout shows the node-verification tick (its own span) and the
  // margin parsed from the pool params.
  await waitFor(() =>
    expect(screen.getByText("✓ Verified by your node")).toBeInTheDocument(),
  );
  expect(screen.getByText(/margin 2\.0%/i)).toBeInTheDocument();
});

test("(b) an unknown pool ID shows 'not found by your node' inline", async () => {
  mockDelegation({ active: false });
  vi.spyOn(client, "getPool").mockRejectedValue(new client.ApiError(404, "not found by your node"));

  render(<Staking />);

  const poolInput = screen.getByPlaceholderText(/pool1\.\.\./i);
  fireEvent.change(poolInput, { target: { value: "pool1bad" } });
  fireEvent.blur(poolInput);

  await waitFor(() => expect(screen.getByText(/not found by your node/i)).toBeInTheDocument());
});

// --- compose → itemized preview ---

test("(c) Review delegation builds the request and shows the itemized confirm", async () => {
  mockDelegation({ active: false });
  const build = vi.spyOn(client, "buildDelegation").mockResolvedValue(MOCK_PREVIEW);

  render(<Staking />);

  fireEvent.change(screen.getByPlaceholderText(/pool1\.\.\./i), { target: { value: "pool1abc" } });
  // Pick "Always Abstain" (first vote option).
  fireEvent.click(screen.getByLabelText(/always abstain/i));

  fireEvent.click(screen.getByRole("button", { name: /review delegation/i }));

  await waitFor(() =>
    expect(build).toHaveBeenCalledWith({ pool_id: "pool1abc", vote: { type: "abstain" } }),
  );

  // Itemized confirm: each cert summary plus the 2 ADA deposit and total.
  await waitFor(() => expect(screen.getByText(/register stake key/i)).toBeInTheDocument());
  expect(screen.getByText(/delegate stake to pool1abc/i)).toBeInTheDocument();
  expect(screen.getByText(/2 ₳ deposit/)).toBeInTheDocument(); // 2000000 lovelace
  expect(screen.getByText(/2\.174 ₳/)).toBeInTheDocument(); // total 2174000 lovelace
});

// --- 4-way voting-power picker ---

test("(d) the voting-power picker offers all four targets", () => {
  mockDelegation({ active: false });
  render(<Staking />);

  expect(screen.getByLabelText(/always abstain/i)).toBeInTheDocument();
  expect(screen.getByLabelText(/always no confidence/i)).toBeInTheDocument();
  expect(screen.getByLabelText(/a specific drep/i)).toBeInTheDocument();
  expect(screen.getByLabelText(/register myself as a drep/i)).toBeInTheDocument();
});

test("(e) choosing 'register self' reveals the optional anchor fields + deposit note", () => {
  mockDelegation({ active: false });
  render(<Staking />);

  fireEvent.click(screen.getByLabelText(/register myself as a drep/i));

  expect(screen.getByPlaceholderText(/example\.org\/my-drep/i)).toBeInTheDocument();
  expect(screen.getByText(/500 ₳ deposit/)).toBeInTheDocument();
});

test("(f) choosing 'a specific DRep' without an ID blocks Review with an error", async () => {
  mockDelegation({ active: false });
  const build = vi.spyOn(client, "buildDelegation");
  render(<Staking />);

  fireEvent.click(screen.getByLabelText(/a specific drep/i));
  fireEvent.click(screen.getByRole("button", { name: /review delegation/i }));

  await waitFor(() => expect(screen.getByRole("alert")).toBeInTheDocument());
  expect(build).not.toHaveBeenCalled();
});

// --- preview → confirm (success) ---

test("(g) confirm signs + submits via confirmDelegation; tx hash shown on success", async () => {
  mockDelegation({ active: false });
  vi.spyOn(client, "buildDelegation").mockResolvedValue(MOCK_PREVIEW);
  const confirm = vi.spyOn(client, "confirmDelegation").mockResolvedValue(MOCK_TX_RESULT);

  render(<Staking />);

  fireEvent.change(screen.getByPlaceholderText(/pool1\.\.\./i), { target: { value: "pool1abc" } });
  fireEvent.click(screen.getByLabelText(/always abstain/i));
  fireEvent.click(screen.getByRole("button", { name: /review delegation/i }));

  await waitFor(() => expect(screen.getByText(/register stake key/i)).toBeInTheDocument());

  const password = screen.getByPlaceholderText(/spending password/i);
  fireEvent.change(password, { target: { value: "s3cr3t" } });
  fireEvent.click(screen.getByRole("button", { name: /confirm & sign/i }));

  await waitFor(() => expect(confirm).toHaveBeenCalledWith("del-pending-1", "s3cr3t"));
  await waitFor(() =>
    expect(screen.getByText(new RegExp(MOCK_TX_RESULT.tx_hash))).toBeInTheDocument(),
  );
});

// --- error path: confirm error keeps preview ---

test("(h) a confirm error keeps the preview so the user can retry", async () => {
  mockDelegation({ active: false });
  vi.spyOn(client, "buildDelegation").mockResolvedValue(MOCK_PREVIEW);
  vi.spyOn(client, "confirmDelegation").mockRejectedValue(
    new client.ApiError(401, "incorrect spending password"),
  );

  render(<Staking />);

  fireEvent.change(screen.getByPlaceholderText(/pool1\.\.\./i), { target: { value: "pool1abc" } });
  fireEvent.click(screen.getByLabelText(/always abstain/i));
  fireEvent.click(screen.getByRole("button", { name: /review delegation/i }));

  await waitFor(() => expect(screen.getByText(/register stake key/i)).toBeInTheDocument());

  fireEvent.change(screen.getByPlaceholderText(/spending password/i), { target: { value: "wrong" } });
  fireEvent.click(screen.getByRole("button", { name: /confirm & sign/i }));

  await waitFor(() => expect(screen.getByText(/incorrect spending password/i)).toBeInTheDocument());
  // Still on preview: the password field is still present.
  expect(screen.getByPlaceholderText(/spending password/i)).toBeInTheDocument();
});

// --- active state: withdraw + change ---

test("(i) active wallet shows withdraw + change; Withdraw builds a withdraw-only request", async () => {
  mockDelegation({
    active: true,
    pool_id: "pool1active",
    withdrawable_amount: "14207000",
  });
  const build = vi.spyOn(client, "buildDelegation").mockResolvedValue({
    pending_id: "wd-1",
    certs: [{ kind: "withdrawal", summary: "Withdraw staking rewards", amount_lovelace: "14207000" }],
    fee: "170000",
    deposit: "0",
    withdrawal: "14207000",
    total: "-14037000",
  });

  render(<Staking />);

  // Status shows Registered + the withdrawable amount.
  expect(screen.getByText(/registered/i)).toBeInTheDocument();
  expect(screen.getByText(/14\.207 ₳/)).toBeInTheDocument();

  fireEvent.click(screen.getByRole("button", { name: /withdraw rewards/i }));

  await waitFor(() => expect(build).toHaveBeenCalledWith({ withdraw: true }));
  // Lands on the itemized confirm for the withdrawal.
  await waitFor(() => expect(screen.getByText(/withdraw staking rewards/i)).toBeInTheDocument());
});

test("(j) active wallet 'Change delegation' switches to the set-up form", () => {
  mockDelegation({ active: true, pool_id: "pool1active", withdrawable_amount: "0" });

  render(<Staking />);

  fireEvent.click(screen.getByRole("button", { name: /change delegation/i }));

  // Set-up form is now shown.
  expect(screen.getByRole("button", { name: /review delegation/i })).toBeInTheDocument();
});

test("(k) withdraw button is disabled when there are no withdrawable rewards", () => {
  mockDelegation({ active: true, pool_id: "pool1active", withdrawable_amount: "0" });

  render(<Staking />);

  expect(screen.getByRole("button", { name: /withdraw rewards/i })).toBeDisabled();
});

// --- build error stays on compose ---

test("(l) a buildDelegation error (e.g. no change) is shown inline on the form", async () => {
  mockDelegation({ active: false });
  vi.spyOn(client, "buildDelegation").mockRejectedValue(
    new client.ApiError(422, "requested state matches current state; nothing to do"),
  );

  render(<Staking />);

  fireEvent.change(screen.getByPlaceholderText(/pool1\.\.\./i), { target: { value: "pool1abc" } });
  fireEvent.click(screen.getByRole("button", { name: /review delegation/i }));

  await waitFor(() => expect(screen.getByText(/nothing to do/i)).toBeInTheDocument());
  // Still on the set-up form.
  expect(screen.getByRole("button", { name: /review delegation/i })).toBeInTheDocument();
});
