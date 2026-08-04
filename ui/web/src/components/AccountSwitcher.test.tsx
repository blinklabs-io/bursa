import { render, screen, fireEvent, waitFor } from "@testing-library/react";
import { AccountSwitcher } from "./AccountSwitcher";
import * as client from "../api/client";
import type { WalletView } from "../api/types";

const wallet: WalletView = {
  id: "w1",
  name: "Main",
  network: "preview",
  stake_address: "stake_test1acct0",
  addresses: ["addr_test1acct0"],
  active: true,
  type: "full",
  active_account_index: 0,
  // The WalletView carries no balances — those come from GET /wallet/accounts
  // (mocked per-test below), which is exactly what the switcher overlays.
  accounts: [
    {
      index: 0,
      label: "Account #0",
      stake_address: "stake_test1acct0",
      first_address: "addr_test1acct0",
      active: true,
    },
    {
      index: 1,
      label: "Account #1",
      stake_address: "stake_test1acct1",
      first_address: "addr_test1acct1",
      active: false,
    },
  ],
};

// The node-local balance summary returned by GET /wallet/accounts.
const accountsWithBalances = {
  active_account_index: 0,
  accounts: [
    { ...wallet.accounts![0], balance: { lovelace: "1500000", assets: [] } },
    { ...wallet.accounts![1], balance: { lovelace: "0", assets: [] } },
  ],
};

// A wallet whose selected account is #1 (used to make #1 the active one).
function walletOnAccount1(): WalletView {
  return {
    ...wallet,
    active_account_index: 1,
    stake_address: "stake_test1acct1",
    addresses: ["addr_test1acct1"],
  };
}

function renderSwitcher(overrides: Partial<Parameters<typeof AccountSwitcher>[0]> = {}) {
  const props = { wallet, onChanged: vi.fn(), ...overrides };
  render(<AccountSwitcher {...props} />);
  return props;
}

beforeEach(() => {
  // useAccounts() fires GET /wallet/accounts on mount; give it a clean default
  // so every test renders without a real fetch. Individual tests override this.
  vi.spyOn(client, "getAccounts").mockResolvedValue(accountsWithBalances);
});

afterEach(() => {
  vi.restoreAllMocks();
});

test("lists every account with its label, marks the active one, and overlays node-local balances from /wallet/accounts", async () => {
  renderSwitcher();
  expect(screen.getByText("Account #0")).toBeInTheDocument();
  expect(screen.getByText("Account #1")).toBeInTheDocument();
  // Balances are not on the WalletView — they arrive once useAccounts resolves.
  expect(await screen.findByText("1.5 ₳")).toBeInTheDocument();

  const active = screen.getByRole("button", { name: /account #0/i });
  expect(active).toHaveAttribute("aria-current", "true");
  const inactive = screen.getByRole("button", { name: /account #1/i });
  expect(inactive).not.toHaveAttribute("aria-current");
});

test("renders accounts without balances when /wallet/accounts is unavailable", async () => {
  vi.spyOn(client, "getAccounts").mockRejectedValue(
    new client.ApiError(503, "node not ready"),
  );
  renderSwitcher();
  // The list still renders from the WalletView; no balance chip is shown.
  expect(screen.getByText("Account #0")).toBeInTheDocument();
  await waitFor(() => expect(client.getAccounts).toHaveBeenCalled());
  expect(screen.queryByText(/₳/)).not.toBeInTheDocument();
});

test("selecting an inactive account switches it server-side and reports the result", async () => {
  const updated = walletOnAccount1();
  const select = vi.spyOn(client, "selectAccount").mockResolvedValue(updated);
  const { onChanged } = renderSwitcher();

  fireEvent.click(screen.getByRole("button", { name: /account #1/i }));

  await waitFor(() => expect(select).toHaveBeenCalledWith(1));
  await waitFor(() => expect(onChanged).toHaveBeenCalledWith(updated));
});

test("clicking the already-active account is a no-op", async () => {
  const select = vi.spyOn(client, "selectAccount");
  const { onChanged } = renderSwitcher();

  fireEvent.click(screen.getByRole("button", { name: /account #0/i }));

  expect(select).not.toHaveBeenCalled();
  expect(onChanged).not.toHaveBeenCalled();
  // Let the mount's getAccounts settle so its state update stays inside act().
  await waitFor(() => expect(client.getAccounts).toHaveBeenCalled());
});

test("adding an account derives the next index then selects it", async () => {
  const add = vi.spyOn(client, "addAccount").mockResolvedValue(wallet);
  const selected = walletOnAccount1();
  const select = vi.spyOn(client, "selectAccount").mockResolvedValue(selected);
  const { onChanged } = renderSwitcher();

  fireEvent.click(screen.getByRole("button", { name: /add account/i }));
  fireEvent.change(screen.getByPlaceholderText(/vault password/i), {
    target: { value: "vault-pass" },
  });
  fireEvent.change(screen.getByPlaceholderText(/spending password/i), {
    target: { value: "spend-pass" },
  });
  fireEvent.click(screen.getByRole("button", { name: /derive account/i }));

  await waitFor(() =>
    expect(add).toHaveBeenCalledWith({
      account_index: 2,
      vault_password: "vault-pass",
      spend_password: "spend-pass",
    }),
  );
  await waitFor(() => expect(select).toHaveBeenCalledWith(2));
  await waitFor(() => expect(onChanged).toHaveBeenCalledWith(selected));
});

test("a selection failure after a successful add is reported distinctly, not as an add failure", async () => {
  const add = vi.spyOn(client, "addAccount").mockResolvedValue(wallet);
  vi.spyOn(client, "selectAccount").mockRejectedValue(
    new client.ApiError(500, "node unavailable"),
  );
  renderSwitcher();

  fireEvent.click(screen.getByRole("button", { name: /add account/i }));
  fireEvent.change(screen.getByPlaceholderText(/vault password/i), {
    target: { value: "vault-pass" },
  });
  fireEvent.change(screen.getByPlaceholderText(/spending password/i), {
    target: { value: "spend-pass" },
  });
  fireEvent.click(screen.getByRole("button", { name: /derive account/i }));

  await waitFor(() => expect(add).toHaveBeenCalled());
  // The add itself succeeded, so the error must say switching failed - not
  // that the (already-derived) account failed to add.
  await waitFor(() =>
    expect(screen.getByRole("alert")).toHaveTextContent(/added, but switching to it failed/i),
  );
});

test("hardware wallets cannot derive a new account", async () => {
  renderSwitcher({ wallet: { ...wallet, type: "hardware" } });
  expect(screen.queryByRole("button", { name: /add account/i })).not.toBeInTheDocument();
  // Let the mount's getAccounts settle so its state update stays inside act().
  await waitFor(() => expect(client.getAccounts).toHaveBeenCalled());
});

test("surfaces an ApiError message when switching fails", async () => {
  vi.spyOn(client, "selectAccount").mockRejectedValue(
    new client.ApiError(404, "unknown account"),
  );
  const { onChanged } = renderSwitcher();

  fireEvent.click(screen.getByRole("button", { name: /account #1/i }));

  await waitFor(() => expect(screen.getByRole("alert")).toHaveTextContent(/unknown account/i));
  expect(onChanged).not.toHaveBeenCalled();
});
