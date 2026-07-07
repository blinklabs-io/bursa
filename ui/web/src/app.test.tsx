import { render, screen, waitFor, fireEvent, act } from "@testing-library/react";
import { App } from "./app";
import * as hooks from "./api/hooks";
import * as client from "./api/client";
import type { WalletView } from "./api/types";

const walletA: WalletView = {
  id: "w1",
  name: "Main",
  network: "preview",
  stake_address: "stake_test1abc",
  addresses: ["addr_test1abc"],
  active: true,
};

const walletB: WalletView = {
  id: "w2",
  name: "Savings",
  network: "preview",
  stake_address: "stake_test1def",
  addresses: ["addr_test1def"],
  active: false,
};

function stubStatus(state: string) {
  vi.spyOn(hooks, "useStatus").mockReturnValue({
    data: { state, tip: 0, caughtUp: state === "ready" },
    error: null,
    loading: false,
    refresh: vi.fn(),
  } as never);
}

function stubVault(data: { exists: boolean; locked: boolean; wallet_count: number; legacy_keystore?: boolean }) {
  vi.spyOn(hooks, "useVaultStatus").mockReturnValue({
    data,
    error: null,
    loading: false,
    refresh: vi.fn(),
  } as never);
}

// Keep Portfolio's data hooks quiet so it renders without firing real fetches.
function quietPortfolio() {
  vi.spyOn(hooks, "useBalance").mockReturnValue({ data: { lovelace: "1000000", assets: [] }, error: null, loading: false, refresh: vi.fn() } as never);
  vi.spyOn(hooks, "useDelegation").mockReturnValue({ data: null, error: null, loading: false, refresh: vi.fn() } as never);
}

afterEach(() => {
  vi.restoreAllMocks();
  window.location.hash = "";
});

test("no vault → Create Vault flow is shown", async () => {
  stubStatus("ready");
  stubVault({ exists: false, locked: true, wallet_count: 0 });
  render(<App />);
  await waitFor(() => expect(screen.getByRole("button", { name: /create vault/i })).toBeInTheDocument());
});

test("legacy keystore without a vault → migration flow is shown", async () => {
  stubStatus("ready");
  stubVault({ exists: false, locked: true, wallet_count: 0, legacy_keystore: true });
  quietPortfolio();
  vi.spyOn(client, "migrateLegacyKeystore").mockResolvedValue(walletA);

  render(<App />);
  await waitFor(() => expect(screen.getByRole("button", { name: /import wallet/i })).toBeInTheDocument());

  fireEvent.change(screen.getByLabelText(/^new vault password$/i), { target: { value: "vault-password-xyz" } });
  fireEvent.change(screen.getByLabelText(/^confirm new vault password$/i), { target: { value: "vault-password-xyz" } });
  fireEvent.change(screen.getByLabelText(/existing spending password/i), { target: { value: "spend-password-aaa" } });
  fireEvent.click(screen.getByRole("button", { name: /import wallet/i }));

  await waitFor(() =>
    expect(client.migrateLegacyKeystore).toHaveBeenCalledWith({
      name: "Wallet",
      vault_password: "vault-password-xyz",
      spend_password: "spend-password-aaa",
    }),
  );
  await waitFor(() => expect(screen.getByText("Main")).toBeInTheDocument());
});

test("vault exists but locked → Unlock screen (vault password only, no seed field)", async () => {
  stubStatus("ready");
  stubVault({ exists: true, locked: true, wallet_count: 2 });
  render(<App />);
  await waitFor(() => expect(screen.getByRole("button", { name: /^unlock$/i })).toBeInTheDocument());
  // No mnemonic/seed field on the unlock screen.
  expect(screen.queryByLabelText(/recovery phrase/i)).not.toBeInTheDocument();
  expect(screen.getByLabelText(/vault password/i)).toBeInTheDocument();
});

test("unlocking a single-wallet vault binds it and shows the main UI", async () => {
  stubStatus("ready");
  stubVault({ exists: true, locked: true, wallet_count: 1 });
  quietPortfolio();
  vi.spyOn(client, "unlockVault").mockResolvedValue([walletA]);

  render(<App />);
  fireEvent.change(screen.getByLabelText(/vault password/i), { target: { value: "vault-password-xyz" } });
  fireEvent.click(screen.getByRole("button", { name: /^unlock$/i }));

  // The sidebar and the active wallet appear.
  await waitFor(() => expect(screen.getByText("Portfolio")).toBeInTheDocument());
  expect(screen.getByText("Main")).toBeInTheDocument();
});

test("lock failure keeps the unlocked UI visible and reports the error", async () => {
  stubStatus("ready");
  stubVault({ exists: true, locked: true, wallet_count: 1 });
  quietPortfolio();
  vi.spyOn(client, "unlockVault").mockResolvedValue([walletA]);
  vi.spyOn(client, "lockVault").mockRejectedValue(new client.ApiError(0, "network error"));

  render(<App />);
  fireEvent.change(screen.getByLabelText(/vault password/i), { target: { value: "vault-password-xyz" } });
  fireEvent.click(screen.getByRole("button", { name: /^unlock$/i }));
  await waitFor(() => expect(screen.getByText("Main")).toBeInTheDocument());

  fireEvent.click(screen.getByRole("button", { name: /lock vault/i }));

  await waitFor(() => expect(screen.getByRole("alert")).toHaveTextContent("network error"));
  expect(screen.getByText("Main")).toBeInTheDocument();
  expect(screen.queryByRole("button", { name: /^unlock$/i })).not.toBeInTheDocument();
});

test("vault status failure shows a retryable error instead of the unlocked shell", async () => {
  stubStatus("ready");
  const refresh = vi.fn();
  vi.spyOn(hooks, "useVaultStatus").mockReturnValue({
    data: null,
    error: new Error("status unavailable"),
    loading: false,
    refresh,
  } as never);

  render(<App />);

  expect(screen.getByRole("alert")).toHaveTextContent("status unavailable");
  expect(screen.queryByText("Wallets")).not.toBeInTheDocument();
  fireEvent.click(screen.getByRole("button", { name: /retry/i }));
  expect(refresh).toHaveBeenCalled();
});

test("while syncing before unlock, the boot Syncing view shows instead of the vault flow", async () => {
  // The node-sync boot gate takes the whole screen while syncing and before the
  // vault is unlocked — there is nothing to operate yet. The escape hatch drops
  // into the vault flow (here: the unlock screen) for a read-only load.
  stubStatus("syncing");
  stubVault({ exists: true, locked: true, wallet_count: 1 });
  render(<App />);
  await waitFor(() =>
    expect(screen.getByText(/catching up to the chain/i)).toBeInTheDocument(),
  );
  // The vault unlock control stays hidden until the user opts in.
  expect(screen.queryByRole("button", { name: /^unlock$/i })).not.toBeInTheDocument();
  // The escape hatch reveals the vault flow (unlock).
  fireEvent.click(screen.getByRole("button", { name: /load wallet anyway/i }));
  expect(screen.getByRole("button", { name: /^unlock$/i })).toBeInTheDocument();
});

test("Send nav is disabled until the node is ready", async () => {
  stubStatus("syncing");
  stubVault({ exists: true, locked: true, wallet_count: 1 });
  quietPortfolio();
  vi.spyOn(client, "unlockVault").mockResolvedValue([walletA]);

  render(<App />);
  // While syncing the boot view is shown; opt in to reach the vault flow, then
  // unlock so the nav (and its gating) becomes visible.
  fireEvent.click(await screen.findByRole("button", { name: /load wallet anyway/i }));
  fireEvent.change(screen.getByLabelText(/vault password/i), { target: { value: "vault-password-xyz" } });
  fireEvent.click(screen.getByRole("button", { name: /^unlock$/i }));

  await waitFor(() => expect(screen.getByText("Main")).toBeInTheDocument());
  expect(screen.getByText("Send").closest("button")).toBeDisabled();
});

test("deep-linking #/send while syncing falls back to Portfolio (guard)", async () => {
  stubStatus("syncing");
  stubVault({ exists: true, locked: true, wallet_count: 1 });
  quietPortfolio();
  vi.spyOn(client, "unlockVault").mockResolvedValue([walletA]);
  window.location.hash = "#/send";

  render(<App />);
  // Past the boot Syncing view, then unlock to reach the routed content area.
  fireEvent.click(await screen.findByRole("button", { name: /load wallet anyway/i }));
  fireEvent.change(screen.getByLabelText(/vault password/i), { target: { value: "vault-password-xyz" } });
  fireEvent.click(screen.getByRole("button", { name: /^unlock$/i }));

  await waitFor(() => expect(screen.getByText("Main")).toBeInTheDocument());
  // Send screen must NOT appear until the node is ready.
  expect(screen.queryByText("Send ADA")).not.toBeInTheDocument();
});

test("an active wallet on a ready node can reach Send", async () => {
  stubStatus("ready");
  stubVault({ exists: true, locked: true, wallet_count: 1 });
  quietPortfolio();
  vi.spyOn(client, "unlockVault").mockResolvedValue([walletA]);
  window.location.hash = "#/send";

  render(<App />);
  fireEvent.change(screen.getByLabelText(/vault password/i), { target: { value: "vault-password-xyz" } });
  fireEvent.click(screen.getByRole("button", { name: /^unlock$/i }));

  await waitFor(() => expect(screen.getByText("Send ADA")).toBeInTheDocument());
});

test("switching active wallets remounts routed content and refetches read state", async () => {
  stubStatus("ready");
  stubVault({ exists: true, locked: true, wallet_count: 2 });
  vi.spyOn(client, "unlockVault").mockResolvedValue([walletA, walletB]);
  vi.spyOn(client, "activateWallet").mockResolvedValue({ ...walletB, active: true });
  const getBalance = vi.spyOn(client, "getBalance").mockResolvedValue({ lovelace: "1000000", assets: [] });
  vi.spyOn(client, "getDelegation").mockResolvedValue({
    pool_id: null,
    active: false,
    rewards_sum: "0",
    withdrawable_amount: "0",
    provisional: false,
    note: "",
  });

  render(<App />);
  fireEvent.change(screen.getByLabelText(/vault password/i), { target: { value: "vault-password-xyz" } });
  fireEvent.click(screen.getByRole("button", { name: /^unlock$/i }));

  await waitFor(() => expect(screen.getByText("Main")).toBeInTheDocument());
  await waitFor(() => expect(getBalance).toHaveBeenCalledTimes(1));

  fireEvent.click(screen.getByRole("button", { name: /Savings/i }));

  await waitFor(() => expect(client.activateWallet).toHaveBeenCalledWith("w2"));
  await waitFor(() => expect(getBalance).toHaveBeenCalledTimes(2));
});

test("a crafted hash (#/constructor) falls back to Portfolio instead of crashing", async () => {
  stubStatus("ready");
  stubVault({ exists: true, locked: true, wallet_count: 1 });
  quietPortfolio();
  vi.spyOn(client, "unlockVault").mockResolvedValue([walletA]);
  window.location.hash = "#/constructor";

  render(<App />);
  fireEvent.change(screen.getByLabelText(/vault password/i), { target: { value: "vault-password-xyz" } });
  fireEvent.click(screen.getByRole("button", { name: /^unlock$/i }));

  await waitFor(() => expect(screen.getByText("Balance")).toBeInTheDocument());
});

test("Add wallet action opens the add-wallet form", async () => {
  stubStatus("ready");
  stubVault({ exists: true, locked: true, wallet_count: 1 });
  quietPortfolio();
  vi.spyOn(client, "unlockVault").mockResolvedValue([walletA]);

  render(<App />);
  fireEvent.change(screen.getByLabelText(/vault password/i), { target: { value: "vault-password-xyz" } });
  fireEvent.click(screen.getByRole("button", { name: /^unlock$/i }));

  await waitFor(() => expect(screen.getByText("Main")).toBeInTheDocument());
  fireEvent.click(screen.getByRole("button", { name: /add wallet/i }));
  // The add-wallet flow now starts with a create/restore chooser.
  await waitFor(() =>
    expect(screen.getByRole("button", { name: /restore from recovery phrase/i })).toBeInTheDocument(),
  );
  // Navigate to the restore path to get the recovery phrase field.
  fireEvent.click(screen.getByRole("button", { name: /restore from recovery phrase/i }));
  await waitFor(() => expect(screen.getByLabelText(/recovery phrase/i)).toBeInTheDocument());
});

// --- Offline banner tests ----------------------------------------------------

test("offline banner appears when an 'offline' event is fired", async () => {
  stubStatus("ready");
  stubVault({ exists: false, locked: true, wallet_count: 0 });

  render(<App />);
  await waitFor(() => expect(screen.getByRole("button", { name: /create vault/i })).toBeInTheDocument());

  expect(screen.queryByRole("alert", { name: /offline/i })).not.toBeInTheDocument();

  act(() => {
    window.dispatchEvent(new Event("offline"));
  });

  await waitFor(() => expect(screen.getByRole("alert", { name: /offline/i })).toBeInTheDocument());
});

test("offline banner hides when an 'online' event fires after going offline", async () => {
  stubStatus("ready");
  stubVault({ exists: false, locked: true, wallet_count: 0 });

  render(<App />);
  await waitFor(() => expect(screen.getByRole("button", { name: /create vault/i })).toBeInTheDocument());

  act(() => {
    window.dispatchEvent(new Event("offline"));
  });
  await waitFor(() => expect(screen.getByRole("alert", { name: /offline/i })).toBeInTheDocument());

  act(() => {
    window.dispatchEvent(new Event("online"));
  });
  await waitFor(() => expect(screen.queryByRole("alert", { name: /offline/i })).not.toBeInTheDocument());
});

test("offline banner can be dismissed by the user", async () => {
  stubStatus("ready");
  stubVault({ exists: false, locked: true, wallet_count: 0 });

  render(<App />);
  await waitFor(() => expect(screen.getByRole("button", { name: /create vault/i })).toBeInTheDocument());

  act(() => {
    window.dispatchEvent(new Event("offline"));
  });
  await waitFor(() => expect(screen.getByRole("alert", { name: /offline/i })).toBeInTheDocument());

  fireEvent.click(screen.getByRole("button", { name: /dismiss/i }));
  expect(screen.queryByRole("alert", { name: /offline/i })).not.toBeInTheDocument();
});
