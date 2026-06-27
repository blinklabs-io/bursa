import { render, screen, waitFor, fireEvent } from "@testing-library/react";
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

function stubStatus(state: string) {
  vi.spyOn(hooks, "useStatus").mockReturnValue({
    data: { state, tip: 0, caughtUp: state === "ready" },
    error: null,
    loading: false,
    refresh: vi.fn(),
  } as never);
}

function stubVault(data: { exists: boolean; locked: boolean; wallet_count: number }) {
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

test("Send nav is disabled until the node is ready", async () => {
  stubStatus("syncing");
  stubVault({ exists: true, locked: true, wallet_count: 1 });
  quietPortfolio();
  vi.spyOn(client, "unlockVault").mockResolvedValue([walletA]);

  render(<App />);
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
  // The add-wallet form (with a recovery-phrase field) appears.
  await waitFor(() => expect(screen.getByLabelText(/recovery phrase/i)).toBeInTheDocument());
});
