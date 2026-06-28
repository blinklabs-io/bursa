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

test("renders the app shell once a wallet is active", async () => {
  vi.spyOn(hooks, "useStatus").mockReturnValue({
    data: { state: "ready", tip: 0, caughtUp: true },
    error: null,
    loading: false,
    refresh: vi.fn(),
  } as never);
  vi.spyOn(hooks, "useVaultStatus").mockReturnValue({
    data: { exists: true, locked: true, wallet_count: 1 },
    error: null,
    loading: false,
    refresh: vi.fn(),
  } as never);
  vi.spyOn(hooks, "useBalance").mockReturnValue({ data: { lovelace: "0", assets: [] }, error: null, loading: false, refresh: vi.fn() } as never);
  vi.spyOn(hooks, "useDelegation").mockReturnValue({ data: null, error: null, loading: false, refresh: vi.fn() } as never);
  vi.spyOn(client, "unlockVault").mockResolvedValue([walletA]);

  render(<App />);
  fireEvent.change(screen.getByLabelText(/vault password/i), { target: { value: "vault-password-xyz" } });
  fireEvent.click(screen.getByRole("button", { name: /^unlock$/i }));

  // Sidebar nav items appear once the vault is unlocked and a wallet is active.
  await waitFor(() => expect(screen.getByText("Portfolio")).toBeInTheDocument());
});
