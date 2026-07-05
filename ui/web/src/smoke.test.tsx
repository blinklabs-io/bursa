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

afterEach(() => {
  document.documentElement.removeAttribute("data-theme");
  vi.restoreAllMocks();
});

// renderUnlockedApp stubs the data hooks + unlockVault, renders the app, and
// drives the vault-unlock form. Shared by both tests below so the theme
// variations stay focused on the thing they're actually asserting.
async function renderUnlockedApp() {
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

  // Nav items appear once the vault is unlocked and a wallet is active.
  // On mobile and desktop the nav is rendered in both the sidebar and the
  // mobile drawer, so multiple elements with the same label may be present.
  await waitFor(() => expect(screen.getAllByText("Portfolio").length).toBeGreaterThan(0));
}

test.each(["dark", "light"] as const)("renders the app shell in the %s theme", async (theme) => {
  document.documentElement.setAttribute("data-theme", theme);

  await renderUnlockedApp();

  // The document root keeps carrying the theme the app started with — the app
  // itself never touches data-theme (only src/theme.ts + the toggle do).
  expect(document.documentElement.getAttribute("data-theme")).toBe(theme);
});

test("renders the app shell once a wallet is active", async () => {
  await renderUnlockedApp();

  // Nav items appear once the vault is unlocked and a wallet is active. On
  // mobile and desktop the nav is rendered in both the sidebar and the
  // mobile drawer, so multiple elements with the same label may be present.
  expect(screen.getAllByText("Portfolio").length).toBeGreaterThan(0);
});
