import { render, screen, waitFor, fireEvent, act, within } from "@testing-library/react";
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

// The idle auto-lock timer reads useAutoLock; default it to Off so existing
// tests (none of which exercise the idle-lock feature) never have a real
// setInterval running against them, and never fire an unmocked fetch.
function stubAutoLock(minutes = 0) {
  vi.spyOn(hooks, "useAutoLock").mockReturnValue({
    data: { minutes },
    error: null,
    loading: false,
    refresh: vi.fn(),
    setData: vi.fn(),
  } as never);
}

// Keep Portfolio's data hooks quiet so it renders without firing real fetches.
function quietPortfolio() {
  vi.spyOn(hooks, "useBalance").mockReturnValue({ data: { lovelace: "1000000", assets: [] }, error: null, loading: false, refresh: vi.fn() } as never);
  vi.spyOn(hooks, "useDelegation").mockReturnValue({ data: null, error: null, loading: false, refresh: vi.fn() } as never);
}

beforeEach(() => {
  stubAutoLock(0);
});

afterEach(() => {
  vi.restoreAllMocks();
  // Belt-and-suspenders: the idle auto-lock tests below call vi.useFakeTimers()
  // and normally switch back with vi.useRealTimers() at the end, but if such a
  // test fails/throws before reaching that line, fake timers would otherwise
  // stay installed and cascade into unrelated tests. useRealTimers() is a
  // harmless no-op when real timers are already active.
  vi.useRealTimers();
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
  // Wallet name appears in both the mobile topbar and the sidebar wallet list.
  await waitFor(() => expect(screen.getAllByText("Main").length).toBeGreaterThan(0));
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

  // Nav items and the active wallet appear; they may be present in both the
  // mobile drawer and the desktop sidebar, so use getAllByText.
  await waitFor(() => expect(screen.getAllByText("Portfolio").length).toBeGreaterThan(0));
  expect(screen.getAllByText("Main").length).toBeGreaterThan(0);
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
  await waitFor(() => expect(screen.getAllByText("Main").length).toBeGreaterThan(0));

  const sidebar = document.querySelector<HTMLElement>(".sidebar");
  expect(sidebar).not.toBeNull();
  const sidebarQueries = within(sidebar as HTMLElement);

  fireEvent.click(sidebarQueries.getByRole("button", { name: /lock vault/i }));

  await waitFor(() => expect(sidebarQueries.getByRole("alert")).toHaveTextContent("network error"));
  expect(screen.getAllByText("Main").length).toBeGreaterThan(0);
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

  await waitFor(() => expect(screen.getAllByText("Main").length).toBeGreaterThan(0));
  // Send appears in both the mobile drawer and the desktop sidebar; both must
  // be disabled while syncing — check that every "Send" button is disabled.
  expect(screen.getAllByText("Send").every((el) => el.closest("button")?.disabled)).toBe(true);
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

  await waitFor(() => expect(screen.getAllByText("Main").length).toBeGreaterThan(0));
  // Send screen must NOT appear until the node is ready.
  expect(screen.queryByText("Send ADA")).not.toBeInTheDocument();
});

test("deep-linking #/swap while syncing opens the read-only swap screen", async () => {
  stubStatus("syncing");
  stubVault({ exists: true, locked: true, wallet_count: 1 });
  vi.spyOn(client, "unlockVault").mockResolvedValue([walletA]);
  vi.spyOn(hooks, "useDexPools").mockReturnValue({
    data: { pools: [] },
    error: null,
    loading: false,
    refresh: vi.fn(),
  } as never);
  window.location.hash = "#/swap";

  render(<App />);
  fireEvent.click(await screen.findByRole("button", { name: /load wallet anyway/i }));
  fireEvent.change(screen.getByLabelText(/vault password/i), { target: { value: "vault-password-xyz" } });
  fireEvent.click(screen.getByRole("button", { name: /^unlock$/i }));

  await waitFor(() =>
    expect(screen.getByRole("heading", { name: /swap quote/i })).toBeInTheDocument(),
  );
  expect(screen.getAllByText("Swap").some((el) => el.closest("button")?.disabled === false)).toBe(true);
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

  await waitFor(() => expect(screen.getAllByText("Main").length).toBeGreaterThan(0));
  await waitFor(() => expect(getBalance).toHaveBeenCalledTimes(1));

  // Savings appears in both the mobile drawer and the desktop sidebar; click
  // the first one (either activates the same server-side wallet).
  fireEvent.click(screen.getAllByRole("button", { name: /Savings/i })[0]);

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

  await waitFor(() => expect(screen.getAllByText("Main").length).toBeGreaterThan(0));
  // "Add wallet" appears in both the mobile drawer and the desktop sidebar.
  fireEvent.click(screen.getAllByRole("button", { name: /add wallet/i })[0]);
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

// -------------------------------------------------------- idle auto-lock ---

test("idle auto-lock locks the vault after the persisted timeout with no activity", async () => {
  vi.useFakeTimers({ shouldAdvanceTime: true });
  stubStatus("ready");
  stubVault({ exists: true, locked: true, wallet_count: 1 });
  stubAutoLock(1); // 1 minute
  quietPortfolio();
  vi.spyOn(client, "unlockVault").mockResolvedValue([walletA]);
  const lockSpy = vi.spyOn(client, "lockVault").mockResolvedValue({
    exists: true,
    locked: true,
    wallet_count: 1,
  });

  render(<App />);
  fireEvent.change(screen.getByLabelText(/vault password/i), { target: { value: "vault-password-xyz" } });
  fireEvent.click(screen.getByRole("button", { name: /^unlock$/i }));
  await waitFor(() => expect(screen.getAllByText("Main").length).toBeGreaterThan(0));

  await act(async () => {
    await vi.advanceTimersByTimeAsync(60_000);
  });

  await waitFor(() => expect(lockSpy).toHaveBeenCalled());
  // Locking clears the unlocked shell and returns to the unlock screen.
  await waitFor(() => expect(screen.getByRole("button", { name: /^unlock$/i })).toBeInTheDocument());
  vi.useRealTimers();
});

test("idle auto-lock does not fire when the setting is Off", async () => {
  vi.useFakeTimers({ shouldAdvanceTime: true });
  stubStatus("ready");
  stubVault({ exists: true, locked: true, wallet_count: 1 });
  stubAutoLock(0); // Off
  quietPortfolio();
  vi.spyOn(client, "unlockVault").mockResolvedValue([walletA]);
  const lockSpy = vi.spyOn(client, "lockVault");

  render(<App />);
  fireEvent.change(screen.getByLabelText(/vault password/i), { target: { value: "vault-password-xyz" } });
  fireEvent.click(screen.getByRole("button", { name: /^unlock$/i }));
  await waitFor(() => expect(screen.getAllByText("Main").length).toBeGreaterThan(0));

  await act(async () => {
    await vi.advanceTimersByTimeAsync(30 * 60_000);
  });

  expect(lockSpy).not.toHaveBeenCalled();
  expect(screen.getAllByText("Main").length).toBeGreaterThan(0);
  vi.useRealTimers();
});

test("activity before the idle timeout elapses prevents the auto-lock", async () => {
  vi.useFakeTimers({ shouldAdvanceTime: true });
  stubStatus("ready");
  stubVault({ exists: true, locked: true, wallet_count: 1 });
  stubAutoLock(1); // 1 minute
  quietPortfolio();
  vi.spyOn(client, "unlockVault").mockResolvedValue([walletA]);
  const lockSpy = vi.spyOn(client, "lockVault").mockResolvedValue({
    exists: true,
    locked: true,
    wallet_count: 1,
  });

  render(<App />);
  fireEvent.change(screen.getByLabelText(/vault password/i), { target: { value: "vault-password-xyz" } });
  fireEvent.click(screen.getByRole("button", { name: /^unlock$/i }));
  await waitFor(() => expect(screen.getAllByText("Main").length).toBeGreaterThan(0));

  await act(async () => {
    await vi.advanceTimersByTimeAsync(50_000);
  });
  act(() => {
    window.dispatchEvent(new Event("pointerdown"));
  });
  await act(async () => {
    await vi.advanceTimersByTimeAsync(50_000); // 100s total, but only 50s since activity
  });

  expect(lockSpy).not.toHaveBeenCalled();
  expect(screen.getAllByText("Main").length).toBeGreaterThan(0);
  vi.useRealTimers();
});

// Regression test for Fix 1: App's useIdleLock and Settings' AutoLockCard used
// to each hold their own useAutoLock() instance (useAsync/useState has no
// shared cache — see api/hooks.ts), so a save made in Settings never reached
// the copy App actually feeds into useIdleLock; changing the timeout (or
// turning it Off) silently had no effect until a full reload. This test does
// NOT stub useAutoLock (unlike the other idle-lock tests above, which
// deliberately do to keep them focused) — it only mocks the fetch/client
// layer, so both the App-level read and the Settings-level save go through
// the real, shared hook instance and would fail here if the state were split
// again.
test("[Fix 1] changing the auto-lock timeout in Settings propagates to the idle timer in the same session (no reload)", async () => {
  // Undo this file's beforeEach stubAutoLock(0), which mocks hooks.useAutoLock
  // directly — this test deliberately exercises the REAL useAutoLock() hook
  // (shared, per Fix 1) in both App and Settings; only the fetch/client layer
  // below is mocked.
  vi.restoreAllMocks();
  vi.useFakeTimers({ shouldAdvanceTime: true });
  stubStatus("ready");
  stubVault({ exists: true, locked: true, wallet_count: 1 });
  quietPortfolio();
  vi.spyOn(client, "unlockVault").mockResolvedValue([walletA]);
  vi.spyOn(client, "getAutoLock").mockResolvedValue({ minutes: 1 });
  const setAutoLockSpy = vi.spyOn(client, "setAutoLock").mockResolvedValue({ minutes: 0 });
  const lockSpy = vi.spyOn(client, "lockVault").mockResolvedValue({
    exists: true,
    locked: true,
    wallet_count: 1,
  });

  render(<App />);
  fireEvent.change(screen.getByLabelText(/vault password/i), { target: { value: "vault-password-xyz" } });
  fireEvent.click(screen.getByRole("button", { name: /^unlock$/i }));
  await waitFor(() => expect(screen.getAllByText("Main").length).toBeGreaterThan(0));

  // Navigate to Settings within the SAME App instance (no remount, no reload)
  // and wait for the real useAutoLock() fetch to resolve to the persisted
  // 1-minute timeout.
  fireEvent.click(screen.getAllByRole("button", { name: "Settings" })[0]);
  const select = await screen.findByRole("combobox", { name: /lock after inactivity/i });
  await waitFor(() => expect(select).toHaveValue("1"));

  // Switch to Off through the real Settings control.
  fireEvent.change(select, { target: { value: "0" } });
  await waitFor(() => expect(setAutoLockSpy).toHaveBeenCalledWith(0));
  await waitFor(() => expect(select).toHaveValue("0"));

  // Advance well past the original 1-minute timeout with no activity. If the
  // Settings save had not propagated to App's copy of the setting (the bug),
  // useIdleLock would still be running with the stale 1-minute value and
  // lockVault would fire around the 60s mark. With the fix, App's shared
  // AsyncState now reports minutes: 0, so useIdleLock is disabled and never
  // locks the vault.
  await act(async () => {
    await vi.advanceTimersByTimeAsync(3 * 60_000);
  });

  expect(lockSpy).not.toHaveBeenCalled();
  vi.useRealTimers();
});
