import { render, screen, waitFor, fireEvent, act, within, cleanup } from "@testing-library/react";
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
  type: "full",
};

const walletB: WalletView = {
  id: "w2",
  name: "Savings",
  network: "preview",
  stake_address: "stake_test1def",
  addresses: ["addr_test1def"],
  active: false,
  type: "full",
};

const mainnetWallet: WalletView = {
  id: "w-mainnet",
  name: "Mainnet",
  network: "mainnet",
  stake_address: "stake1abc",
  addresses: ["addr1abc"],
  active: true,
  type: "full",
};

const hardwareWallet: WalletView = {
  id: "w-ledger",
  name: "Ledger",
  network: "preview",
  stake_address: "stake_test1ledger",
  addresses: ["addr_test1ledger"],
  active: true,
  type: "hardware",
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

test("deep-linking #/swap while syncing opens the mainnet read-only swap screen", async () => {
  stubStatus("syncing");
  stubVault({ exists: true, locked: true, wallet_count: 1 });
  vi.spyOn(client, "unlockVault").mockResolvedValue([mainnetWallet]);
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

test("deep-linking #/swap with a preview wallet falls back to Portfolio", async () => {
  stubStatus("ready");
  stubVault({ exists: true, locked: true, wallet_count: 1 });
  quietPortfolio();
  vi.spyOn(client, "unlockVault").mockResolvedValue([walletA]);
  const useDexPools = vi.spyOn(hooks, "useDexPools").mockReturnValue({
    data: { pools: [] },
    error: null,
    loading: false,
    refresh: vi.fn(),
  } as never);
  window.location.hash = "#/swap";

  render(<App />);
  fireEvent.change(screen.getByLabelText(/vault password/i), { target: { value: "vault-password-xyz" } });
  fireEvent.click(screen.getByRole("button", { name: /^unlock$/i }));

  await waitFor(() => expect(screen.getByText("Balance")).toBeInTheDocument());
  expect(screen.queryByRole("heading", { name: /swap quote/i })).not.toBeInTheDocument();
  expect(screen.getAllByText("Swap").every((el) => el.closest("button")?.disabled)).toBe(true);
  expect(useDexPools).not.toHaveBeenCalled();
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

test("read_only wallet cannot enter the regular Send flow", async () => {
  stubStatus("ready");
  stubVault({ exists: true, locked: true, wallet_count: 1 });
  quietPortfolio();
  vi.spyOn(client, "unlockVault").mockResolvedValue([{ ...walletA, type: "read_only" }]);
  window.location.hash = "#/send";

  render(<App />);
  fireEvent.change(screen.getByLabelText(/vault password/i), { target: { value: "vault-password-xyz" } });
  fireEvent.click(screen.getByRole("button", { name: /^unlock$/i }));

  await waitFor(() => expect(screen.getByText("Balance")).toBeInTheDocument());
  expect(screen.queryByText("Send ADA")).not.toBeInTheDocument();
});

test("a multi-signature wallet sends by collecting witnesses, not by signing", async () => {
  // It used to be barred from Send entirely, which was wrong: it can spend, it
  // just gathers the other signatures first. Send routes it to that flow.
  stubStatus("ready");
  stubVault({ exists: true, locked: true, wallet_count: 1 });
  quietPortfolio();
  vi.spyOn(client, "unlockVault").mockResolvedValue([
    {
      ...walletA,
      type: "multi_signature",
      stake_address: "",
      addresses: ["addr_test1wqscript"],
      multisig: {
        id: walletA.id,
        label: "Treasury",
        network: "preview",
        policy: { threshold: 2, participants: [{ key_hash_hex: "a".repeat(56) }] },
        script_cbor: "8201",
        script_address: "addr_test1wqscript",
      },
    },
  ]);
  window.location.hash = "#/send";

  render(<App />);
  fireEvent.change(screen.getByLabelText(/vault password/i), { target: { value: "vault-password-xyz" } });
  fireEvent.click(screen.getByRole("button", { name: /^unlock$/i }));

  // The collect-witnesses flow, not the ordinary one.
  expect(await screen.findByRole("button", { name: /build transaction/i })).toBeInTheDocument();
  expect(screen.queryByText("Send ADA")).not.toBeInTheDocument();
});

test("Settings identifies a hardware wallet as using on-device signing", async () => {
  stubStatus("ready");
  stubVault({ exists: true, locked: true, wallet_count: 1 });
  vi.spyOn(client, "unlockVault").mockResolvedValue([hardwareWallet]);
  window.location.hash = "#/settings";

  render(<App />);
  fireEvent.change(screen.getByLabelText(/vault password/i), { target: { value: "vault-password-xyz" } });
  fireEvent.click(screen.getByRole("button", { name: /^unlock$/i }));

  expect(await screen.findByText(/hardware wallet.*on-device signing/i)).toBeInTheDocument();
  expect(screen.queryByText(/read.?only/i)).not.toBeInTheDocument();
});

test("a seedless multi-signature wallet submits with external witnesses only", async () => {
  // The active wallet IS the script account now, so this arrives through Send
  // rather than through a screen listing accounts.
  stubStatus("ready");
  stubVault({ exists: true, locked: true, wallet_count: 1 });
  quietPortfolio();
  vi.spyOn(client, "unlockVault").mockResolvedValue([
    {
      ...hardwareWallet,
      type: "multi_signature",
      stake_address: "",
      addresses: ["addr_test1wqscriptaddressxyz"],
      multisig: {
        id: "acct1",
        label: "Treasury",
        network: "preview",
        policy: { threshold: 1, participants: [{ key_hash_hex: "a".repeat(56) }] },
        script_cbor: "8200",
        script_address: "addr_test1wqscriptaddressxyz",
      },
    },
  ]);
  vi.spyOn(client, "multiSigBuild").mockResolvedValue({
    unsigned_tx_cbor: "84a400",
    required_signers: ["a".repeat(56)],
    threshold: 1,
  });
  const submit = vi.spyOn(client, "multiSigSubmit").mockResolvedValue({ tx_hash: "feedface" });
  window.location.hash = "#/send";

  render(<App />);
  fireEvent.change(screen.getByLabelText(/vault password/i), { target: { value: "vault-password-xyz" } });
  fireEvent.click(screen.getByRole("button", { name: /^unlock$/i }));

  fireEvent.change(await screen.findByLabelText(/recipient address/i), {
    target: { value: "addr_test1recipient" },
  });
  fireEvent.change(screen.getByLabelText(/amount \(ada\)/i), { target: { value: "1" } });
  fireEvent.click(screen.getByRole("button", { name: /build transaction/i }));

  expect(await screen.findByText(/0 of 1 signed/i)).toBeInTheDocument();
  // Seedless: no local signing offered.
  expect(screen.queryByRole("button", { name: /sign here/i })).not.toBeInTheDocument();
  fireEvent.change(screen.getByLabelText(/co-signer witness/i), { target: { value: "81a0external" } });
  fireEvent.click(screen.getByRole("button", { name: /add witness/i }));
  fireEvent.click(await screen.findByRole("button", { name: /^submit$/i }));

  await waitFor(() =>
    expect(submit).toHaveBeenCalledWith("acct1", {
      unsigned_tx_cbor: "84a400",
      witnesses: ["81a0external"],
    }),
  );
});

test("the old #/multisig link lands on the spend flow", async () => {
  stubStatus("ready");
  stubVault({ exists: true, locked: true, wallet_count: 1 });
  quietPortfolio();
  vi.spyOn(client, "unlockVault").mockResolvedValue([
    {
      ...walletA,
      type: "multi_signature",
      stake_address: "",
      addresses: ["addr_test1wqscript"],
      multisig: {
        id: walletA.id,
        label: "Treasury",
        network: "preview",
        policy: { threshold: 2, participants: [{ key_hash_hex: "a".repeat(56) }] },
        script_cbor: "8201",
        script_address: "addr_test1wqscript",
      },
    },
  ]);
  window.location.hash = "#/multisig";

  render(<App />);
  fireEvent.change(screen.getByLabelText(/vault password/i), { target: { value: "vault-password-xyz" } });
  fireEvent.click(screen.getByRole("button", { name: /^unlock$/i }));

  expect(await screen.findByRole("button", { name: /build transaction/i })).toBeInTheDocument();
});

test("deep-linking #/import with an active wallet renders the Import Transaction screen", async () => {
  stubStatus("ready");
  stubVault({ exists: true, locked: true, wallet_count: 1 });
  quietPortfolio();
  vi.spyOn(client, "unlockVault").mockResolvedValue([walletA]);
  window.location.hash = "#/import";

  render(<App />);
  fireEvent.change(screen.getByLabelText(/vault password/i), { target: { value: "vault-password-xyz" } });
  fireEvent.click(screen.getByRole("button", { name: /^unlock$/i }));

  await waitFor(() =>
    expect(screen.getByRole("heading", { name: /import transaction/i })).toBeInTheDocument(),
  );
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

// Prototype-pollution guard: a crafted hash whose name collides with an
// inherited Object.prototype member must resolve through the production ROUTES
// Map (app.tsx) to a real, absent key and fall back to Portfolio — never render
// an inherited member as a "screen" nor crash. Exercised end-to-end here (not
// against a hand-built Map) so the check is bound to the code that ships.
test.each(["#/__proto__", "#/constructor"])(
  "a crafted hash (%s) falls back to Portfolio instead of crashing",
  async (hash) => {
    stubStatus("ready");
    stubVault({ exists: true, locked: true, wallet_count: 1 });
    quietPortfolio();
    vi.spyOn(client, "unlockVault").mockResolvedValue([walletA]);
    window.location.hash = hash;

    render(<App />);
    fireEvent.change(screen.getByLabelText(/vault password/i), { target: { value: "vault-password-xyz" } });
    fireEvent.click(screen.getByRole("button", { name: /^unlock$/i }));

    await waitFor(() => expect(screen.getByText("Balance")).toBeInTheDocument());
  },
);

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

// --- Absorbed destinations ------------------------------------------------

// Unlocks with the given wallet and returns the desktop sidebar, so nav
// assertions are not confused by the mobile drawer rendering the same labels.
async function unlockAndGetSidebar(wallet: WalletView): Promise<HTMLElement> {
  stubStatus("ready");
  stubVault({ exists: true, locked: true, wallet_count: 1 });
  quietPortfolio();
  vi.spyOn(client, "unlockVault").mockResolvedValue([{ ...wallet, active: true }]);

  render(<App />);
  fireEvent.change(screen.getByLabelText(/vault password/i), { target: { value: "vault-password-xyz" } });
  fireEvent.click(screen.getByRole("button", { name: /^unlock$/i }));

  await waitFor(() => expect(document.querySelector(".sidebar")).not.toBeNull());
  return document.querySelector(".sidebar") as HTMLElement;
}

test("the nav carries only destinations, not actions or housekeeping", async () => {
  const sidebar = await unlockAndGetSidebar(walletA);
  const q = within(sidebar);

  // An EXACT set, deliberately not a filtered count. Filtering to the expected
  // labels and then counting them can only catch a removal: a screen that adds
  // a sixth destination is filtered out of its own assertion and sails through.
  expect(
    Array.from(sidebar.querySelectorAll(".nav-item")).map((b) => b.textContent),
  ).toEqual(["Portfolio", "Activity", "Stake", "Swap", "Settings"]);

  // Send and Receive are actions on the Portfolio; the rest are Settings
  // panels. None of them earns a nav entry.
  // Multi-sig joined them: it is a wallet in the switcher now, spent from
  // through Send, so it no longer earns a destination either.
  // Import Tx, Offline and Pool Ops left too: the first two are reached from
  // the send flow and the palette, and pool operations appear only for the
  // minority who turn operator mode on.
  for (const gone of [
    "Send", "Receive", "Contacts", "Sign", "Verify",
    "Diagnostics", "Multi-sig", "Import Tx", "Offline", "Operate", "Pool Ops",
  ]) {
    expect(q.queryByRole("button", { name: gone })).not.toBeInTheDocument();
  }
});

// With the nav down to five destinations, the palette is how everything else is
// found — so it gets the same exact-set treatment as the nav above. A screen
// that is routed but listed in neither surface is unreachable, which is a real
// failure mode here, not a hypothetical one.
async function openPalette(wallet: WalletView): Promise<HTMLElement> {
  const sidebar = await unlockAndGetSidebar(wallet);
  fireEvent.click(within(sidebar).getByRole("button", { name: /search/i }));
  return await screen.findByRole("dialog", { name: /command palette/i });
}

test("the palette lists every destination the nav no longer carries", async () => {
  const palette = await openPalette(walletA);

  expect(
    Array.from(palette.querySelectorAll('[role="option"]')).map((o) =>
      o.id.replace("palette-cmd-", ""),
    ),
  ).toEqual([
    "portfolio", "activity", "stake", "swap", "settings",
    "send", "receive", "import", "offline",
    "contacts", "sign", "verify", "diagnostics",
    "operate", "add-wallet", "lock",
  ]);
});

// Being listed is not the same as working. These three have no nav entry at
// all, so the palette is the only way in: assert the command is enabled, that
// activating it navigates, and that the palette gets out of the way.
test.each([
  ["Address book", "#/contacts"],
  ["Node diagnostics", "#/diagnostics"],
  ["Sign a transaction offline", "#/offline"],
])("%s is actually reachable from the palette", async (label, hash) => {
  const palette = await openPalette(walletA);

  const cmd = within(palette).getByRole("option", { name: new RegExp(label, "i") });
  expect(cmd).toBeEnabled();

  fireEvent.click(cmd);

  await waitFor(() => expect(window.location.hash).toBe(hash));
  await waitFor(() => expect(document.querySelector(".palette")).toBeNull());
});

test("Send and Receive are offered on the balance they act on", async () => {
  await unlockAndGetSidebar(walletA);

  const main = document.querySelector("main") as HTMLElement;
  const q = within(main);
  expect(await q.findByRole("button", { name: "Send" })).toBeInTheDocument();
  expect(q.getByRole("button", { name: "Receive" })).toBeInTheDocument();
});

test("Send on the Portfolio actually reaches the send flow", async () => {
  // Send is no longer in the nav, so this button is the only way in. Asserting
  // it renders is not enough — it has to be enabled and it has to navigate.
  await unlockAndGetSidebar(walletA);
  const main = document.querySelector("main") as HTMLElement;

  const send = await within(main).findByRole("button", { name: "Send" });
  expect(send).toBeEnabled();

  fireEvent.click(send);

  await waitFor(() => expect(window.location.hash).toBe("#/send"));
  expect(await screen.findByText(/send ada/i)).toBeInTheDocument();
});

test("a wallet that cannot spend gets a disabled Send, not a dead end", async () => {
  await unlockAndGetSidebar({ ...walletA, type: "read_only" });
  const main = document.querySelector("main") as HTMLElement;

  expect(await within(main).findByRole("button", { name: "Send" })).toBeDisabled();
  // Receive needs nothing, so it stays available.
  expect(within(main).getByRole("button", { name: "Receive" })).toBeEnabled();
});

test("the routes the absorbed screens used to own still resolve", async () => {
  // Old links and bookmarks must not break just because the screen moved.
  // Asserting the nav highlight alone is not enough: every one of these
  // highlights Settings, so a mis-mapped SETTINGS_ROUTES entry would sail
  // through while opening the wrong panel. Check the panel that opened.
  for (const [hash, navEntry, panel] of [
    ["#/contacts", "Settings", "Address book"],
    ["#/sign", "Settings", "Tools"],
    ["#/verify", "Settings", "Tools"],
    ["#/diagnostics", "Settings", "Diagnostics"],
    ["#/settings", "Settings", "General"],
  ] as const) {
    window.location.hash = hash;
    const sidebar = await unlockAndGetSidebar(walletA);

    expect(within(sidebar).getByRole("button", { name: navEntry })).toHaveAttribute(
      "aria-current",
      "page",
    );
    expect(await screen.findByRole("tab", { name: panel })).toHaveAttribute(
      "aria-selected",
      "true",
    );

    cleanup();
    vi.restoreAllMocks();
    stubAutoLock(0);
  }
});

test("#/receive opens Receive while the nav still points at Portfolio", async () => {
  // Send and Receive are Portfolio actions, so the highlight is deliberate.
  vi.spyOn(hooks, "useAddresses").mockReturnValue({
    data: { receive: ["addr_test1abc"], used: [], next_unused: "addr_test1abc" },
    error: null,
    loading: false,
    refresh: vi.fn(),
  } as never);
  window.location.hash = "#/receive";
  const sidebar = await unlockAndGetSidebar(walletA);

  expect(within(sidebar).getByRole("button", { name: "Portfolio" })).toHaveAttribute(
    "aria-current",
    "page",
  );
  expect(await screen.findByText(/next unused address/i)).toBeInTheDocument();
});

test("a fault in Receive is reported as Receive, not as Portfolio", async () => {
  // The nav highlight collapses receive onto Portfolio, so the boundary label
  // has to come from somewhere else — otherwise a crash here sends the reader
  // to a screen that is working fine. Exercise the boundary rather than
  // asserting the label indirectly.
  vi.spyOn(console, "error").mockImplementation(() => {});
  vi.spyOn(hooks, "useAddresses").mockImplementation(() => {
    throw new Error("addresses blew up");
  });
  window.location.hash = "#/receive";
  await unlockAndGetSidebar(walletA);

  const alert = await screen.findByRole("alert");
  expect(alert).toHaveTextContent(/the receive screen could not be displayed/i);
  expect(alert).not.toHaveTextContent(/portfolio/i);
});

test("a route that falls back to Portfolio is reported as Portfolio", async () => {
  // #/swap on a testnet wallet declines the request and renders Portfolio, so
  // naming the route the user asked for would point at a screen that never
  // appeared.
  vi.spyOn(console, "error").mockImplementation(() => {});
  // Not useBalance: the unlock helper stubs that one, and its stub would win.
  vi.spyOn(hooks, "useAssetMetadata").mockImplementation(() => {
    throw new Error("metadata blew up");
  });
  window.location.hash = "#/swap";
  await unlockAndGetSidebar(walletA); // preview network → canSwap is false

  const alert = await screen.findByRole("alert");
  expect(alert).toHaveTextContent(/the portfolio screen could not be displayed/i);
  expect(alert).not.toHaveTextContent(/swap screen/i);
});

// --- Command palette -------------------------------------------------------

test("the palette has a visible trigger, not just a shortcut", async () => {
  // A palette nobody knows about is a palette nobody uses. It must be reachable
  // by pointing and clicking, and the trigger teaches the key.
  const sidebar = await unlockAndGetSidebar(walletA);

  const trigger = within(sidebar).getByRole("button", { name: /search/i });
  expect(trigger).toBeInTheDocument();
  // Non-Mac platform (jsdom default): the handler binds Ctrl-K too, so the hint
  // must not promise a modifier this keyboard does not have.
  expect(trigger).toHaveTextContent("Ctrl+K");

  fireEvent.click(trigger);
  expect(await screen.findByRole("dialog", { name: /command palette/i })).toBeInTheDocument();
});

test("the palette trigger shows the Mac shortcut on a Mac", async () => {
  // platform is an inherited getter on Navigator.prototype, not an own
  // property, so getOwnPropertyDescriptor returns undefined here and there is
  // nothing to put back — the override has to be deleted instead, or "MacIntel"
  // leaks into every later test in this file.
  const original = Object.getOwnPropertyDescriptor(window.navigator, "platform");
  Object.defineProperty(window.navigator, "platform", {
    value: "MacIntel",
    configurable: true,
  });
  try {
    const sidebar = await unlockAndGetSidebar(walletA);
    const trigger = within(sidebar).getByRole("button", { name: /search/i });
    expect(trigger).toHaveTextContent("⌘K");
  } finally {
    if (original) {
      Object.defineProperty(window.navigator, "platform", original);
    } else {
      delete (window.navigator as unknown as Record<string, unknown>).platform;
    }
  }
});

test("the palette hint stays platform-correct after the Mac test", () => {
  // Guards the restore above: a leaked "MacIntel" override would make this
  // read as a Mac long after that test finished.
  expect(/Mac|iPhone|iPad/.test(window.navigator.platform)).toBe(false);
});

test("Cmd-K opens the palette and reaches a screen that left the nav", async () => {
  await unlockAndGetSidebar(walletA);

  fireEvent.keyDown(window, { key: "k", metaKey: true });
  const dialog = await screen.findByRole("dialog", { name: /command palette/i });

  // Offline has no nav entry any more; the palette is one of its routes in.
  fireEvent.change(within(dialog).getByRole("combobox"), { target: { value: "air gap" } });
  fireEvent.click(within(dialog).getByRole("option", { name: /offline/i }));

  await waitFor(() => expect(window.location.hash).toBe("#/offline"));
});

test("pool operations stay out of the nav until turned on", async () => {
  const sidebar = await unlockAndGetSidebar(walletA);
  expect(within(sidebar).queryByRole("button", { name: "Pool Ops" })).not.toBeInTheDocument();

  // Reachable regardless — hidden from the nav is not hidden from the wallet.
  fireEvent.keyDown(window, { key: "k", metaKey: true });
  const dialog = await screen.findByRole("dialog", { name: /command palette/i });
  fireEvent.change(within(dialog).getByRole("combobox"), { target: { value: "pool" } });
  expect(within(dialog).getByRole("option", { name: /stake pool operations/i })).toBeInTheDocument();
});

test("operator mode puts Pool Ops in the nav", async () => {
  window.localStorage.setItem("bursa.operatorMode", "1");
  try {
    const sidebar = await unlockAndGetSidebar(walletA);
    expect(within(sidebar).getByRole("button", { name: "Pool Ops" })).toBeInTheDocument();
  } finally {
    window.localStorage.removeItem("bursa.operatorMode");
  }
});

test("a multi-signature wallet with an unreadable policy cannot spend, and says why", async () => {
  // The wallet type says multi_signature but the policy did not decode, so
  // there is no spend flow. Letting canSend say otherwise would drop it into
  // the seed-based one, which cannot work for a script wallet.
  stubStatus("ready");
  stubVault({ exists: true, locked: true, wallet_count: 1 });
  quietPortfolio();
  vi.spyOn(client, "unlockVault").mockResolvedValue([
    {
      ...walletA,
      type: "multi_signature",
      stake_address: "",
      addresses: ["addr_test1wqscript"],
      multisig_error: "This account's signing policy could not be read, so it cannot spend. Its funds are safe.",
    },
  ]);

  render(<App />);
  fireEvent.change(screen.getByLabelText(/vault password/i), { target: { value: "vault-password-xyz" } });
  fireEvent.click(screen.getByRole("button", { name: /^unlock$/i }));

  await waitFor(() => expect(document.querySelector(".sidebar")).not.toBeNull());
  const main = document.querySelector("main") as HTMLElement;
  expect(await within(main).findByRole("alert")).toHaveTextContent(/policy could not be read/i);
  expect(within(main).getByRole("button", { name: "Send" })).toBeDisabled();
  // Receiving is unaffected — the address is still valid.
  expect(within(main).getByRole("button", { name: "Receive" })).toBeEnabled();
});

test("turning on operator mode adds Pool Ops without a reload", async () => {
  // The nav is built by App, so a preference written only inside Settings would
  // not show up until some unrelated re-render.
  const sidebar = await unlockAndGetSidebar(walletA);
  expect(within(sidebar).queryByRole("button", { name: "Pool Ops" })).not.toBeInTheDocument();

  try {
    fireEvent.click(within(sidebar).getByRole("button", { name: "Settings" }));
    fireEvent.click(await screen.findByRole("button", { name: /show pool operations/i }));

    expect(await within(sidebar).findByRole("button", { name: "Pool Ops" })).toBeInTheDocument();
  } finally {
    // Restore even when an assertion above throws: otherwise operator mode
    // leaks into every later test in this file.
    window.localStorage.removeItem("bursa.operatorMode");
  }
});
