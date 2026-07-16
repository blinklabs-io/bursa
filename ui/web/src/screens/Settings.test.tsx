import { act, render, screen, fireEvent, waitFor } from "@testing-library/react";
import { Settings } from "./Settings";
import * as hooks from "../api/hooks";
import type { AsyncState } from "../api/hooks";
import * as client from "../api/client";
import * as connectorApi from "../api/connector";
import type {
  Account,
  HistoryExpirySetting,
  AutoLockSetting,
  TPMStatus,
  ConnectorState,
  PendingPairing,
} from "../api/types";

const mockAccount: Account = {
  network: "preview",
  stake_address: "stake_test1uzqxyz1234567890abcdefghijklmnopqrstuvwxyz",
  receive_addresses: ["addr_test1abc"],
};

const defaultConnectorState: ConnectorState = {
  paired: false,
  extension_id: "",
  origins: [],
};

function mockStatus(state: string, tip = 12345, caughtUp = false) {
  vi.spyOn(hooks, "useStatus").mockReturnValue({
    data: { state, tip, caughtUp },
    error: null,
    loading: false,
    refresh: vi.fn(),
  } as never);
}

// The Lean Storage card reads useHistoryExpiry; default it to a loaded
// disabled/no-restart state so the existing Settings assertions are unaffected.
function mockHistoryExpiry(setting: HistoryExpirySetting | null, loading = false) {
  vi.spyOn(hooks, "useHistoryExpiry").mockReturnValue({
    data: setting,
    error: null,
    loading,
    refresh: vi.fn(),
  } as never);
}

// Settings no longer calls useAutoLock() itself — App owns the single shared
// instance and passes its AsyncState down as the `autoLock` prop (see Fix 1:
// a second independent useAutoLock() call inside Settings/AutoLockCard would
// never see a save made through the other instance). Tests build that
// AsyncState directly and pass it via the `autoLock` prop; default it to a
// loaded state so existing Settings assertions are unaffected.
let autoLockState: AsyncState<AutoLockSetting>;

function mockAutoLock(setting: AutoLockSetting | null, loading = false) {
  autoLockState = {
    data: setting,
    error: null,
    loading,
    refresh: vi.fn(),
    setData: vi.fn(),
  };
}

// renderSettings wraps render(<Settings .../>) with the module's current
// autoLockState so every call site doesn't need to thread it explicitly.
function renderSettings(props: Partial<Pick<Parameters<typeof Settings>[0], "account" | "walletType">> = {}) {
  return render(
    <Settings
      account={props.account ?? mockAccount}
      walletType={props.walletType ?? "read_only"}
      autoLock={autoLockState}
    />,
  );
}

function mockTPMStatus(tpmStatus: TPMStatus) {
  vi.spyOn(hooks, "useTPMStatus").mockReturnValue({
    data: tpmStatus,
    error: null,
    loading: false,
    refresh: vi.fn(),
    setData: vi.fn(),
  } as never);
}

function mockConnector(
  state: ConnectorState = defaultConnectorState,
  pending: PendingPairing[] = [],
) {
  vi.spyOn(connectorApi, "getConnectorState").mockResolvedValue(state);
  vi.spyOn(connectorApi, "pendingPairings").mockResolvedValue(pending);
}

const tpmAvailable: TPMStatus = { available: true, enabled: false, pcrBound: false };
const tpmUnavailable: TPMStatus = { available: false, reason: "tpm: no device found", enabled: false, pcrBound: false };
const tpmEnabled: TPMStatus = { available: true, enabled: true, pcrBound: false };
const tpmEnabledUnavailable: TPMStatus = { available: false, reason: "tpm: no device found", enabled: true, pcrBound: false };
const tpmEnabledPCR: TPMStatus = { available: true, enabled: true, pcrBound: true };

// Default-mock both hooks for every test so tests that don't exercise those
// cards never fire an unmocked async fetch (which triggers act() warnings).
// Individual tests override as needed.
beforeEach(() => {
  mockHistoryExpiry({ enabled: false, restart_required: false });
  mockAutoLock({ minutes: 15 });
  mockTPMStatus(tpmUnavailable);
  mockConnector();
});

afterEach(() => {
  vi.restoreAllMocks();
  vi.useRealTimers();
});

test("(a) renders network from account prop", () => {
  mockStatus("ready", 12345, true);
  renderSettings();
  expect(screen.getByText("preview")).toBeInTheDocument();
});

test("(b) renders stake address in monospace and a CopyButton for it", async () => {
  const writeText = vi.fn().mockResolvedValue(undefined);
  Object.assign(navigator, { clipboard: { writeText } });
  mockStatus("ready", 12345, true);

  renderSettings();

  // The stake address should appear in the document
  expect(screen.getByText(mockAccount.stake_address)).toBeInTheDocument();
  // The copy button must copy the FULL stake address.
  fireEvent.click(screen.getByRole("button", { name: /copy/i }));
  expect(writeText).toHaveBeenCalledWith(mockAccount.stake_address);
  expect(await screen.findByText("Copied")).toBeInTheDocument();
});

test("(c) renders sync state pill from useStatus", () => {
  mockStatus("syncing", 10000, false);
  renderSettings();
  // The sync state must be visible
  expect(screen.getByText("syncing")).toBeInTheDocument();
});

test("(d) renders tip block number from useStatus", () => {
  mockStatus("ready", 99999, true);
  renderSettings();
  expect(screen.getByText("99999")).toBeInTheDocument();
});

test("(e) caughtUp=true shows a caught-up indicator", () => {
  mockStatus("ready", 12345, true);
  renderSettings();
  expect(screen.getByText(/caught.?up/i)).toBeInTheDocument();
});

test("(f) caughtUp=false does NOT show caught-up indicator", () => {
  mockStatus("syncing", 12345, false);
  renderSettings();
  expect(screen.queryByText(/caught.?up/i)).toBeNull();
});

test("(g) full wallet type shows spending enabled", () => {
  mockStatus("ready", 12345, true);
  renderSettings({ walletType: "full" });
  expect(screen.getByText(/full wallet.*spending enabled/i)).toBeInTheDocument();
});

test("(h) read-only wallet type shows 'Read-only'", () => {
  mockStatus("ready", 12345, true);
  renderSettings();
  expect(screen.getByText(/read.?only/i)).toBeInTheDocument();
});

test("hardware wallet shows on-device signing instead of 'Read-only'", () => {
  mockStatus("ready", 12345, true);
  renderSettings({ walletType: "hardware" });
  expect(screen.getByText(/hardware wallet.*on-device signing/i)).toBeInTheDocument();
  expect(screen.queryByText(/read.?only/i)).not.toBeInTheDocument();
});

test("multi-signature wallet type is identified explicitly", () => {
  mockStatus("ready", 12345, true);
  renderSettings({ walletType: "multi_signature" });
  expect(screen.getByText(/multi-signature wallet/i)).toBeInTheDocument();
});

test("(i) loading state from useStatus renders gracefully", () => {
  vi.spyOn(hooks, "useStatus").mockReturnValue({
    data: null,
    error: null,
    loading: true,
    refresh: vi.fn(),
    setData: vi.fn(),
  } as never);
  renderSettings();
  // Should not crash; network card still shows
  expect(screen.getByText("preview")).toBeInTheDocument();
});

// ---------------------------------------------------------- lean storage ---

test("(j) lean storage toggle reflects the persisted enabled state", () => {
  mockStatus("ready", 12345, true);
  mockHistoryExpiry({ enabled: true, restart_required: false });
  renderSettings();
  const toggle = screen.getByRole("switch", { name: /lean storage/i });
  expect(toggle).toBeChecked();
  expect(screen.getByText(/enabled/i)).toBeInTheDocument();
});

test("(k) lean storage renders the tradeoff copy", () => {
  mockStatus("ready", 12345, true);
  renderSettings();
  expect(screen.getByText(/saves significant disk space/i)).toBeInTheDocument();
  expect(screen.getByText(/your mithril snapshot is kept/i)).toBeInTheDocument();
  expect(screen.getByText(/one-way until re-sync/i)).toBeInTheDocument();
});

test("(l) toggling lean storage PUTs the new value and shows restart note", async () => {
  mockStatus("ready", 12345, true);
  mockHistoryExpiry({ enabled: false, restart_required: false });
  const spy = vi
    .spyOn(client, "setHistoryExpiry")
    .mockResolvedValue({ enabled: true, restart_required: true });

  renderSettings();
  const toggle = screen.getByRole("switch", { name: /lean storage/i });
  fireEvent.click(toggle);

  await waitFor(() => expect(spy).toHaveBeenCalledWith(true));
  await waitFor(() => expect(toggle).not.toBeDisabled());
  expect(toggle).toBeChecked();
  // The live restart note (role=status) must appear after a save that returns
  // restart_required=true. findByRole is used here because the static copy
  // section also contains the same text ("Takes effect after a node restart."),
  // and findByText would match both elements.
  expect(await screen.findByRole("status")).toHaveTextContent(/takes effect after a node restart/i);
});

test("(m) failed lean storage update rolls back and surfaces the error", async () => {
  mockStatus("ready", 12345, true);
  mockHistoryExpiry({ enabled: false, restart_required: false });
  const spy = vi
    .spyOn(client, "setHistoryExpiry")
    .mockRejectedValue(new client.ApiError(500, "disk full"));

  renderSettings();
  const toggle = screen.getByRole("switch", { name: /lean storage/i });
  fireEvent.click(toggle);

  await waitFor(() => expect(spy).toHaveBeenCalledWith(true));
  await waitFor(() => expect(toggle).not.toBeDisabled());
  expect(toggle).not.toBeChecked();
  expect(screen.getByRole("alert")).toHaveTextContent(/disk full/i);
});

test("(n) failed initial lean storage load renders unavailable", () => {
  mockStatus("ready", 12345, true);
  vi.spyOn(hooks, "useHistoryExpiry").mockReturnValue({
    data: null,
    error: new Error("settings unavailable"),
    loading: false,
    refresh: vi.fn(),
    setData: vi.fn(),
  } as never);

  renderSettings();
  const toggle = screen.getByRole("switch", { name: /lean storage/i });
  expect(toggle).toBeDisabled();
  expect(screen.getByText(/^Unavailable$/)).toBeInTheDocument();
  expect(screen.queryByText(/^disabled$/i)).toBeNull();
  expect(screen.getByRole("alert")).toHaveTextContent(/settings unavailable/i);
});

test("(o) a persisted restart_required surfaces the restart note", () => {
  mockStatus("ready", 12345, true);
  mockHistoryExpiry({ enabled: true, restart_required: true });
  renderSettings();
  // The restart note appears both in the live status line (role=status) and as
  // the final bullet of the copy; assert the live status one specifically.
  expect(screen.getByRole("status")).toHaveTextContent(/takes effect after a node restart/i);
});

// ------------------------------------------------------------- auto-lock ---

test("(al1) auto-lock select reflects the persisted timeout", () => {
  mockStatus("ready", 12345, true);
  mockAutoLock({ minutes: 30 });
  renderSettings();
  const select = screen.getByRole("combobox", { name: /lock after inactivity/i });
  expect(select).toHaveValue("30");
  expect(screen.getByText(/locks after 30 minutes/i)).toBeInTheDocument();
});

test("(al2) auto-lock 'Off' (0) is rendered distinctly", () => {
  mockStatus("ready", 12345, true);
  mockAutoLock({ minutes: 0 });
  renderSettings();
  const select = screen.getByRole("combobox", { name: /lock after inactivity/i });
  expect(select).toHaveValue("0");
  expect(screen.getByText(/the vault will not auto-lock/i)).toBeInTheDocument();
});

test("(al3) changing the auto-lock select PUTs the new value", async () => {
  mockStatus("ready", 12345, true);
  mockAutoLock({ minutes: 15 });
  const saved = { minutes: 5 } as const;
  const spy = vi.spyOn(client, "setAutoLock").mockResolvedValue(saved);

  renderSettings();
  const select = screen.getByRole("combobox", { name: /lock after inactivity/i });
  fireEvent.change(select, { target: { value: "5" } });

  await waitFor(() => expect(spy).toHaveBeenCalledWith(5));
  await waitFor(() => expect(autoLockState.setData).toHaveBeenCalledWith(saved));
  await waitFor(() => expect(select).toHaveValue("5"));
  expect(screen.getByText(/locks after 5 minutes/i)).toBeInTheDocument();
});

test("(al4) failed auto-lock update rolls back and surfaces the error", async () => {
  mockStatus("ready", 12345, true);
  mockAutoLock({ minutes: 15 });
  const spy = vi
    .spyOn(client, "setAutoLock")
    .mockRejectedValue(new client.ApiError(500, "disk full"));

  renderSettings();
  const select = screen.getByRole("combobox", { name: /lock after inactivity/i });
  fireEvent.change(select, { target: { value: "5" } });

  await waitFor(() => expect(spy).toHaveBeenCalledWith(5));
  await waitFor(() => expect(select).toHaveValue("15"));
  expect(screen.getByRole("alert")).toHaveTextContent(/disk full/i);
});

test("(al5) failed initial auto-lock load renders unavailable", () => {
  mockStatus("ready", 12345, true);
  autoLockState = {
    data: null,
    error: new Error("settings unavailable"),
    loading: false,
    refresh: vi.fn(),
    setData: vi.fn(),
  };

  renderSettings();
  const select = screen.getByRole("combobox", { name: /lock after inactivity/i });
  expect(select).toBeDisabled();
  expect(screen.getAllByText(/unavailable/i).length).toBeGreaterThan(0);
});

// --- Hardware security (TPM) card -----------------------------------------

test("(j0) TPM card renders a loading state while status is fetching", () => {
  mockStatus("ready");
  vi.spyOn(hooks, "useTPMStatus").mockReturnValue({
    data: null,
    error: null,
    loading: true,
    refresh: vi.fn(),
    setData: vi.fn(),
  } as never);
  renderSettings();
  // The card must still be present (not gated away) and show a loading hint.
  expect(screen.getByText("Hardware security")).toBeInTheDocument();
  const loadings = screen.getAllByText(/loading/i);
  expect(loadings.length).toBeGreaterThan(0);
});

test("(j1) TPM card renders an error/unavailable state on status-fetch error", () => {
  mockStatus("ready");
  vi.spyOn(hooks, "useTPMStatus").mockReturnValue({
    data: null,
    error: new Error("network down"),
    loading: false,
    refresh: vi.fn(),
    setData: vi.fn(),
  } as never);
  renderSettings();
  // The card must remain present (not vanish) and surface the failure.
  expect(screen.getByText("Hardware security")).toBeInTheDocument();
  expect(screen.getByText(/unavailable/i)).toBeInTheDocument();
  expect(screen.getByRole("alert")).toHaveTextContent(/network down/i);
});

test("(p) TPM card shows 'No TPM detected' message when unavailable", () => {
  mockStatus("ready");
  mockTPMStatus(tpmUnavailable);
  renderSettings();
  expect(screen.getByText(/no tpm detected/i)).toBeInTheDocument();
});

test("(q) TPM card shows the unavailable reason text", () => {
  mockStatus("ready");
  mockTPMStatus({ available: false, reason: "tss group permission denied", enabled: false, pcrBound: false });
  renderSettings();
  expect(screen.getByText(/tss group permission denied/i)).toBeInTheDocument();
});

test("(r) TPM card shows toggle when TPM is available and not enabled", () => {
  mockStatus("ready");
  mockTPMStatus(tpmAvailable);
  renderSettings();
  // Toggle button / checkbox should be present to enable TPM
  expect(screen.getByRole("button", { name: /enable/i })).toBeInTheDocument();
});

test("(s) TPM card shows disable button when TPM is enabled", () => {
  mockStatus("ready");
  mockTPMStatus(tpmEnabled);
  renderSettings();
  expect(screen.getByRole("button", { name: /disable/i })).toBeInTheDocument();
});

test("(s1) TPM-enabled vault can be disabled when TPM is unavailable", () => {
  mockStatus("ready");
  mockTPMStatus(tpmEnabledUnavailable);
  renderSettings();
  expect(screen.getByRole("button", { name: /disable/i })).toBeInTheDocument();
  expect(screen.queryByText(/no tpm detected/i)).toBeNull();
});

test("(t) enabling TPM calls enableTPM client function with password", async () => {
  mockStatus("ready");
  mockTPMStatus(tpmAvailable);
  const enableTPMSpy = vi.spyOn(client, "enableTPM").mockResolvedValue(tpmEnabled);

  renderSettings();
  fireEvent.click(screen.getByRole("button", { name: /enable/i }));

  // Password prompt appears
  const pwInput = await screen.findByPlaceholderText(/vault password/i);
  fireEvent.change(pwInput, { target: { value: "valid-vault-password" } });
  fireEvent.click(screen.getByRole("button", { name: /confirm/i }));

  await waitFor(() => {
    expect(enableTPMSpy).toHaveBeenCalledWith(
      expect.objectContaining({ password: "valid-vault-password" })
    );
  });
});

test("(t1) failed TPM enable is announced as an alert", async () => {
  mockStatus("ready");
  mockTPMStatus(tpmAvailable);
  vi.spyOn(client, "enableTPM").mockRejectedValue(new client.ApiError(500, "TPM seal failed"));

  renderSettings();
  fireEvent.click(screen.getByRole("button", { name: /enable/i }));

  const pwInput = await screen.findByPlaceholderText(/vault password/i);
  fireEvent.change(pwInput, { target: { value: "valid-vault-password" } });
  fireEvent.click(screen.getByRole("button", { name: /confirm/i }));

  expect(await screen.findByRole("alert")).toHaveTextContent(/tpm seal failed/i);
});

test("(u) disabling TPM calls disableTPM client function with password", async () => {
  mockStatus("ready");
  mockTPMStatus(tpmEnabled);
  const disableTPMSpy = vi.spyOn(client, "disableTPM").mockResolvedValue(tpmAvailable);

  renderSettings();
  fireEvent.click(screen.getByRole("button", { name: /disable/i }));

  const pwInput = await screen.findByPlaceholderText(/vault password/i);
  fireEvent.change(pwInput, { target: { value: "valid-vault-password" } });
  fireEvent.click(screen.getByRole("button", { name: /confirm/i }));

  await waitFor(() => {
    expect(disableTPMSpy).toHaveBeenCalledWith({ password: "valid-vault-password" });
  });
});

test("(u1) failed TPM disable is announced as an alert", async () => {
  mockStatus("ready");
  mockTPMStatus(tpmEnabled);
  vi.spyOn(client, "disableTPM").mockRejectedValue(new client.ApiError(500, "TPM disable failed"));

  renderSettings();
  fireEvent.click(screen.getByRole("button", { name: /disable/i }));

  const pwInput = await screen.findByPlaceholderText(/vault password/i);
  fireEvent.change(pwInput, { target: { value: "valid-vault-password" } });
  fireEvent.click(screen.getByRole("button", { name: /confirm/i }));

  expect(await screen.findByRole("alert")).toHaveTextContent(/tpm disable failed/i);
});

test("(v) PCR advanced option shows brittleness warning when checked", async () => {
  mockStatus("ready");
  mockTPMStatus(tpmAvailable);
  renderSettings();
  fireEvent.click(screen.getByRole("button", { name: /enable/i }));

  // Advanced PCR checkbox should appear in the enable dialog
  const pcrCheckbox = await screen.findByRole("checkbox", { name: /pcr/i });
  fireEvent.click(pcrCheckbox);

  // Brittleness warning should appear
  expect(await screen.findByRole("status")).toHaveTextContent(/firmware update/i);
});

test("(w) TPM card shows PCR-bound status when enabled with PCR", () => {
  mockStatus("ready");
  mockTPMStatus(tpmEnabledPCR);
  renderSettings();
  expect(screen.getByText(/pcr/i)).toBeInTheDocument();
});

test("connector shows paired extension and connected sites", async () => {
  mockStatus("ready", 12345, true);
  vi.mocked(connectorApi.getConnectorState).mockResolvedValue({
    paired: true,
    extension_id: "chrome-extension://abc123",
    origins: ["https://app.sundae.fi"],
  });
  vi.spyOn(connectorApi, "revokeGrant").mockResolvedValue(undefined);

  renderSettings();

  await waitFor(() => expect(screen.getByText("Paired")).toBeInTheDocument());
  expect(screen.getByText("chrome-extension://abc123")).toBeInTheDocument();
  expect(screen.getByText("https://app.sundae.fi")).toBeInTheDocument();
  expect(screen.getByRole("button", { name: /revoke/i })).toBeInTheDocument();
});

test("connector surfaces a failed grant revocation", async () => {
  mockStatus("ready", 12345, true);
  vi.mocked(connectorApi.getConnectorState).mockResolvedValue({
    paired: true,
    extension_id: "chrome-extension://abc123",
    origins: ["https://app.sundae.fi"],
  });
  vi.spyOn(connectorApi, "revokeGrant").mockRejectedValue(
    new client.ApiError(500, "Revoke failed"),
  );

  renderSettings();
  const revoke = await screen.findByRole("button", {
    name: "Revoke https://app.sundae.fi",
  });
  fireEvent.click(revoke);

  expect(await screen.findByRole("alert")).toHaveTextContent("Revoke failed");
});

test("connector surfaces a failed extension unpair", async () => {
  mockStatus("ready", 12345, true);
  vi.mocked(connectorApi.getConnectorState).mockResolvedValue({
    paired: true,
    extension_id: "chrome-extension://abc123",
    origins: [],
  });
  vi.spyOn(connectorApi, "unpair").mockRejectedValue(
    new client.ApiError(500, "Unpair failed"),
  );

  renderSettings();
  fireEvent.click(await screen.findByRole("button", { name: /unpair extension/i }));

  expect(await screen.findByRole("alert")).toHaveTextContent("Unpair failed");
});

test("connector reveals a pending pairing code after password confirmation", async () => {
  mockStatus("ready", 12345, true);
  vi.mocked(connectorApi.pendingPairings).mockImplementation(async (password?: string) =>
    password
      ? [{ extension_id: "chrome-extension://ext1", code: "123456" }]
      : [{ extension_id: "chrome-extension://ext1" }],
  );

  renderSettings();

  await waitFor(() =>
    expect(screen.getByText("chrome-extension://ext1")).toBeInTheDocument(),
  );
  fireEvent.change(screen.getByLabelText(/vault password/i), {
    target: { value: "vault-password" },
  });
  fireEvent.click(screen.getByRole("button", { name: /reveal code/i }));
  await waitFor(() => expect(screen.getByText("123456")).toBeInTheDocument());
});

test("connector card recovers after a transient missing endpoint", async () => {
  vi.useFakeTimers({ shouldAdvanceTime: true });
  mockStatus("ready", 12345, true);
  vi.mocked(connectorApi.getConnectorState)
    .mockRejectedValueOnce(new client.ApiError(404, "not found"))
    .mockResolvedValue(defaultConnectorState);

  renderSettings();

  await waitFor(() => expect(screen.queryByText("dApp Connector")).toBeNull());
  await act(async () => {
    await vi.advanceTimersByTimeAsync(3000);
  });
  await waitFor(() =>
    expect(screen.getByText("dApp Connector")).toBeInTheDocument(),
  );
});
