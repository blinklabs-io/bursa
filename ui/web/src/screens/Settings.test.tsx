import { render, screen, fireEvent, waitFor } from "@testing-library/react";
import { Settings } from "./Settings";
import * as hooks from "../api/hooks";
import * as client from "../api/client";
import type { Account, HistoryExpirySetting, TPMStatus } from "../api/types";

const mockAccount: Account = {
  network: "preview",
  stake_address: "stake_test1uzqxyz1234567890abcdefghijklmnopqrstuvwxyz",
  receive_addresses: ["addr_test1abc"],
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

function mockTPMStatus(tpmStatus: TPMStatus) {
  vi.spyOn(hooks, "useTPMStatus").mockReturnValue({
    data: tpmStatus,
    error: null,
    loading: false,
    refresh: vi.fn(),
    setData: vi.fn(),
  } as never);
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
  mockTPMStatus(tpmUnavailable);
});

afterEach(() => {
  vi.restoreAllMocks();
});

test("(a) renders network from account prop", () => {
  mockStatus("ready", 12345, true);
  render(<Settings account={mockAccount} spendingEnabled={false} />);
  expect(screen.getByText("preview")).toBeInTheDocument();
});

test("(b) renders stake address in monospace and a CopyButton for it", async () => {
  const writeText = vi.fn().mockResolvedValue(undefined);
  Object.assign(navigator, { clipboard: { writeText } });
  mockStatus("ready", 12345, true);

  render(<Settings account={mockAccount} spendingEnabled={false} />);

  // The stake address should appear in the document
  expect(screen.getByText(mockAccount.stake_address)).toBeInTheDocument();
  // The copy button must copy the FULL stake address.
  fireEvent.click(screen.getByRole("button", { name: /copy/i }));
  expect(writeText).toHaveBeenCalledWith(mockAccount.stake_address);
  expect(await screen.findByText("Copied")).toBeInTheDocument();
});

test("(c) renders sync state pill from useStatus", () => {
  mockStatus("syncing", 10000, false);
  render(<Settings account={mockAccount} spendingEnabled={false} />);
  // The sync state must be visible
  expect(screen.getByText("syncing")).toBeInTheDocument();
});

test("(d) renders tip block number from useStatus", () => {
  mockStatus("ready", 99999, true);
  render(<Settings account={mockAccount} spendingEnabled={false} />);
  expect(screen.getByText("99999")).toBeInTheDocument();
});

test("(e) caughtUp=true shows a caught-up indicator", () => {
  mockStatus("ready", 12345, true);
  render(<Settings account={mockAccount} spendingEnabled={false} />);
  expect(screen.getByText(/caught.?up/i)).toBeInTheDocument();
});

test("(f) caughtUp=false does NOT show caught-up indicator", () => {
  mockStatus("syncing", 12345, false);
  render(<Settings account={mockAccount} spendingEnabled={false} />);
  expect(screen.queryByText(/caught.?up/i)).toBeNull();
});

test("(g) spendingEnabled=true shows 'Spending enabled'", () => {
  mockStatus("ready", 12345, true);
  render(<Settings account={mockAccount} spendingEnabled={true} />);
  expect(screen.getByText(/spending enabled/i)).toBeInTheDocument();
});

test("(h) spendingEnabled=false shows 'Read-only'", () => {
  mockStatus("ready", 12345, true);
  render(<Settings account={mockAccount} spendingEnabled={false} />);
  expect(screen.getByText(/read.?only/i)).toBeInTheDocument();
});

test("(i) loading state from useStatus renders gracefully", () => {
  vi.spyOn(hooks, "useStatus").mockReturnValue({
    data: null,
    error: null,
    loading: true,
    refresh: vi.fn(),
    setData: vi.fn(),
  } as never);
  render(<Settings account={mockAccount} spendingEnabled={false} />);
  // Should not crash; network card still shows
  expect(screen.getByText("preview")).toBeInTheDocument();
});

// ---------------------------------------------------------- lean storage ---

test("(j) lean storage toggle reflects the persisted enabled state", () => {
  mockStatus("ready", 12345, true);
  mockHistoryExpiry({ enabled: true, restart_required: false });
  render(<Settings account={mockAccount} spendingEnabled={false} />);
  const toggle = screen.getByRole("switch", { name: /lean storage/i });
  expect(toggle).toBeChecked();
  expect(screen.getByText(/enabled/i)).toBeInTheDocument();
});

test("(k) lean storage renders the tradeoff copy", () => {
  mockStatus("ready", 12345, true);
  render(<Settings account={mockAccount} spendingEnabled={false} />);
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

  render(<Settings account={mockAccount} spendingEnabled={false} />);
  const toggle = screen.getByRole("switch", { name: /lean storage/i });
  fireEvent.click(toggle);

  await waitFor(() => expect(spy).toHaveBeenCalledWith(true));
  await waitFor(() => expect(toggle).not.toBeDisabled());
  expect(toggle).toBeChecked();
  expect(screen.getByRole("status")).toHaveTextContent(/takes effect after a node restart/i);
});

test("(m) failed lean storage update rolls back and surfaces the error", async () => {
  mockStatus("ready", 12345, true);
  mockHistoryExpiry({ enabled: false, restart_required: false });
  const spy = vi
    .spyOn(client, "setHistoryExpiry")
    .mockRejectedValue(new client.ApiError(500, "disk full"));

  render(<Settings account={mockAccount} spendingEnabled={false} />);
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

  render(<Settings account={mockAccount} spendingEnabled={false} />);
  const toggle = screen.getByRole("switch", { name: /lean storage/i });
  expect(toggle).toBeDisabled();
  expect(screen.getByText(/^Unavailable$/)).toBeInTheDocument();
  expect(screen.queryByText(/^disabled$/i)).toBeNull();
  expect(screen.getByRole("alert")).toHaveTextContent(/settings unavailable/i);
});

test("(o) a persisted restart_required surfaces the restart note", () => {
  mockStatus("ready", 12345, true);
  mockHistoryExpiry({ enabled: true, restart_required: true });
  render(<Settings account={mockAccount} spendingEnabled={false} />);
  // The restart note appears both in the live status line (role=status) and as
  // the final bullet of the copy; assert the live status one specifically.
  expect(screen.getByRole("status")).toHaveTextContent(/takes effect after a node restart/i);
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
  render(<Settings account={mockAccount} spendingEnabled={false} />);
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
  render(<Settings account={mockAccount} spendingEnabled={false} />);
  // The card must remain present (not vanish) and surface the failure.
  expect(screen.getByText("Hardware security")).toBeInTheDocument();
  expect(screen.getByText(/unavailable/i)).toBeInTheDocument();
  expect(screen.getByRole("alert")).toHaveTextContent(/network down/i);
});

test("(p) TPM card shows 'No TPM detected' message when unavailable", () => {
  mockStatus("ready");
  mockTPMStatus(tpmUnavailable);
  render(<Settings account={mockAccount} spendingEnabled={false} />);
  expect(screen.getByText(/no tpm detected/i)).toBeInTheDocument();
});

test("(q) TPM card shows the unavailable reason text", () => {
  mockStatus("ready");
  mockTPMStatus({ available: false, reason: "tss group permission denied", enabled: false, pcrBound: false });
  render(<Settings account={mockAccount} spendingEnabled={false} />);
  expect(screen.getByText(/tss group permission denied/i)).toBeInTheDocument();
});

test("(r) TPM card shows toggle when TPM is available and not enabled", () => {
  mockStatus("ready");
  mockTPMStatus(tpmAvailable);
  render(<Settings account={mockAccount} spendingEnabled={false} />);
  // Toggle button / checkbox should be present to enable TPM
  expect(screen.getByRole("button", { name: /enable/i })).toBeInTheDocument();
});

test("(s) TPM card shows disable button when TPM is enabled", () => {
  mockStatus("ready");
  mockTPMStatus(tpmEnabled);
  render(<Settings account={mockAccount} spendingEnabled={false} />);
  expect(screen.getByRole("button", { name: /disable/i })).toBeInTheDocument();
});

test("(s1) TPM-enabled vault can be disabled when TPM is unavailable", () => {
  mockStatus("ready");
  mockTPMStatus(tpmEnabledUnavailable);
  render(<Settings account={mockAccount} spendingEnabled={false} />);
  expect(screen.getByRole("button", { name: /disable/i })).toBeInTheDocument();
  expect(screen.queryByText(/no tpm detected/i)).toBeNull();
});

test("(t) enabling TPM calls enableTPM client function with password", async () => {
  mockStatus("ready");
  mockTPMStatus(tpmAvailable);
  const enableTPMSpy = vi.spyOn(client, "enableTPM").mockResolvedValue(tpmEnabled);

  render(<Settings account={mockAccount} spendingEnabled={false} />);
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

  render(<Settings account={mockAccount} spendingEnabled={false} />);
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

  render(<Settings account={mockAccount} spendingEnabled={false} />);
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

  render(<Settings account={mockAccount} spendingEnabled={false} />);
  fireEvent.click(screen.getByRole("button", { name: /disable/i }));

  const pwInput = await screen.findByPlaceholderText(/vault password/i);
  fireEvent.change(pwInput, { target: { value: "valid-vault-password" } });
  fireEvent.click(screen.getByRole("button", { name: /confirm/i }));

  expect(await screen.findByRole("alert")).toHaveTextContent(/tpm disable failed/i);
});

test("(v) PCR advanced option shows brittleness warning when checked", async () => {
  mockStatus("ready");
  mockTPMStatus(tpmAvailable);
  render(<Settings account={mockAccount} spendingEnabled={false} />);
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
  render(<Settings account={mockAccount} spendingEnabled={false} />);
  expect(screen.getByText(/pcr/i)).toBeInTheDocument();
});
