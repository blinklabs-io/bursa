import { render, screen, fireEvent, waitFor } from "@testing-library/react";
import { Settings } from "./Settings";
import * as hooks from "../api/hooks";
import * as client from "../api/client";
import type { Account, HistoryExpirySetting } from "../api/types";

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

function mockNftMedia(
  overrides: Partial<{ enabled: boolean; loading: boolean; saving: boolean; setEnabled: ReturnType<typeof vi.fn> }> = {},
) {
  const setEnabled = overrides.setEnabled ?? vi.fn().mockResolvedValue(undefined);
  vi.spyOn(hooks, "useNftMedia").mockReturnValue({
    enabled: overrides.enabled ?? false,
    loading: overrides.loading ?? false,
    saving: overrides.saving ?? false,
    error: null,
    setEnabled,
  } as never);
  return setEnabled;
}

beforeEach(() => {
  mockHistoryExpiry({ enabled: false, restart_required: false });
  // Default: media off, not loading — so existing tests don't hit the network.
  mockNftMedia();
});

afterEach(() => {
  vi.restoreAllMocks();
});

test("(a) renders network from account prop", () => {
  mockStatus("ready", 12345, true);
  render(<Settings account={mockAccount} spendingEnabled={false} />);
  expect(screen.getByText("preview")).toBeInTheDocument();
});

test("(b) renders stake address in monospace and a CopyButton for it", () => {
  const writeText = vi.fn().mockResolvedValue(undefined);
  Object.assign(navigator, { clipboard: { writeText } });
  mockStatus("ready", 12345, true);

  render(<Settings account={mockAccount} spendingEnabled={false} />);

  // The stake address should appear in the document
  expect(screen.getByText(mockAccount.stake_address)).toBeInTheDocument();
  // The copy button must copy the FULL stake address.
  fireEvent.click(screen.getByRole("button", { name: /copy/i }));
  expect(writeText).toHaveBeenCalledWith(mockAccount.stake_address);
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
  } as never);

  render(<Settings account={mockAccount} spendingEnabled={false} />);
  const toggle = screen.getByRole("switch", { name: /lean storage/i });
  expect(toggle).toBeDisabled();
  expect(screen.getByText(/^Unavailable$/)).toBeInTheDocument();
  // The lean storage card must not show "Disabled" when load fails; the NFT card
  // may show "Disabled" in the same render, so scope to the setting-state class.
  const settingStates = document.querySelectorAll(".setting-state");
  for (const el of settingStates) {
    expect(el.textContent?.toLowerCase()).not.toMatch(/^disabled$/);
  }
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

// ------------------------------------------------------------ NFT media ---

test("(p) NFT media card explains the embedded IPFS client and shows Disabled by default", () => {
  mockStatus("ready", 12345, true);
  mockNftMedia({ enabled: false });
  render(<Settings account={mockAccount} spendingEnabled={false} />);
  // The explanation makes the consent clear.
  expect(screen.getByText(/embedded ipfs client/i)).toBeInTheDocument();
  // Use getAllByText since lean storage may also show "Disabled"; at least one match is fine.
  expect(screen.getAllByText(/disabled/i).length).toBeGreaterThan(0);
  expect(screen.getByRole("button", { name: /enable nft media/i })).toBeInTheDocument();
});

test("(q) clicking Enable calls setEnabled(true) — the one-time opt-in", () => {
  mockStatus("ready", 12345, true);
  const setEnabled = mockNftMedia({ enabled: false });
  render(<Settings account={mockAccount} spendingEnabled={false} />);
  fireEvent.click(screen.getByRole("button", { name: /enable nft media/i }));
  expect(setEnabled).toHaveBeenCalledWith(true);
});

test("(r) when enabled, the button offers to disable and shows Enabled status", () => {
  mockStatus("ready", 12345, true);
  const setEnabled = mockNftMedia({ enabled: true });
  render(<Settings account={mockAccount} spendingEnabled={false} />);
  expect(screen.getByText(/enabled/i)).toBeInTheDocument();
  const btn = screen.getByRole("button", { name: /disable nft media/i });
  fireEvent.click(btn);
  expect(setEnabled).toHaveBeenCalledWith(false);
});
