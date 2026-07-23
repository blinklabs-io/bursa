import { render, screen, fireEvent, waitFor } from "@testing-library/react";
import { WalletSwitcher } from "./WalletSwitcher";
import * as client from "../api/client";
import type { WalletView } from "../api/types";

const walletA: WalletView = {
  id: "w1",
  name: "Main",
  network: "preview",
  stake_address: "stake_test1abc",
  addresses: ["addr_test1abc"],
  active: true,
  type: "full",
};

// network is "preprod" (not "mainnet") so the "main" substring in an accessible
// name uniquely identifies wallet A's button.
const walletB: WalletView = {
  id: "w2",
  name: "Savings",
  network: "preprod",
  stake_address: "stake1def",
  addresses: ["addr1def"],
  active: false,
  type: "full",
};

function renderSwitcher(overrides: Partial<Parameters<typeof WalletSwitcher>[0]> = {}) {
  const props = {
    wallets: [walletA, walletB],
    activeId: "w1",
    onActivated: vi.fn(),
    onAddWallet: vi.fn(),
    onLock: vi.fn(),
    ...overrides,
  };
  render(<WalletSwitcher {...props} />);
  return props;
}

afterEach(() => {
  vi.restoreAllMocks();
});

// --- rendering ---

test("lists every wallet with its name and network, marking the active one", () => {
  renderSwitcher();

  expect(screen.getByText("Main")).toBeInTheDocument();
  expect(screen.getByText("Savings")).toBeInTheDocument();
  expect(screen.getByText("preview")).toBeInTheDocument();
  expect(screen.getByText("preprod")).toBeInTheDocument();

  const active = screen.getByRole("button", { name: /main/i });
  expect(active).toHaveAttribute("aria-current", "true");
  const inactive = screen.getByRole("button", { name: /savings/i });
  expect(inactive).not.toHaveAttribute("aria-current");
});

// --- switching ---

test("selecting an inactive wallet activates it server-side and reports the result", async () => {
  const activated: WalletView = { ...walletB, active: true };
  const activate = vi.spyOn(client, "activateWallet").mockResolvedValue(activated);
  const { onActivated } = renderSwitcher();

  fireEvent.click(screen.getByRole("button", { name: /savings/i }));

  await waitFor(() => expect(activate).toHaveBeenCalledWith("w2"));
  await waitFor(() => expect(onActivated).toHaveBeenCalledWith(activated));
});

test("clicking the already-active wallet is a no-op", () => {
  const activate = vi.spyOn(client, "activateWallet");
  const { onActivated } = renderSwitcher();

  fireEvent.click(screen.getByRole("button", { name: /main/i }));

  expect(activate).not.toHaveBeenCalled();
  expect(onActivated).not.toHaveBeenCalled();
});

test("every wallet button is disabled while a switch is in flight, so no second request can start", async () => {
  let resolve!: (w: WalletView) => void;
  const activate = vi
    .spyOn(client, "activateWallet")
    .mockReturnValue(new Promise<WalletView>((r) => (resolve = r)));
  renderSwitcher();

  // Kick off the switch to Savings. The guard against a concurrent second
  // request is enforced in the DOM: while one activation is pending, EVERY
  // wallet button is disabled, so the user cannot dispatch another select().
  fireEvent.click(screen.getByRole("button", { name: /savings/i }));
  await waitFor(() => expect(screen.getByRole("button", { name: /savings/i })).toBeDisabled());
  // The other wallet's button is disabled too — not just the one in flight —
  // which is what actually prevents a second request from being started.
  expect(screen.getByRole("button", { name: /main/i })).toBeDisabled();
  expect(activate).toHaveBeenCalledTimes(1);

  // Buttons re-enable once the in-flight switch resolves.
  resolve({ ...walletB, active: true });
  await waitFor(() => expect(screen.getByRole("button", { name: /savings/i })).not.toBeDisabled());
  expect(screen.getByRole("button", { name: /main/i })).not.toBeDisabled();
});

// --- error handling ---

test("surfaces an ApiError message when activation fails", async () => {
  vi.spyOn(client, "activateWallet").mockRejectedValue(
    new client.ApiError(423, "vault is locked"),
  );
  const { onActivated } = renderSwitcher();

  fireEvent.click(screen.getByRole("button", { name: /savings/i }));

  await waitFor(() => expect(screen.getByRole("alert")).toHaveTextContent(/vault is locked/i));
  expect(onActivated).not.toHaveBeenCalled();
  // Buttons re-enable after the failure.
  expect(screen.getByRole("button", { name: /savings/i })).not.toBeDisabled();
});

test("shows a generic message for a non-ApiError failure", async () => {
  vi.spyOn(client, "activateWallet").mockRejectedValue(new TypeError("boom"));
  renderSwitcher();

  fireEvent.click(screen.getByRole("button", { name: /savings/i }));

  await waitFor(() =>
    expect(screen.getByRole("alert")).toHaveTextContent(/could not switch wallet/i),
  );
});

// --- footer actions ---

test("the footer actions invoke their callbacks", () => {
  const { onAddWallet, onLock } = renderSwitcher();

  fireEvent.click(screen.getByRole("button", { name: /add wallet/i }));
  expect(onAddWallet).toHaveBeenCalledTimes(1);

  fireEvent.click(screen.getByRole("button", { name: /lock vault/i }));
  expect(onLock).toHaveBeenCalledTimes(1);
});
