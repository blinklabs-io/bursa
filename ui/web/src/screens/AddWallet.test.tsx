import { render, screen, fireEvent, waitFor } from "@testing-library/react";
import { AddWallet } from "./AddWallet";
import * as client from "../api/client";
import type { WalletView } from "../api/types";

// ── Ledger mock ───────────────────────────────────────────────────────────────
const FIXED_XPUB =
  "root_xvk1qpxlt6hkndkymk3lgchrcgpjnkrxkutp6c4p0nwegwuhlhqmlkzjhxm7qhz8c7dw8qvpgm4y8ayjzce7hqjm0p7g4uh6ypmfmzrk4sv4k39n";

// vi.hoisted creates variables that are available before vi.mock() factory runs.
const { mockSession, mockConnectLedger } = vi.hoisted(() => {
  const mockSession = {
    getAccountXpub: vi.fn().mockResolvedValue(
      "root_xvk1qpxlt6hkndkymk3lgchrcgpjnkrxkutp6c4p0nwegwuhlhqmlkzjhxm7qhz8c7dw8qvpgm4y8ayjzce7hqjm0p7g4uh6ypmfmzrk4sv4k39n",
    ),
    signTx: vi.fn(),
    close: vi.fn().mockResolvedValue(undefined),
  };
  const mockConnectLedger = vi.fn().mockResolvedValue(mockSession);
  return { mockSession, mockConnectLedger };
});

vi.mock("../hw/ledger", () => ({
  connectLedger: mockConnectLedger,
}));

const created: WalletView = {
  id: "w2",
  name: "Savings",
  network: "preview",
  stake_address: "stake_test1xyz",
  addresses: ["addr_test1xyz"],
  active: true,
  type: "full",
};

const MNEMONIC = "word1 word2 word3 word4 word5 word6 word7 word8 word9 word10 word11 word12";

// 24-word mnemonic for the create-new path.
const GENERATED =
  "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo wrong";

afterEach(() => vi.restoreAllMocks());

// Helper: navigate from the "choose" screen to the "restore" form.
function goToRestore() {
  fireEvent.click(screen.getByRole("button", { name: /restore from recovery phrase/i }));
}

test("with a known vault password the vault field is hidden and add sends all fields", async () => {
  const spy = vi.spyOn(client, "addWallet").mockResolvedValue(created);
  const onAdded = vi.fn();

  render(<AddWallet network="preview" knownVaultPassword="vault-password-xyz" onAdded={onAdded} />);

  // The initial screen is the create/restore chooser.
  goToRestore();

  // No vault-password field when the vault password is already known.
  expect(screen.queryByLabelText(/^vault password$/i)).not.toBeInTheDocument();

  fireEvent.change(screen.getByLabelText(/wallet name/i), { target: { value: "Savings" } });
  fireEvent.change(screen.getByLabelText(/recovery phrase/i), { target: { value: MNEMONIC } });
  fireEvent.change(screen.getByLabelText(/spending password/i), { target: { value: "spend-password-aaa" } });
  fireEvent.click(screen.getByRole("button", { name: /add wallet/i }));

  await waitFor(() =>
    expect(spy).toHaveBeenCalledWith({
      name: "Savings",
      mnemonic: MNEMONIC,
      network: "preview",
      vault_password: "vault-password-xyz",
      spend_password: "spend-password-aaa",
    }),
  );
  await waitFor(() => expect(onAdded).toHaveBeenCalledWith(created));
});

test("the network is shown read-only (no selector) and taken from the node", () => {
  render(<AddWallet network="preprod" knownVaultPassword="vault-password-xyz" onAdded={vi.fn()} />);
  goToRestore();

  // The old network <Select> is gone: there is no network combobox to pick a
  // network the node isn't running.
  expect(screen.queryByRole("combobox")).not.toBeInTheDocument();

  // The node's network is shown read-only for context.
  expect(screen.getByTestId("wallet-network")).toHaveTextContent(/Preprod/i);
});

test("without a known vault password the vault field is shown and required", async () => {
  const spy = vi.spyOn(client, "addWallet").mockResolvedValue(created);
  const onAdded = vi.fn();

  render(<AddWallet network="preview" onAdded={onAdded} />);
  goToRestore();

  expect(screen.getByLabelText(/^vault password$/i)).toBeInTheDocument();

  fireEvent.change(screen.getByLabelText(/recovery phrase/i), { target: { value: MNEMONIC } });
  fireEvent.change(screen.getByLabelText(/spending password/i), { target: { value: "spend-password-aaa" } });
  fireEvent.change(screen.getByLabelText(/^vault password$/i), { target: { value: "vault-password-xyz" } });
  fireEvent.click(screen.getByRole("button", { name: /add wallet/i }));

  await waitFor(() =>
    expect(spy).toHaveBeenCalledWith(
      expect.objectContaining({ vault_password: "vault-password-xyz", spend_password: "spend-password-aaa" }),
    ),
  );
});

test("a too-short spending password is rejected client-side before any request", async () => {
  const spy = vi.spyOn(client, "addWallet");
  const onAdded = vi.fn();

  render(<AddWallet network="preview" knownVaultPassword="vault-password-xyz" onAdded={onAdded} />);
  goToRestore();
  fireEvent.change(screen.getByLabelText(/recovery phrase/i), { target: { value: MNEMONIC } });
  fireEvent.change(screen.getByLabelText(/spending password/i), { target: { value: "short" } });
  fireEvent.click(screen.getByRole("button", { name: /add wallet/i }));

  await waitFor(() => expect(screen.getByText(/at least 12 characters/i)).toBeInTheDocument());
  expect(spy).not.toHaveBeenCalled();
  expect(onAdded).not.toHaveBeenCalled();
});

// Fills in every rendered recovery-phrase challenge input with the correct
// word from `words` (challenged positions are randomized, so this reads each
// input's own label rather than assuming fixed indices).
function fillChallengeAnswers(words: string[]) {
  const inputs = screen.getAllByLabelText(/^word #\d+$/i);
  for (const input of inputs) {
    const match = /Word #(\d+)/i.exec(input.getAttribute("aria-label") ?? "");
    if (!match) throw new Error("challenge input missing a parseable label");
    const index = Number(match[1]) - 1;
    fireEvent.change(input, { target: { value: words[index] } });
  }
}

test("create new wallet: generate phrase → acknowledge → pass challenge → fill form → submit", async () => {
  vi.spyOn(client, "generateMnemonic").mockResolvedValue(GENERATED);
  const spy = vi.spyOn(client, "addWallet").mockResolvedValue(created);
  const onAdded = vi.fn();

  render(
    <AddWallet
      network="preview"
      knownVaultPassword="vault-password-xyz"
      onAdded={onAdded}
      submitLabel="Finish setup"
    />,
  );

  // Click "Create new wallet" to trigger mnemonic generation.
  fireEvent.click(screen.getByRole("button", { name: /create new wallet/i }));

  // The generated phrase should appear; check for the unique last word.
  await waitFor(() => expect(screen.getByText("wrong")).toBeInTheDocument());

  // Must acknowledge before proceeding.
  fireEvent.click(screen.getByRole("button", { name: /continue/i }));
  await waitFor(() =>
    expect(screen.getByRole("alert")).toHaveTextContent(/confirm.*saved/i),
  );

  // Check the acknowledgement checkbox then proceed.
  fireEvent.click(screen.getByLabelText(/i have saved my recovery phrase/i));
  fireEvent.click(screen.getByRole("button", { name: /continue/i }));

  // Now on the create-confirm form: the phrase re-entry challenge gates the
  // submit button until every quizzed word is answered correctly.
  await waitFor(() =>
    expect(screen.getByLabelText(/spending password/i)).toBeInTheDocument(),
  );
  fireEvent.change(screen.getByLabelText(/spending password/i), {
    target: { value: "spend-password-aaa" },
  });

  expect(screen.getByRole("button", { name: /finish setup/i })).toBeDisabled();

  // A wrong answer surfaces per-field "Incorrect" feedback and keeps submit
  // disabled.
  const [firstChallengeInput] = screen.getAllByLabelText(/^word #\d+$/i);
  fireEvent.change(firstChallengeInput, { target: { value: "definitely-not-it" } });
  await waitFor(() => expect(screen.getByText("Incorrect")).toBeInTheDocument());
  expect(screen.getByRole("status")).toHaveTextContent("Incorrect");
  expect(screen.getByRole("button", { name: /finish setup/i })).toBeDisabled();

  // Filling in every challenged word correctly unlocks submit.
  fillChallengeAnswers(GENERATED.split(" "));
  await waitFor(() =>
    expect(screen.getByRole("button", { name: /finish setup/i })).toBeEnabled(),
  );
  expect(screen.getAllByText("Correct").length).toBeGreaterThan(0);

  fireEvent.click(screen.getByRole("button", { name: /finish setup/i }));

  await waitFor(() =>
    expect(spy).toHaveBeenCalledWith(
      expect.objectContaining({
        mnemonic: GENERATED,
        spend_password: "spend-password-aaa",
        vault_password: "vault-password-xyz",
      }),
    ),
  );
  await waitFor(() => expect(onAdded).toHaveBeenCalledWith(created));
});

test("create-confirm: submit stays blocked while the challenge is unanswered or wrong", async () => {
  vi.spyOn(client, "generateMnemonic").mockResolvedValue(GENERATED);
  const spy = vi.spyOn(client, "addWallet");

  render(<AddWallet network="preview" knownVaultPassword="vault-password-xyz" onAdded={vi.fn()} />);

  fireEvent.click(screen.getByRole("button", { name: /create new wallet/i }));
  await waitFor(() => expect(screen.getByText("wrong")).toBeInTheDocument());
  fireEvent.click(screen.getByLabelText(/i have saved my recovery phrase/i));
  fireEvent.click(screen.getByRole("button", { name: /continue/i }));

  await waitFor(() =>
    expect(screen.getByRole("button", { name: /add wallet/i })).toBeDisabled(),
  );

  fireEvent.change(screen.getByLabelText(/spending password/i), {
    target: { value: "spend-password-aaa" },
  });
  fireEvent.click(screen.getByRole("button", { name: /add wallet/i }));

  // The button is disabled, so the click is a no-op — no request is sent.
  expect(spy).not.toHaveBeenCalled();
});

// ── Connect Ledger flow ───────────────────────────────────────────────────────

const hwWallet: WalletView = {
  id: "hw1",
  name: "Ledger Main",
  network: "preview",
  stake_address: "stake_test1hw",
  addresses: ["addr_test1hw"],
  active: true,
  type: "hardware",
};

// Helper: navigate from the "choose" screen to the "Connect Ledger" form.
function goToLedger() {
  fireEvent.click(screen.getByRole("button", { name: /connect ledger/i }));
}

// Re-arm the connectLedger mock before each Ledger test because
// vi.restoreAllMocks() (called in afterEach above) clears vi.fn() implementations.
beforeEach(() => {
  mockSession.getAccountXpub.mockReset().mockResolvedValue(FIXED_XPUB);
  mockSession.close.mockReset().mockResolvedValue(undefined);
  mockConnectLedger.mockReset().mockResolvedValue(mockSession);
});

test("Connect Ledger: calls getAccountXpub(0) then addHardwareWallet, wallet added", async () => {
  const hwSpy = vi.spyOn(client, "addHardwareWallet").mockResolvedValue(hwWallet);
  const onAdded = vi.fn();

  render(<AddWallet network="preview" knownVaultPassword="vault-pw" onAdded={onAdded} />);

  // Navigate from the chooser to the Ledger form.
  goToLedger();

  // Fill in wallet name
  fireEvent.change(screen.getByLabelText(/wallet name/i), { target: { value: "Ledger Main" } });

  // Trigger connect
  fireEvent.click(screen.getByRole("button", { name: /connect ledger/i }));

  await waitFor(() => expect(mockSession.getAccountXpub).toHaveBeenCalledWith(0));
  await waitFor(() =>
    expect(hwSpy).toHaveBeenCalledWith("Ledger Main", FIXED_XPUB, 0, "preview", "vault-pw"),
  );
  await waitFor(() => expect(onAdded).toHaveBeenCalledWith(hwWallet));
  expect(mockSession.close).toHaveBeenCalledOnce();
});

test("Connect Ledger: derives and stores the selected account index", async () => {
  const hwSpy = vi.spyOn(client, "addHardwareWallet").mockResolvedValue(hwWallet);

  render(<AddWallet network="preview" knownVaultPassword="vault-pw" onAdded={vi.fn()} />);
  goToLedger();
  fireEvent.change(screen.getByLabelText(/account index/i), { target: { value: "2" } });
  fireEvent.click(screen.getByRole("button", { name: /connect ledger/i }));

  await waitFor(() => expect(mockSession.getAccountXpub).toHaveBeenCalledWith(2));
  expect(hwSpy).toHaveBeenCalledWith("Ledger Wallet", FIXED_XPUB, 2, "preview", "vault-pw");
});

test("Connect Ledger: an empty account index is rejected before touching the device", async () => {
  // Number("") is 0, so an empty field must be caught explicitly — otherwise it
  // would silently import account 0, a different Ledger account than intended.
  const hwSpy = vi.spyOn(client, "addHardwareWallet");

  render(<AddWallet network="preview" knownVaultPassword="vault-pw" onAdded={vi.fn()} />);
  goToLedger();
  fireEvent.change(screen.getByLabelText(/account index/i), { target: { value: "" } });
  fireEvent.click(screen.getByRole("button", { name: /connect ledger/i }));

  await waitFor(() => expect(screen.getByText(/account index must be an integer/i)).toBeInTheDocument());
  expect(mockConnectLedger).not.toHaveBeenCalled();
  expect(hwSpy).not.toHaveBeenCalled();
});

test("Connect Ledger: closes the session when reading the account xpub fails", async () => {
  mockSession.getAccountXpub.mockRejectedValueOnce(new Error("Cardano app is not open"));
  const hwSpy = vi.spyOn(client, "addHardwareWallet");

  render(<AddWallet network="preview" knownVaultPassword="vault-pw" onAdded={vi.fn()} />);

  goToLedger();
  fireEvent.click(screen.getByRole("button", { name: /connect ledger/i }));

  await waitFor(() =>
    expect(screen.getByRole("alert")).toHaveTextContent("Cardano app is not open"),
  );
  expect(mockSession.close).toHaveBeenCalledOnce();
  expect(hwSpy).not.toHaveBeenCalled();
});

test("Connect Ledger: WebHID unavailable error message is shown", async () => {
  mockConnectLedger.mockRejectedValueOnce(
    new Error("WebHID not available — open this in a Chromium browser"),
  );
  const onAdded = vi.fn();

  render(<AddWallet network="preview" knownVaultPassword="vault-pw" onAdded={onAdded} />);

  goToLedger();
  fireEvent.click(screen.getByRole("button", { name: /connect ledger/i }));

  await waitFor(() =>
    expect(
      screen.getByText(/open this in a chromium browser/i),
    ).toBeInTheDocument(),
  );
  expect(onAdded).not.toHaveBeenCalled();
});
