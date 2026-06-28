import { render, screen, fireEvent, waitFor } from "@testing-library/react";
import { AddWallet } from "./AddWallet";
import * as client from "../api/client";
import type { WalletView } from "../api/types";

const created: WalletView = {
  id: "w2",
  name: "Savings",
  network: "preview",
  stake_address: "stake_test1xyz",
  addresses: ["addr_test1xyz"],
  active: true,
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

test("create new wallet: generate phrase → acknowledge → fill form → submit", async () => {
  vi.spyOn(client, "generateMnemonic").mockResolvedValue(GENERATED);
  const spy = vi.spyOn(client, "addWallet").mockResolvedValue(created);
  const onAdded = vi.fn();

  render(<AddWallet network="preview" knownVaultPassword="vault-password-xyz" onAdded={onAdded} />);

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

  // Now on the create-confirm form: fill in password.
  await waitFor(() =>
    expect(screen.getByLabelText(/spending password/i)).toBeInTheDocument(),
  );
  fireEvent.change(screen.getByLabelText(/spending password/i), {
    target: { value: "spend-password-aaa" },
  });
  fireEvent.click(screen.getByRole("button", { name: /create wallet/i }));

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
