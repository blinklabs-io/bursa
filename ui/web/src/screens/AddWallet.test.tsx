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

afterEach(() => vi.restoreAllMocks());

test("with a known vault password the vault field is hidden and add sends all fields", async () => {
  const spy = vi.spyOn(client, "addWallet").mockResolvedValue(created);
  const onAdded = vi.fn();

  render(<AddWallet network="preview" knownVaultPassword="vault-password-xyz" onAdded={onAdded} />);

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
  fireEvent.change(screen.getByLabelText(/recovery phrase/i), { target: { value: MNEMONIC } });
  fireEvent.change(screen.getByLabelText(/spending password/i), { target: { value: "short" } });
  fireEvent.click(screen.getByRole("button", { name: /add wallet/i }));

  await waitFor(() => expect(screen.getByText(/at least 12 characters/i)).toBeInTheDocument());
  expect(spy).not.toHaveBeenCalled();
  expect(onAdded).not.toHaveBeenCalled();
});
