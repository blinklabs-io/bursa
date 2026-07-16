import { render, screen, fireEvent, waitFor } from "@testing-library/react";
import { UnlockVault } from "./UnlockVault";
import * as client from "../api/client";
import type { WalletView } from "../api/types";

const wallets: WalletView[] = [
  { id: "w1", name: "Main", network: "preview", stake_address: "stake_test1", addresses: ["addr1"], active: true, type: "full" },
];

afterEach(() => vi.restoreAllMocks());

test("submits the vault password and reports the wallet list", async () => {
  const spy = vi.spyOn(client, "unlockVault").mockResolvedValue(wallets);
  const onUnlocked = vi.fn();

  render(<UnlockVault walletCount={1} onUnlocked={onUnlocked} />);
  fireEvent.change(screen.getByLabelText(/vault password/i), { target: { value: "vault-password-xyz" } });
  fireEvent.click(screen.getByRole("button", { name: /^unlock$/i }));

  await waitFor(() => expect(spy).toHaveBeenCalledWith({ password: "vault-password-xyz" }));
  await waitFor(() => expect(onUnlocked).toHaveBeenCalledWith(wallets));
});

test("renders the server error on a wrong password", async () => {
  vi.spyOn(client, "unlockVault").mockRejectedValue(new client.ApiError(401, "incorrect password"));
  const onUnlocked = vi.fn();

  render(<UnlockVault walletCount={2} onUnlocked={onUnlocked} />);
  fireEvent.change(screen.getByLabelText(/vault password/i), { target: { value: "wrong-but-long-pw" } });
  fireEvent.click(screen.getByRole("button", { name: /^unlock$/i }));

  await waitFor(() => expect(screen.getByText("incorrect password")).toBeInTheDocument());
  expect(onUnlocked).not.toHaveBeenCalled();
});
