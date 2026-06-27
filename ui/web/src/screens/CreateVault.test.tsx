import { render, screen, fireEvent, waitFor } from "@testing-library/react";
import { CreateVault } from "./CreateVault";
import * as client from "../api/client";

afterEach(() => vi.restoreAllMocks());

test("creating the vault then advances to the add-first-wallet step", async () => {
  const createSpy = vi.spyOn(client, "createVault").mockResolvedValue({ exists: true, locked: false, wallet_count: 0 });
  const onReady = vi.fn();

  render(<CreateVault network="preview" onReady={onReady} />);

  fireEvent.change(screen.getByLabelText(/^vault password$/i), { target: { value: "vault-password-xyz" } });
  fireEvent.change(screen.getByLabelText(/confirm vault password/i), { target: { value: "vault-password-xyz" } });
  fireEvent.click(screen.getByRole("button", { name: /create vault/i }));

  await waitFor(() => expect(createSpy).toHaveBeenCalledWith({ password: "vault-password-xyz" }));
  // After creation, the add-first-wallet form (recovery phrase) is shown.
  await waitFor(() => expect(screen.getByLabelText(/recovery phrase/i)).toBeInTheDocument());
});

test("mismatched passwords are rejected before any request", async () => {
  const createSpy = vi.spyOn(client, "createVault");
  const onReady = vi.fn();

  render(<CreateVault network="preview" onReady={onReady} />);
  fireEvent.change(screen.getByLabelText(/^vault password$/i), { target: { value: "vault-password-xyz" } });
  fireEvent.change(screen.getByLabelText(/confirm vault password/i), { target: { value: "different-password-1" } });
  fireEvent.click(screen.getByRole("button", { name: /create vault/i }));

  await waitFor(() => expect(screen.getByText(/do not match/i)).toBeInTheDocument());
  expect(createSpy).not.toHaveBeenCalled();
});

test("a too-short vault password is rejected client-side", async () => {
  const createSpy = vi.spyOn(client, "createVault");
  const onReady = vi.fn();

  render(<CreateVault network="preview" onReady={onReady} />);
  fireEvent.change(screen.getByLabelText(/^vault password$/i), { target: { value: "short" } });
  fireEvent.change(screen.getByLabelText(/confirm vault password/i), { target: { value: "short" } });
  fireEvent.click(screen.getByRole("button", { name: /create vault/i }));

  await waitFor(() => expect(screen.getByText(/at least 12 characters/i)).toBeInTheDocument());
  expect(createSpy).not.toHaveBeenCalled();
});
