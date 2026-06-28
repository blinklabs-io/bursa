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
  // After creation, the add-first-wallet chooser (create/restore) is shown.
  await waitFor(() =>
    expect(screen.getByRole("button", { name: /restore from recovery phrase/i })).toBeInTheDocument(),
  );
  // Navigate to the restore path to get the recovery-phrase field.
  fireEvent.click(screen.getByRole("button", { name: /restore from recovery phrase/i }));
  await waitFor(() => expect(screen.getByLabelText(/recovery phrase/i)).toBeInTheDocument());
});

test("duplicate submits while create is in flight call create once", async () => {
  let resolveCreate!: () => void;
  const createSpy = vi.spyOn(client, "createVault").mockReturnValue(
    new Promise((resolve) => {
      resolveCreate = () => resolve({ exists: true, locked: false, wallet_count: 0 });
    }),
  );
  const onReady = vi.fn();

  render(<CreateVault network="preview" onReady={onReady} />);

  fireEvent.change(screen.getByLabelText(/^vault password$/i), { target: { value: "vault-password-xyz" } });
  fireEvent.change(screen.getByLabelText(/confirm vault password/i), { target: { value: "vault-password-xyz" } });
  const form = screen.getByRole("button", { name: /create vault/i }).closest("form");
  if (!form) throw new Error("create form not found");

  fireEvent.submit(form);
  fireEvent.submit(form);

  expect(createSpy).toHaveBeenCalledTimes(1);
  resolveCreate();
  // After creation the add-wallet chooser (create/restore) appears.
  await waitFor(() =>
    expect(screen.getByRole("button", { name: /restore from recovery phrase/i })).toBeInTheDocument(),
  );
  fireEvent.click(screen.getByRole("button", { name: /restore from recovery phrase/i }));
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
