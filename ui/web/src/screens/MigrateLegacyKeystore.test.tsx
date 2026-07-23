import { render, screen, fireEvent, waitFor } from "@testing-library/react";
import { MigrateLegacyKeystore } from "./MigrateLegacyKeystore";
import * as client from "../api/client";
import type { WalletView } from "../api/types";
import { MIN_PASSWORD_LEN } from "../password";

const wallet: WalletView = {
  id: "w1",
  name: "Imported",
  network: "preview",
  stake_address: "stake_test1abc",
  addresses: ["addr_test1abc"],
  active: true,
  type: "full",
};

const VALID_VAULT_PW = "a".repeat(MIN_PASSWORD_LEN);

afterEach(() => {
  vi.restoreAllMocks();
});

function fill(fields: { vault?: string; confirm?: string; spend?: string; name?: string }) {
  if (fields.name !== undefined) {
    fireEvent.change(screen.getByLabelText(/^wallet name$/i), { target: { value: fields.name } });
  }
  if (fields.vault !== undefined) {
    fireEvent.change(screen.getByLabelText(/^new vault password$/i), {
      target: { value: fields.vault },
    });
  }
  if (fields.confirm !== undefined) {
    fireEvent.change(screen.getByLabelText(/^confirm new vault password$/i), {
      target: { value: fields.confirm },
    });
  }
  if (fields.spend !== undefined) {
    fireEvent.change(screen.getByLabelText(/^existing spending password$/i), {
      target: { value: fields.spend },
    });
  }
}

// --- happy path ---

test("imports the legacy keystore into a new vault and reports the wallet", async () => {
  const migrate = vi.spyOn(client, "migrateLegacyKeystore").mockResolvedValue(wallet);
  const onReady = vi.fn();

  render(<MigrateLegacyKeystore onReady={onReady} onCreateNew={vi.fn()} />);

  fill({ name: "  My Legacy  ", vault: VALID_VAULT_PW, confirm: VALID_VAULT_PW, spend: "oldpw" });
  fireEvent.click(screen.getByRole("button", { name: /^import wallet$/i }));

  await waitFor(() =>
    expect(migrate).toHaveBeenCalledWith({
      name: "My Legacy", // trimmed
      vault_password: VALID_VAULT_PW,
      spend_password: "oldpw",
    }),
  );
  await waitFor(() => expect(onReady).toHaveBeenCalledWith(wallet));
});

test("a blank/whitespace name falls back to the default 'Wallet'", async () => {
  const migrate = vi.spyOn(client, "migrateLegacyKeystore").mockResolvedValue(wallet);

  render(<MigrateLegacyKeystore onReady={vi.fn()} onCreateNew={vi.fn()} />);

  fill({ name: "   ", vault: VALID_VAULT_PW, confirm: VALID_VAULT_PW, spend: "oldpw" });
  fireEvent.click(screen.getByRole("button", { name: /^import wallet$/i }));

  await waitFor(() =>
    expect(migrate).toHaveBeenCalledWith(expect.objectContaining({ name: "Wallet" })),
  );
});

// --- client-side validation branches (API must not be called) ---

test("rejects a too-short vault password before calling the API", () => {
  const migrate = vi.spyOn(client, "migrateLegacyKeystore");

  render(<MigrateLegacyKeystore onReady={vi.fn()} onCreateNew={vi.fn()} />);

  fill({ vault: "short", confirm: "short", spend: "oldpw" });
  fireEvent.click(screen.getByRole("button", { name: /^import wallet$/i }));

  expect(screen.getByRole("alert")).toHaveTextContent(
    new RegExp(`at least ${MIN_PASSWORD_LEN} characters`, "i"),
  );
  expect(migrate).not.toHaveBeenCalled();
});

test("rejects mismatched vault password confirmation", () => {
  const migrate = vi.spyOn(client, "migrateLegacyKeystore");

  render(<MigrateLegacyKeystore onReady={vi.fn()} onCreateNew={vi.fn()} />);

  fill({ vault: VALID_VAULT_PW, confirm: VALID_VAULT_PW + "x", spend: "oldpw" });
  fireEvent.click(screen.getByRole("button", { name: /^import wallet$/i }));

  expect(screen.getByRole("alert")).toHaveTextContent(/passwords do not match/i);
  expect(migrate).not.toHaveBeenCalled();
});

test("requires the existing spending password", () => {
  const migrate = vi.spyOn(client, "migrateLegacyKeystore");

  render(<MigrateLegacyKeystore onReady={vi.fn()} onCreateNew={vi.fn()} />);

  fill({ vault: VALID_VAULT_PW, confirm: VALID_VAULT_PW, spend: "" });
  fireEvent.click(screen.getByRole("button", { name: /^import wallet$/i }));

  expect(screen.getByRole("alert")).toHaveTextContent(/existing spending password is required/i);
  expect(migrate).not.toHaveBeenCalled();
});

// --- API error handling ---

test("surfaces an ApiError message from a failed import", async () => {
  vi.spyOn(client, "migrateLegacyKeystore").mockRejectedValue(
    new client.ApiError(401, "incorrect spending password"),
  );
  const onReady = vi.fn();

  render(<MigrateLegacyKeystore onReady={onReady} onCreateNew={vi.fn()} />);

  fill({ vault: VALID_VAULT_PW, confirm: VALID_VAULT_PW, spend: "wrong" });
  fireEvent.click(screen.getByRole("button", { name: /^import wallet$/i }));

  await waitFor(() =>
    expect(screen.getByRole("alert")).toHaveTextContent(/incorrect spending password/i),
  );
  expect(onReady).not.toHaveBeenCalled();
  // Button is re-enabled after the failure so the user can retry.
  expect(screen.getByRole("button", { name: /^import wallet$/i })).not.toBeDisabled();
});

test("shows a generic message for a non-ApiError thrown value", async () => {
  vi.spyOn(client, "migrateLegacyKeystore").mockRejectedValue(new TypeError("network down"));

  render(<MigrateLegacyKeystore onReady={vi.fn()} onCreateNew={vi.fn()} />);

  fill({ vault: VALID_VAULT_PW, confirm: VALID_VAULT_PW, spend: "oldpw" });
  fireEvent.click(screen.getByRole("button", { name: /^import wallet$/i }));

  await waitFor(() =>
    expect(screen.getByRole("alert")).toHaveTextContent(/an unexpected error occurred/i),
  );
});

// --- create-new escape hatch ---

test("'Create New Vault' calls onCreateNew without importing", () => {
  const migrate = vi.spyOn(client, "migrateLegacyKeystore");
  const onCreateNew = vi.fn();

  render(<MigrateLegacyKeystore onReady={vi.fn()} onCreateNew={onCreateNew} />);

  fireEvent.click(screen.getByRole("button", { name: /create new vault/i }));

  expect(onCreateNew).toHaveBeenCalledTimes(1);
  expect(migrate).not.toHaveBeenCalled();
});
