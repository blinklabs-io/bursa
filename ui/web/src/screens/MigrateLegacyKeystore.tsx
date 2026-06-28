import { useState } from "react";
import type { FormEvent } from "react";
import { Card } from "../components/Card";
import { Input } from "../components/Input";
import { Button } from "../components/Button";
import { migrateLegacyKeystore, ApiError } from "../api/client";
import type { WalletView } from "../api/types";
import { MIN_PASSWORD_LEN, passwordLength } from "../password";

interface MigrateLegacyKeystoreProps {
  onReady: (wallet: WalletView) => void;
  onCreateNew: () => void;
}

export function MigrateLegacyKeystore({ onReady, onCreateNew }: MigrateLegacyKeystoreProps) {
  const [name, setName] = useState("Wallet");
  const [vaultPassword, setVaultPassword] = useState("");
  const [confirm, setConfirm] = useState("");
  const [spendPassword, setSpendPassword] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);

  async function handleSubmit(e: FormEvent) {
    e.preventDefault();
    setError(null);

    if (passwordLength(vaultPassword) < MIN_PASSWORD_LEN) {
      setError(`Vault password must be at least ${MIN_PASSWORD_LEN} characters`);
      return;
    }
    if (vaultPassword !== confirm) {
      setError("Passwords do not match");
      return;
    }
    if (spendPassword === "") {
      setError("Existing spending password is required");
      return;
    }

    setLoading(true);
    try {
      const wallet = await migrateLegacyKeystore({
        name: name.trim() || "Wallet",
        vault_password: vaultPassword,
        spend_password: spendPassword,
      });
      onReady(wallet);
    } catch (err) {
      setError(err instanceof ApiError ? err.message : "An unexpected error occurred");
    } finally {
      setLoading(false);
    }
  }

  return (
    <Card title="Import Existing Wallet">
      <form onSubmit={handleSubmit}>
        <p className="helper-text">
          An older encrypted wallet was found. Import it into a vault to continue.
        </p>

        <div className="field-group">
          <label htmlFor="legacy-name">Wallet Name</label>
          <Input
            id="legacy-name"
            value={name}
            onChange={(e) => setName(e.target.value)}
            placeholder="Wallet"
            aria-label="Wallet Name"
          />
        </div>

        <div className="field-group">
          <label htmlFor="legacy-vault-password">New Vault Password</label>
          <Input
            id="legacy-vault-password"
            type="password"
            value={vaultPassword}
            onChange={(e) => setVaultPassword(e.target.value)}
            placeholder={`At least ${MIN_PASSWORD_LEN} characters`}
            aria-label="New Vault Password"
          />
        </div>

        <div className="field-group">
          <label htmlFor="legacy-vault-confirm">Confirm New Vault Password</label>
          <Input
            id="legacy-vault-confirm"
            type="password"
            value={confirm}
            onChange={(e) => setConfirm(e.target.value)}
            placeholder="Re-enter the vault password"
            aria-label="Confirm New Vault Password"
          />
        </div>

        <div className="field-group">
          <label htmlFor="legacy-spend-password">Existing Spending Password</label>
          <Input
            id="legacy-spend-password"
            type="password"
            value={spendPassword}
            onChange={(e) => setSpendPassword(e.target.value)}
            placeholder="Password for the existing wallet"
            aria-label="Existing Spending Password"
          />
        </div>

        {error && (
          <p className="error-text" role="alert">
            {error}
          </p>
        )}

        <div className="preview-actions">
          <Button type="submit" disabled={loading}>
            {loading ? "Importing..." : "Import Wallet"}
          </Button>
          <Button type="button" variant="ghost" onClick={onCreateNew} disabled={loading}>
            Create New Vault
          </Button>
        </div>
      </form>
    </Card>
  );
}
