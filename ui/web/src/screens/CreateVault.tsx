import { useState } from "react";
import type { FormEvent } from "react";
import { Card } from "../components/Card";
import { Input } from "../components/Input";
import { Button } from "../components/Button";
import { createVault, ApiError } from "../api/client";
import { AddWallet } from "./AddWallet";
import type { WalletView } from "../api/types";

// Mirrors keystore.MinPasswordLen on the node.
const MIN_PASSWORD_LEN = 12;

interface CreateVaultProps {
  network: string;
  onReady: (wallet: WalletView) => void;
}

// CreateVault is the first-run flow: set the vault password (which unlocks the
// instance for read-only access on every later launch), then add the first
// wallet (seed + name + spending password). The vault password is held only in
// component state and passed straight into AddWallet so the first wallet can be
// added without re-prompting.
export function CreateVault({ network, onReady }: CreateVaultProps) {
  const [password, setPassword] = useState("");
  const [confirm, setConfirm] = useState("");
  const [vaultPassword, setVaultPassword] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);

  async function handleCreate(e: FormEvent) {
    e.preventDefault();
    setError(null);

    if ([...password].length < MIN_PASSWORD_LEN) {
      setError(`Vault password must be at least ${MIN_PASSWORD_LEN} characters`);
      return;
    }
    if (password !== confirm) {
      setError("Passwords do not match");
      return;
    }

    setLoading(true);
    try {
      await createVault({ password });
      // The vault now exists and is unlocked; move on to add the first wallet.
      setVaultPassword(password);
    } catch (err) {
      setError(err instanceof ApiError ? err.message : "An unexpected error occurred");
    } finally {
      setLoading(false);
    }
  }

  if (vaultPassword !== null) {
    return (
      <div className="screen-settings">
        <Card title="Vault Created">
          <p className="helper-text">
            Your vault is ready. Add your first wallet to begin.
          </p>
        </Card>
        <AddWallet
          network={network}
          knownVaultPassword={vaultPassword}
          onAdded={onReady}
          title="Add Your First Wallet"
          submitLabel="Add Wallet"
        />
      </div>
    );
  }

  return (
    <Card title="Create Vault">
      <form onSubmit={handleCreate}>
        <p className="helper-text">
          The vault password unlocks this app and reveals your wallets in read-only
          mode. Each wallet keeps its own spending password for signing.
        </p>

        <div className="field-group">
          <label htmlFor="vault-password">Vault Password</label>
          <Input
            id="vault-password"
            type="password"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            placeholder={`At least ${MIN_PASSWORD_LEN} characters`}
            aria-label="Vault Password"
          />
        </div>

        <div className="field-group">
          <label htmlFor="vault-password-confirm">Confirm Vault Password</label>
          <Input
            id="vault-password-confirm"
            type="password"
            value={confirm}
            onChange={(e) => setConfirm(e.target.value)}
            placeholder="Re-enter the vault password"
            aria-label="Confirm Vault Password"
          />
        </div>

        {error && (
          <p className="error-text" role="alert">
            {error}
          </p>
        )}

        <Button type="submit" disabled={loading}>
          {loading ? "Creating…" : "Create Vault"}
        </Button>
      </form>
    </Card>
  );
}
