import { useState } from "react";
import type { FormEvent } from "react";
import { Card } from "../components/Card";
import { Input } from "../components/Input";
import { Button } from "../components/Button";
import { unlockVault, ApiError } from "../api/client";
import type { WalletView } from "../api/types";

interface UnlockVaultProps {
  walletCount: number;
  onUnlocked: (wallets: WalletView[]) => void;
}

// UnlockVault is the returning-user flow: the vault password ONLY (no seed
// re-entry). It reveals the wallet list and grants read-only access across all
// wallets; spending later requires the active wallet's spending password.
export function UnlockVault({ walletCount, onUnlocked }: UnlockVaultProps) {
  const [password, setPassword] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);

  async function handleSubmit(e: FormEvent) {
    e.preventDefault();
    setError(null);
    setLoading(true);
    try {
      const wallets = await unlockVault({ password });
      onUnlocked(wallets);
    } catch (err) {
      setError(err instanceof ApiError ? err.message : "An unexpected error occurred");
    } finally {
      setLoading(false);
    }
  }

  return (
    <Card title="Unlock Vault">
      <form onSubmit={handleSubmit}>
        <p className="helper-text">
          {walletCount === 1
            ? "Enter your vault password to unlock your wallet."
            : `Enter your vault password to unlock your ${walletCount} wallets.`}
        </p>

        <div className="field-group">
          <label htmlFor="unlock-password">Vault Password</label>
          <Input
            id="unlock-password"
            type="password"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            placeholder="Your vault password"
            aria-label="Vault Password"
            autoFocus
          />
        </div>

        {error && (
          <p className="error-text" role="alert">
            {error}
          </p>
        )}

        <Button type="submit" disabled={loading}>
          {loading ? "Unlocking…" : "Unlock"}
        </Button>
      </form>
    </Card>
  );
}
