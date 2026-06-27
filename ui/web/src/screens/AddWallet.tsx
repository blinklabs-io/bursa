import { useState } from "react";
import type { FormEvent } from "react";
import { Card } from "../components/Card";
import { Input } from "../components/Input";
import { Select } from "../components/Select";
import { Button } from "../components/Button";
import { addWallet, ApiError } from "../api/client";
import type { WalletView } from "../api/types";
import { MIN_PASSWORD_LEN, passwordLength } from "../password";

const NETWORK_OPTIONS = [
  { value: "preview", label: "Preview" },
  { value: "preprod", label: "Preprod" },
  { value: "mainnet", label: "Mainnet" },
];

interface AddWalletProps {
  network: string;
  // When the vault password is already known (e.g. just created during the
  // first-run flow), it is passed in and the field is hidden. Otherwise the
  // user re-enters it so the index can be re-sealed.
  knownVaultPassword?: string;
  onAdded: (wallet: WalletView) => void;
  onCancel?: () => void;
  title?: string;
  submitLabel?: string;
}

export function AddWallet({
  network,
  knownVaultPassword,
  onAdded,
  onCancel,
  title = "Add Wallet",
  submitLabel = "Add Wallet",
}: AddWalletProps) {
  const [name, setName] = useState("");
  const [mnemonic, setMnemonic] = useState("");
  const [selectedNetwork, setSelectedNetwork] = useState(network);
  const [spendPassword, setSpendPassword] = useState("");
  const [vaultPassword, setVaultPassword] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);

  const needsVaultPassword = knownVaultPassword === undefined;

  async function handleSubmit(e: FormEvent) {
    e.preventDefault();
    setError(null);

    // Normalise pasted phrases: trim and collapse any whitespace to single spaces.
    const cleanMnemonic = mnemonic.trim().replace(/\s+/g, " ");
    if (cleanMnemonic === "") {
      setError("Recovery phrase is required");
      return;
    }
    // Count code points, not UTF-16 units, to match the server's RuneCount.
    if (passwordLength(spendPassword) < MIN_PASSWORD_LEN) {
      setError(`Spending password must be at least ${MIN_PASSWORD_LEN} characters`);
      return;
    }
    const vaultPw = knownVaultPassword ?? vaultPassword;
    if (vaultPw === "") {
      setError("Vault password is required");
      return;
    }

    setLoading(true);
    try {
      const wallet = await addWallet({
        name: name.trim() || "Wallet",
        mnemonic: cleanMnemonic,
        network: selectedNetwork,
        vault_password: vaultPw,
        spend_password: spendPassword,
      });
      onAdded(wallet);
    } catch (err) {
      setError(err instanceof ApiError ? err.message : "An unexpected error occurred");
    } finally {
      setLoading(false);
    }
  }

  return (
    <Card title={title}>
      <form onSubmit={handleSubmit}>
        <div className="field-group">
          <label htmlFor="add-name">Wallet Name</label>
          <Input
            id="add-name"
            value={name}
            onChange={(e) => setName(e.target.value)}
            placeholder="e.g. Main"
            aria-label="Wallet Name"
          />
        </div>

        <div className="field-group">
          <label htmlFor="add-network">Network</label>
          <Select
            id="add-network"
            options={NETWORK_OPTIONS}
            value={selectedNetwork}
            onChange={(e) => setSelectedNetwork(e.target.value)}
          />
        </div>

        <div className="field-group">
          <label htmlFor="add-mnemonic">Recovery Phrase</label>
          <textarea
            id="add-mnemonic"
            className="field"
            rows={4}
            value={mnemonic}
            onChange={(e) => setMnemonic(e.target.value)}
            placeholder="Enter your 12 or 24 word recovery phrase..."
            aria-label="Recovery Phrase"
          />
        </div>

        <div className="field-group">
          <label htmlFor="add-spend-password">Spending Password</label>
          <Input
            id="add-spend-password"
            type="password"
            value={spendPassword}
            onChange={(e) => setSpendPassword(e.target.value)}
            placeholder={`At least ${MIN_PASSWORD_LEN} characters`}
            aria-label="Spending Password"
          />
          <p className="helper-text">
            Encrypts this wallet&apos;s seed; required to sign and send.
          </p>
        </div>

        {needsVaultPassword && (
          <div className="field-group">
            <label htmlFor="add-vault-password">Vault Password</label>
            <Input
              id="add-vault-password"
              type="password"
              value={vaultPassword}
              onChange={(e) => setVaultPassword(e.target.value)}
              placeholder="Your vault password"
              aria-label="Vault Password"
            />
            <p className="helper-text">Confirms the change to your encrypted vault.</p>
          </div>
        )}

        {error && (
          <p className="error-text" role="alert">
            {error}
          </p>
        )}

        <div className="preview-actions">
          <Button type="submit" disabled={loading}>
            {loading ? "Adding…" : submitLabel}
          </Button>
          {onCancel && (
            <Button type="button" variant="ghost" onClick={onCancel} disabled={loading}>
              Cancel
            </Button>
          )}
        </div>
      </form>
    </Card>
  );
}
