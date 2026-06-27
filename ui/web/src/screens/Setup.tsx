import { useState } from "react";
import type { FormEvent } from "react";
import { Card } from "../components/Card";
import { Input } from "../components/Input";
import { Select } from "../components/Select";
import { Button } from "../components/Button";
import { loadWallet, createKeystore, ApiError } from "../api/client";
import type { Account } from "../api/types";

const NETWORK_OPTIONS = [
  { value: "preview", label: "Preview" },
  { value: "preprod", label: "Preprod" },
  { value: "mainnet", label: "Mainnet" },
];

// Mirrors keystore.MinPasswordLen on the node; the server enforces the same
// floor, this just surfaces it before a round-trip. Keep the two in sync.
const MIN_PASSWORD_LEN = 12;

interface SetupProps {
  network: string;
  onLoaded: (account: Account, spendingEnabled: boolean) => void;
}

export function Setup({ network, onLoaded }: SetupProps) {
  const [mnemonic, setMnemonic] = useState("");
  const [selectedNetwork, setSelectedNetwork] = useState(network);
  const [password, setPassword] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);

  async function handleSubmit(e: FormEvent) {
    e.preventDefault();
    setError(null);
    setLoading(true);
    // Normalise pasted phrases: trim and collapse any whitespace (newlines,
    // double spaces) to single spaces so a stray newline isn't sent to the node.
    const cleanMnemonic = mnemonic.trim().replace(/\s+/g, " ");
    // A whitespace-only password isn't a real password — treat it as read-only.
    const hasPassword = password.trim() !== "";
    // Count code points (spread), not UTF-16 units, to match the server's
    // utf8.RuneCountInString — otherwise an astral-char password could pass here
    // and be rejected by /wallet/keystore.
    if (hasPassword && [...password].length < MIN_PASSWORD_LEN) {
      setError(`Spending password must be at least ${MIN_PASSWORD_LEN} characters`);
      setLoading(false);
      return;
    }
    try {
      let account: Account;
      if (hasPassword) {
        account = await createKeystore({ mnemonic: cleanMnemonic, network: selectedNetwork, password });
      } else {
        account = await loadWallet({ mnemonic: cleanMnemonic, network: selectedNetwork });
      }
      onLoaded(account, hasPassword);
    } catch (err) {
      if (err instanceof ApiError) {
        setError(err.message);
      } else {
        setError("An unexpected error occurred");
      }
    } finally {
      setLoading(false);
    }
  }

  return (
    <Card title="Load Wallet">
      <form onSubmit={handleSubmit}>
        <div className="field-group">
          <label htmlFor="setup-network">Network</label>
          <Select
            id="setup-network"
            options={NETWORK_OPTIONS}
            value={selectedNetwork}
            onChange={(e) => setSelectedNetwork(e.target.value)}
          />
        </div>

        <div className="field-group">
          <label htmlFor="setup-mnemonic">Mnemonic</label>
          <textarea
            id="setup-mnemonic"
            className="field"
            rows={4}
            value={mnemonic}
            onChange={(e) => setMnemonic(e.target.value)}
            placeholder="Enter your 12 or 24 word recovery phrase..."
            aria-label="Mnemonic"
          />
        </div>

        <div className="field-group">
          <label htmlFor="setup-password">Spending Password</label>
          <Input
            id="setup-password"
            type="password"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            placeholder="Optional"
            aria-label="Spending Password"
          />
          <p className="helper-text">
            Set a password to enable sending; leave blank for read-only.
          </p>
        </div>

        {error && <p className="error-text" role="alert">{error}</p>}

        <Button type="submit" disabled={loading}>
          {loading ? "Loading…" : "Load Wallet"}
        </Button>
      </form>
    </Card>
  );
}
