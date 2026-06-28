import { useState } from "react";
import type { FormEvent } from "react";
import { Card } from "../components/Card";
import { Input } from "../components/Input";
import { Select } from "../components/Select";
import { Button } from "../components/Button";
import { CopyButton } from "../components/CopyButton";
import { addWallet, generateMnemonic, ApiError } from "../api/client";
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

// Mode within the Add Wallet flow.
type Mode = "choose" | "create" | "create-confirm" | "restore";

export function AddWallet({
  network,
  knownVaultPassword,
  onAdded,
  onCancel,
  title = "Add Wallet",
  submitLabel = "Add Wallet",
}: AddWalletProps) {
  const [mode, setMode] = useState<Mode>("choose");

  // Create-new state
  const [generatedMnemonic, setGeneratedMnemonic] = useState("");
  const [confirmed, setConfirmed] = useState(false);
  const [generating, setGenerating] = useState(false);

  // Shared form state
  const [name, setName] = useState("");
  const [mnemonic, setMnemonic] = useState("");
  const [selectedNetwork, setSelectedNetwork] = useState(network);
  const [spendPassword, setSpendPassword] = useState("");
  const [vaultPassword, setVaultPassword] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);

  const needsVaultPassword = knownVaultPassword === undefined;

  // --- "Create new wallet" path -------------------------------------------

  async function handleGenerate() {
    setError(null);
    setGenerating(true);
    try {
      const m = await generateMnemonic();
      setGeneratedMnemonic(m);
      setConfirmed(false);
      setMode("create");
    } catch (err) {
      setError(err instanceof ApiError ? err.message : "Failed to generate mnemonic");
    } finally {
      setGenerating(false);
    }
  }

  function handleProceedToConfirm() {
    if (!confirmed) {
      setError("Please confirm you have saved your recovery phrase before continuing.");
      return;
    }
    setError(null);
    setMode("create-confirm");
  }

  // --- Common submit path (restore or after create-confirm) ---------------

  async function handleSubmit(e: FormEvent) {
    e.preventDefault();
    setError(null);

    const mnemonicToUse = mode === "create-confirm" ? generatedMnemonic : mnemonic.trim().replace(/\s+/g, " ");

    if (mode !== "create-confirm" && mnemonicToUse === "") {
      setError("Recovery phrase is required");
      return;
    }
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
        mnemonic: mnemonicToUse,
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

  // --- Mode: choose -------------------------------------------------------

  if (mode === "choose") {
    return (
      <Card title={title}>
        <p className="helper-text" style={{ marginBottom: "var(--space-3)" }}>
          Create a brand-new wallet with a freshly generated recovery phrase, or
          restore an existing one from a phrase you already have.
        </p>
        <div className="preview-actions" style={{ flexDirection: "column" }}>
          <Button onClick={handleGenerate} disabled={generating}>
            {generating ? "Generating…" : "Create new wallet"}
          </Button>
          <Button variant="ghost" onClick={() => { setError(null); setMode("restore"); }}>
            Restore from recovery phrase
          </Button>
          {onCancel && (
            <Button type="button" variant="ghost" onClick={onCancel}>
              Cancel
            </Button>
          )}
        </div>
        {error && (
          <p className="error-text" role="alert" style={{ marginTop: "var(--space-2)" }}>
            {error}
          </p>
        )}
      </Card>
    );
  }

  // --- Mode: create (show phrase + backup warning) -----------------------

  if (mode === "create") {
    const words = generatedMnemonic.split(" ");
    return (
      <Card title="Save Your Recovery Phrase">
        <p className="helper-text" style={{ marginBottom: "var(--space-2)" }}>
          This is the <strong>only</strong> way to recover your wallet. Write it
          down and store it somewhere safe. Never share it with anyone.
        </p>

        {/* Recovery phrase display */}
        <div className="recovery-phrase-grid" aria-label="Recovery phrase">
          {words.map((word, i) => (
            <div key={i} className="recovery-phrase-word">
              <span className="recovery-phrase-index">{i + 1}</span>
              <span className="recovery-phrase-text">{word}</span>
            </div>
          ))}
        </div>

        <div style={{ margin: "var(--space-3) 0", display: "flex", gap: "var(--space-2)" }}>
          <CopyButton value={generatedMnemonic} label="Copy phrase" />
        </div>

        <div className="backup-warning">
          <p>
            ⚠ If you lose this phrase and forget your spending password, your funds
            cannot be recovered.
          </p>
        </div>

        {/* Required acknowledgement */}
        <label className="checkbox-row" style={{ marginTop: "var(--space-3)" }}>
          <input
            type="checkbox"
            checked={confirmed}
            onChange={(e) => { setConfirmed(e.target.checked); setError(null); }}
            aria-label="I have saved my recovery phrase"
          />
          I have saved my recovery phrase in a secure location
        </label>

        {error && (
          <p className="error-text" role="alert" style={{ marginTop: "var(--space-2)" }}>
            {error}
          </p>
        )}

        <div className="preview-actions" style={{ marginTop: "var(--space-3)" }}>
          <Button onClick={handleProceedToConfirm}>
            Continue
          </Button>
          <Button variant="ghost" onClick={() => { setError(null); setMode("choose"); }}>
            Back
          </Button>
        </div>
      </Card>
    );
  }

  // --- Mode: create-confirm (name + passwords, then submit) ----------------

  if (mode === "create-confirm") {
    return (
      <Card title="Set Up Your New Wallet">
        <p className="helper-text" style={{ marginBottom: "var(--space-3)" }}>
          Your recovery phrase has been generated. Give your wallet a name and
          set a spending password to protect it.
        </p>
        <form onSubmit={handleSubmit}>
          <div className="field-group">
            <label htmlFor="create-name">Wallet Name</label>
            <Input
              id="create-name"
              value={name}
              onChange={(e) => setName(e.target.value)}
              placeholder="e.g. Main"
              aria-label="Wallet Name"
            />
          </div>

          <div className="field-group">
            <label htmlFor="create-network">Network</label>
            <Select
              id="create-network"
              options={NETWORK_OPTIONS}
              value={selectedNetwork}
              onChange={(e) => setSelectedNetwork(e.target.value)}
            />
          </div>

          <div className="field-group">
            <label htmlFor="create-spend-password">Spending Password</label>
            <Input
              id="create-spend-password"
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
              <label htmlFor="create-vault-password">Vault Password</label>
              <Input
                id="create-vault-password"
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
              {loading ? "Creating…" : "Create Wallet"}
            </Button>
            <Button
              type="button"
              variant="ghost"
              onClick={() => { setError(null); setMode("create"); }}
              disabled={loading}
            >
              Back
            </Button>
          </div>
        </form>
      </Card>
    );
  }

  // --- Mode: restore (original form) --------------------------------------

  return (
    <Card title={mode === "restore" ? "Restore Wallet" : title}>
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
          <Button
            type="button"
            variant="ghost"
            onClick={() => { setError(null); setMode("choose"); }}
            disabled={loading}
          >
            Back
          </Button>
          {onCancel && mode !== "restore" && (
            <Button type="button" variant="ghost" onClick={onCancel} disabled={loading}>
              Cancel
            </Button>
          )}
        </div>
      </form>
    </Card>
  );
}
