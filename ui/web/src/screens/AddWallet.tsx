import { useState } from "react";
import type { FormEvent } from "react";
import { Card } from "../components/Card";
import { Input } from "../components/Input";
import { Button } from "../components/Button";
import { CopyButton } from "../components/CopyButton";
import { addWallet, addHardwareWallet, generateMnemonic, ApiError } from "../api/client";
import { connectLedger } from "../hw/ledger";
import type { LedgerSession } from "../hw/ledger";
import type { WalletView } from "../api/types";
import { MIN_PASSWORD_LEN, passwordLength } from "../password";
import { CHALLENGE_WORD_COUNT, isChallengeAnswerCorrect, pickChallengeIndices, validateChallenge } from "../phraseChallenge";

const NETWORK_LABELS: Record<string, string> = {
  preview: "Preview",
  preprod: "Preprod",
  mainnet: "Mainnet",
};

function networkLabel(network: string): string {
  return NETWORK_LABELS[network] ?? network ?? "";
}

// NetworkDisplay shows the network the wallet will be created on, read-only.
// The embedded node runs exactly one network and the backend rejects any
// mismatch, so there is nothing to choose — the value is shown for context.
function NetworkDisplay({ network }: { network: string }) {
  return (
    <div className="field-group">
      <label>Network</label>
      <p className="helper-text" data-testid="wallet-network">
        {networkLabel(network)} — set by the connected node
      </p>
    </div>
  );
}

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
type Mode = "choose" | "create" | "create-confirm" | "restore" | "ledger";

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

  // Recovery-phrase re-entry challenge (create-confirm gate): a few random
  // word positions the user must retype correctly before submit unlocks.
  const [challengeIndices, setChallengeIndices] = useState<number[]>([]);
  const [challengeAnswers, setChallengeAnswers] = useState<Record<number, string>>({});

  // Shared form state
  const [name, setName] = useState("");
  const [mnemonic, setMnemonic] = useState("");
  const [spendPassword, setSpendPassword] = useState("");
  const [vaultPassword, setVaultPassword] = useState("");
  const [ledgerAccountIndex, setLedgerAccountIndex] = useState("0");
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
    // Freshly pick which word positions to quiz on each time this step is
    // entered, and clear any answers left over from a previous attempt.
    const wordCount = generatedMnemonic.split(" ").length;
    setChallengeIndices(pickChallengeIndices(wordCount, Math.min(CHALLENGE_WORD_COUNT, wordCount)));
    setChallengeAnswers({});
    setMode("create-confirm");
  }

  function handleChallengeAnswerChange(index: number, value: string) {
    setChallengeAnswers((prev) => ({ ...prev, [index]: value }));
  }

  const generatedWords = generatedMnemonic.split(" ");
  const challengePassed = validateChallenge(generatedWords, challengeIndices, challengeAnswers);

  // --- Common submit path (restore or after create-confirm) ---------------

  async function handleSubmit(e: FormEvent) {
    e.preventDefault();
    setError(null);

    const mnemonicToUse = mode === "create-confirm" ? generatedMnemonic : mnemonic.trim().replace(/\s+/g, " ");

    if (mode !== "create-confirm" && mnemonicToUse === "") {
      setError("Recovery phrase is required");
      return;
    }
    if (mode === "create-confirm" && !challengePassed) {
      setError("Please correctly re-enter the requested words from your recovery phrase.");
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
        network,
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

  // --- "Connect Ledger" path -----------------------------------------------
  // No mnemonic and no spending password: the device holds the private key
  // and signs every transaction directly. Only the account-level xpub is
  // read from the device and stored (watch-only).

  async function handleLedgerConnect(e: FormEvent) {
    e.preventDefault();
    setError(null);

    const vaultPw = knownVaultPassword ?? vaultPassword;
    if (vaultPw === "") {
      setError("Vault password is required");
      return;
    }
    // Reject an empty field explicitly: Number("") is 0, which would otherwise
    // pass the integer/range check and silently import Ledger account 0 — a
    // different account than a user who cleared the field may intend.
    const trimmedIndex = ledgerAccountIndex.trim();
    const accountIndex = Number(trimmedIndex);
    if (
      trimmedIndex === "" ||
      !Number.isInteger(accountIndex) ||
      accountIndex < 0 ||
      accountIndex >= 0x80000000
    ) {
      setError("Account index must be an integer from 0 to 2147483647");
      return;
    }

    setLoading(true);
    let session: LedgerSession | null = null;
    try {
      session = await connectLedger();
      const xpub = await session.getAccountXpub(accountIndex);
      const wallet = await addHardwareWallet(
        name.trim() || "Ledger Wallet",
        xpub,
        accountIndex,
        network,
        vaultPw,
      );
      onAdded(wallet);
    } catch (err) {
      setError(err instanceof Error ? err.message : "An unexpected error occurred");
    } finally {
      if (session) await session.close().catch(() => {});
      setLoading(false);
    }
  }

  // --- Mode: choose -------------------------------------------------------

  if (mode === "choose") {
    return (
      <Card title={title}>
        <p className="helper-text" style={{ marginBottom: "var(--space-3)" }}>
          Create a brand-new wallet with a freshly generated recovery phrase,
          restore an existing one from a phrase you already have, or connect a
          Ledger hardware wallet.
        </p>
        <div className="preview-actions" style={{ flexDirection: "column" }}>
          <Button onClick={handleGenerate} disabled={generating}>
            {generating ? "Generating…" : "Create new wallet"}
          </Button>
          <Button variant="ghost" onClick={() => { setError(null); setMode("restore"); }} disabled={generating}>
            Restore from recovery phrase
          </Button>
          <Button variant="ghost" onClick={() => { setError(null); setMode("ledger"); }} disabled={generating}>
            Connect Ledger
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
          <CopyButton value={generatedMnemonic} />
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
          <Button
            variant="ghost"
            onClick={() => {
              setError(null);
              setGeneratedMnemonic("");
              setConfirmed(false);
              setMode("choose");
            }}
          >
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

        {/* Re-entry challenge: proves the phrase was actually saved before
            the final submit is allowed. */}
        <div className="field-group" aria-label="Recovery phrase confirmation">
          <p className="helper-text">
            Prove you saved your recovery phrase by re-entering the words below.
          </p>
          {challengeIndices.map((idx) => {
            const answer = challengeAnswers[idx] ?? "";
            const answered = answer.trim() !== "";
            const correct = isChallengeAnswerCorrect(generatedWords, idx, answer);
            return (
              <div className="field-group" key={idx}>
                <label htmlFor={`challenge-word-${idx}`}>Word #{idx + 1}</label>
                <Input
                  id={`challenge-word-${idx}`}
                  value={answer}
                  onChange={(e) => handleChallengeAnswerChange(idx, e.target.value)}
                  aria-label={`Word #${idx + 1}`}
                  autoComplete="off"
                  autoCapitalize="none"
                  spellCheck={false}
                />
                {answered && (
                  correct ? (
                    <p className="success-text" role="status" aria-live="polite">Correct</p>
                  ) : (
                    <p className="error-text" role="status" aria-live="polite">Incorrect</p>
                  )
                )}
              </div>
            );
          })}
        </div>

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

          <NetworkDisplay network={network} />

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

          {!challengePassed && (
            <p className="helper-text">
              Correctly re-enter the requested words above to enable wallet creation.
            </p>
          )}

          {error && (
            <p className="error-text" role="alert">
              {error}
            </p>
          )}

          <div className="preview-actions">
            <Button type="submit" disabled={loading || !challengePassed}>
              {loading ? "Creating…" : submitLabel}
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

  // --- Mode: ledger (Connect Ledger, no mnemonic or spending password) ----

  if (mode === "ledger") {
    return (
      <Card title="Connect Ledger">
        <form onSubmit={handleLedgerConnect}>
          <div className="field-group">
            <label htmlFor="ledger-name">Wallet Name</label>
            <Input
              id="ledger-name"
              value={name}
              onChange={(e) => setName(e.target.value)}
              placeholder="e.g. Ledger Main"
              aria-label="Wallet Name"
            />
          </div>

          <NetworkDisplay network={network} />

          <div className="field-group">
            <label htmlFor="ledger-account-index">Account Index</label>
            <Input
              id="ledger-account-index"
              type="number"
              min={0}
              max={0x7fffffff}
              step={1}
              value={ledgerAccountIndex}
              onChange={(e) => setLedgerAccountIndex(e.target.value)}
              aria-label="Account Index"
            />
          </div>

          {needsVaultPassword && (
            <div className="field-group">
              <label htmlFor="ledger-vault-password">Vault Password</label>
              <Input
                id="ledger-vault-password"
                type="password"
                value={vaultPassword}
                onChange={(e) => setVaultPassword(e.target.value)}
                placeholder="Your vault password"
                aria-label="Vault Password"
              />
              <p className="helper-text">Confirms the change to your encrypted vault.</p>
            </div>
          )}

          <p className="helper-text">
            Connect your Ledger device, open the Cardano app, then click Connect Ledger.
            No spending password is needed — the device signs every transaction.
          </p>

          {error && (
            <p className="error-text" role="alert">
              {error}
            </p>
          )}

          <div className="preview-actions">
            <Button type="submit" disabled={loading}>
              {loading ? "Connecting…" : "Connect Ledger"}
            </Button>
            <Button
              type="button"
              variant="ghost"
              onClick={() => { setError(null); setMode("choose"); }}
              disabled={loading}
            >
              Back
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

  // --- Mode: restore (original form) --------------------------------------

  return (
    <Card title="Restore Wallet">
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

        <NetworkDisplay network={network} />

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
