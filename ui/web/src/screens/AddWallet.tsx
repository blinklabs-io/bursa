import { useState } from "react";
import type { FormEvent } from "react";
import { Card } from "../components/Card";
import { Input } from "../components/Input";
import { Button } from "../components/Button";
import { CopyButton } from "../components/CopyButton";
import { addWallet, addHardwareWallet, generateMnemonic, ApiError } from "../api/client";
import { connectHardware, connectDevice } from "../hw";
import type { HardwareKind, HardwareSigner } from "../hw";
import { setDeviceKind, setKeystoneXfp } from "../hw/deviceKind";
import { parseAccountSyncUR } from "../hw/keystone";
import { useKeystoneQRBridge } from "../components/KeystoneQRModal";
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
type Mode = "choose" | "create" | "create-confirm" | "restore" | "hardware";

// Selectable hardware devices.
const DEVICE_OPTIONS: { kind: HardwareKind; label: string; disabled?: boolean }[] = [
  { kind: "ledger", label: "Ledger" },
  { kind: "trezor", label: "Trezor" },
  { kind: "keystone", label: "Keystone" },
];

const DEVICE_LABELS: Record<HardwareKind, string> = {
  ledger: "Ledger",
  trezor: "Trezor",
  keystone: "Keystone",
};

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

  // Hardware-wallet state: which device, which account, and (for a
  // cloud-reaching device like Trezor) the external-connection consent.
  const [deviceKind, setDeviceKindState] = useState<HardwareKind>("ledger");
  const [accountIndex, setAccountIndex] = useState("0");
  const [externalConsent, setExternalConsent] = useState(false);
  // Keystone has two local transports; QR (air-gapped) is the primary one.
  const [keystoneTransport, setKeystoneTransport] = useState<"qr" | "usb">("qr");
  // The QR modal bridge is always mounted (hooks can't be conditional); it
  // renders nothing until a Keystone QR flow drives it.
  const { bridge: keystoneBridge, element: keystoneModal } = useKeystoneQRBridge();

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

  // --- Hardware-wallet path -------------------------------------------------
  // No mnemonic and no spending password: the device holds the private key
  // and signs every transaction directly. Only the account-level xpub is
  // read from the device and stored (watch-only). The chosen device kind is
  // recorded client-side so Send later reconnects the same device.

  async function handleHardwareConnect(e: FormEvent) {
    e.preventDefault();
    setError(null);

    const vaultPw = knownVaultPassword ?? vaultPassword;
    if (vaultPw === "") {
      setError("Vault password is required");
      return;
    }
    // Reject an empty field explicitly: Number("") is 0, which would otherwise
    // pass the integer/range check and silently import account 0 — a different
    // account than a user who cleared the field may intend.
    const trimmedIndex = accountIndex.trim();
    const account = Number(trimmedIndex);
    if (
      trimmedIndex === "" ||
      !Number.isInteger(account) ||
      account < 0 ||
      account >= 0x80000000
    ) {
      setError("Account index must be an integer from 0 to 2147483647");
      return;
    }

    setLoading(true);
    let session: HardwareSigner | null = null;
    const defaultName = `${DEVICE_LABELS[deviceKind]} Wallet`;
    try {
      if (deviceKind === "keystone" && keystoneTransport === "qr") {
        // Air-gapped account-sync: the account xpub arrives on its OWN QR
        // (crypto-multi-accounts), scanned through the webcam modal — never a
        // network round-trip and never the sign registry. parseAccountSyncUR
        // re-encodes it through the shared xpub helper (byte-identical to every
        // other device) and hands back the device master fingerprint we must
        // remember so Send can sign over QR later.
        let xfp: string;
        let xpub: string;
        try {
          const scanned = await keystoneBridge.scanResponse();
          const sync = await parseAccountSyncUR(scanned, account);
          xpub = sync.xpub;
          xfp = sync.xfp;
        } finally {
          keystoneBridge.close();
        }
        const wallet = await addHardwareWallet(name.trim() || defaultName, xpub, account, network, vaultPw);
        setDeviceKind(wallet.id, "keystone");
        // The xfp is a client-only hint (localStorage), not server-persisted
        // wallet state. If it is ever missing or cleared, Send detects that
        // (needsKeystoneResync) and prompts an account-sync re-scan to recover
        // it before any QR signing — so a lost hint is non-fatal.
        setKeystoneXfp(wallet.id, xfp);
        onAdded(wallet);
        return;
      }

      // Ledger, Trezor, and Keystone-over-USB connect to a live device and read
      // the account xpub from it. For Trezor the consent box gates the connect
      // button, so this reports the given approval; the real init() gate lives
      // inside connectTrezor. For local devices the callback is ignored.
      session =
        deviceKind === "keystone"
          ? await connectDevice("keystone", { transport: "usb" })
          : await connectHardware(deviceKind, async () => externalConsent);
      const xpub = await session.getAccountXpub(account);
      const wallet = await addHardwareWallet(
        name.trim() || defaultName,
        xpub,
        account,
        network,
        vaultPw,
      );
      // Remember which device backs this wallet so Send reconnects it.
      // TODO(follow-up): this hint is client-only (localStorage); persist the
      // device kind on the server-side wallet record so it survives a browser
      // wipe or another browser. Send's post-failure device picker mitigates
      // the wrong-signer risk until then (see hw/deviceKind.ts).
      setDeviceKind(wallet.id, deviceKind);
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
          hardware wallet (Ledger or Trezor).
        </p>
        <div className="preview-actions" style={{ flexDirection: "column" }}>
          <Button onClick={handleGenerate} disabled={generating}>
            {generating ? "Generating…" : "Create new wallet"}
          </Button>
          <Button variant="ghost" onClick={() => { setError(null); setMode("restore"); }} disabled={generating}>
            Restore from recovery phrase
          </Button>
          <Button variant="ghost" onClick={() => { setError(null); setMode("hardware"); }} disabled={generating}>
            Connect hardware wallet
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

  // --- Mode: hardware (connect a device, no mnemonic or spending password) --

  if (mode === "hardware") {
    const deviceLabel = DEVICE_LABELS[deviceKind];
    // Trezor reaches connect.trezor.io; its connect is gated on explicit
    // acknowledgement (consent law). Ledger (WebHID) and Keystone (local QR/USB)
    // need no such gate.
    const needsExternalConsent = deviceKind === "trezor";
    const isKeystone = deviceKind === "keystone";
    const isKeystoneQR = isKeystone && keystoneTransport === "qr";
    const connectVerb = isKeystoneQR ? "Scan account QR" : `Connect ${deviceLabel}`;
    return (
      <Card title="Connect hardware wallet">
        <form onSubmit={handleHardwareConnect}>
          <fieldset className="field-group" style={{ border: "none", padding: 0, margin: 0 }}>
            <legend className="field-label">Device</legend>
            {DEVICE_OPTIONS.map((opt) => (
              <label className="checkbox-row" key={opt.kind}>
                <input
                  type="radio"
                  name="hw-device"
                  value={opt.kind}
                  checked={deviceKind === opt.kind}
                  disabled={opt.disabled || loading}
                  onChange={() => {
                    setError(null);
                    setExternalConsent(false);
                    setDeviceKindState(opt.kind);
                  }}
                  aria-label={opt.label}
                />
                {opt.label}
              </label>
            ))}
          </fieldset>

          {isKeystone && (
            <fieldset className="field-group" style={{ border: "none", padding: 0, margin: 0 }}>
              <legend className="field-label">Connection</legend>
              <label className="checkbox-row">
                <input
                  type="radio"
                  name="hw-keystone-transport"
                  value="qr"
                  checked={keystoneTransport === "qr"}
                  disabled={loading}
                  onChange={() => { setError(null); setKeystoneTransport("qr"); }}
                  aria-label="Air-gapped QR"
                />
                Air-gapped QR (offline)
              </label>
              <label className="checkbox-row">
                <input
                  type="radio"
                  name="hw-keystone-transport"
                  value="usb"
                  checked={keystoneTransport === "usb"}
                  disabled={loading}
                  onChange={() => { setError(null); setKeystoneTransport("usb"); }}
                  aria-label="USB"
                />
                USB cable
              </label>
            </fieldset>
          )}

          <div className="field-group">
            <label htmlFor="hw-name">Wallet Name</label>
            <Input
              id="hw-name"
              value={name}
              onChange={(e) => setName(e.target.value)}
              placeholder={`e.g. ${deviceLabel} Main`}
              aria-label="Wallet Name"
            />
          </div>

          <NetworkDisplay network={network} />

          <div className="field-group">
            <label htmlFor="hw-account-index">Account Index</label>
            <Input
              id="hw-account-index"
              type="number"
              min={0}
              max={0x7fffffff}
              step={1}
              value={accountIndex}
              onChange={(e) => setAccountIndex(e.target.value)}
              aria-label="Account Index"
            />
          </div>

          {needsVaultPassword && (
            <div className="field-group">
              <label htmlFor="hw-vault-password">Vault Password</label>
              <Input
                id="hw-vault-password"
                type="password"
                value={vaultPassword}
                onChange={(e) => setVaultPassword(e.target.value)}
                placeholder="Your vault password"
                aria-label="Vault Password"
              />
              <p className="helper-text">Confirms the change to your encrypted vault.</p>
            </div>
          )}

          {needsExternalConsent && (
            <label className="checkbox-row">
              <input
                type="checkbox"
                checked={externalConsent}
                onChange={(e) => setExternalConsent(e.target.checked)}
                aria-label="Approve contacting connect.trezor.io to reach the Trezor"
              />
              I understand this connects to connect.trezor.io to reach my {deviceLabel},
              which leaves my node.
            </label>
          )}

          <p className="helper-text">
            {isKeystoneQR
              ? "On your Keystone, open the Cardano account and choose Sync / Connect Software Wallet, then scan the account QR it shows. No spending password is needed — the device signs every transaction."
              : `Connect your ${deviceLabel} device, open the Cardano app, then click Connect. No spending password is needed — the device signs every transaction.`}
          </p>

          {error && (
            <p className="error-text" role="alert">
              {error}
            </p>
          )}

          <div className="preview-actions">
            <Button
              type="submit"
              disabled={loading || (needsExternalConsent && !externalConsent)}
            >
              {loading ? (isKeystoneQR ? "Scanning…" : "Connecting…") : connectVerb}
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
        {keystoneModal}
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
