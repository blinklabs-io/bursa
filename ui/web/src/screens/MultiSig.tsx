import { useEffect, useRef, useState } from "react";
import type { Dispatch, SetStateAction } from "react";
import type {
  WalletView,
  MultiSigAccount,
  MultiSigParticipant,
  MultiSigUnsignedTx,
  TxResult,
  WitnessResult,
} from "../api/types";
import {
  createMultiSig,
  multiSigMyKey,
  multiSigBuild,
  multiSigSign,
  multiSigSubmit,
} from "../api/client";
import { Card } from "../components/Card";
import { Input } from "../components/Input";
import { Button } from "../components/Button";
import { CopyButton } from "../components/CopyButton";
import { DownloadButton } from "../components/DownloadButton";
import { MultiSigProgress } from "../components/MultiSigProgress";
import { parseAda } from "../format";
import { errorMessage } from "../errorMessage";

// A 28-byte Blake2b-224 key hash is 56 hex chars. Participant input currently
// accepts only key hashes; vkeys must be hashed before being added here.
const KEY_HASH_RE = /^[0-9a-fA-F]{56}$/;

function useMountedRef() {
  const mounted = useRef(false);
  useEffect(() => {
    mounted.current = true;
    return () => {
      mounted.current = false;
    };
  }, []);
  return mounted;
}

function ErrorText({ message }: { message: string }) {
  return <p role="alert" className="error-text">{message}</p>;
}

// ---------------------------------------------------------------------------
// Create view
// ---------------------------------------------------------------------------

interface ComposeMultiSigProps {
  canSign: boolean;
  onCancel: () => void;
  onCreated: (wallet: WalletView) => void;
}

/**
 * Composes an N-of-M native-script policy into a multi-signature wallet.
 *
 * This lives in the add-wallet flow rather than on a screen of its own, because
 * a multi-signature account is a wallet: it appears in the switcher, it holds a
 * balance, and you spend from it with Send. Creating one is a vault write, which
 * is also where the vault password legitimately comes from.
 */
export function ComposeMultiSig({ canSign, onCancel, onCreated }: ComposeMultiSigProps) {
  const [vaultPassword, setVaultPassword] = useState("");
  const mounted = useMountedRef();
  const [label, setLabel] = useState("");
  const [threshold, setThreshold] = useState("2");
  const [participants, setParticipants] = useState<MultiSigParticipant[]>([]);
  const [invalidBefore, setInvalidBefore] = useState("");
  const [invalidAfter, setInvalidAfter] = useState("");

  // The wallet's own participant identity (fetched with the spending password) so
  // it can be shown to share and added to the policy.
  const [myKeyPassword, setMyKeyPassword] = useState("");
  const [myKeyHash, setMyKeyHash] = useState<string | null>(null);
  const [myKeyVkey, setMyKeyVkey] = useState<string | null>(null);
  const [myKeyError, setMyKeyError] = useState<string | null>(null);
  const [loadingMyKey, setLoadingMyKey] = useState(false);

  // Adding a co-signer participant.
  const [newKeyHash, setNewKeyHash] = useState("");
  const [newLabel, setNewLabel] = useState("");

  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);

  async function handleRevealMyKey() {
    setMyKeyError(null);
    setLoadingMyKey(true);
    try {
      const mk = await multiSigMyKey(myKeyPassword);
      if (!mounted.current) return;
      setMyKeyHash(mk.key_hash_hex);
      setMyKeyVkey(mk.vkey_hex);
      setMyKeyPassword("");
    } catch (e) {
      if (mounted.current) setMyKeyError(errorMessage(e));
    } finally {
      if (mounted.current) setLoadingMyKey(false);
    }
  }

  // Returns whether the participant was added, so callers can decide whether
  // to clear their input (keeping it on failure lets the user fix and retry
  // instead of retyping).
  function addParticipant(keyHash: string, partLabel?: string): boolean {
    const kh = keyHash.trim().toLowerCase();
    if (!KEY_HASH_RE.test(kh)) {
      setError("Key hash must be 56 hex characters (28-byte Blake2b-224).");
      return false;
    }
    if (participants.some((p) => p.key_hash_hex.toLowerCase() === kh)) {
      setError("That participant is already in the policy.");
      return false;
    }
    setError(null);
    setParticipants((prev) => [...prev, { key_hash_hex: kh, ...(partLabel ? { label: partLabel } : {}) }]);
    return true;
  }

  function addMyself() {
    if (myKeyHash) addParticipant(myKeyHash, "me");
  }

  function removeParticipant(idx: number) {
    setParticipants((prev) => prev.filter((_, i) => i !== idx));
  }

  async function handleCreate() {
    setError(null);
    const n = Number(threshold);
    if (!Number.isInteger(n) || n < 1) {
      setError("Threshold must be a positive whole number.");
      return;
    }
    if (n > participants.length) {
      setError(`Threshold ${n} exceeds the ${participants.length} participants.`);
      return;
    }
    if (!label.trim()) {
      setError("A label is required.");
      return;
    }
    const policy = {
      threshold: n,
      participants,
      ...(invalidBefore.trim() ? { invalid_before: Number(invalidBefore.trim()) } : {}),
      ...(invalidAfter.trim() ? { invalid_after: Number(invalidAfter.trim()) } : {}),
    };
    if (
      (policy.invalid_before != null &&
        (!Number.isInteger(policy.invalid_before) || policy.invalid_before < 0)) ||
      (policy.invalid_after != null &&
        (!Number.isInteger(policy.invalid_after) || policy.invalid_after < 0))
    ) {
      setError("Time-lock slots must be whole, non-negative numbers.");
      return;
    }
    setLoading(true);
    try {
      const created = await createMultiSig({
        label: label.trim(),
        policy,
        vault_password: vaultPassword,
      });
      if (!mounted.current) return;
      onCreated(created);
    } catch (e) {
      if (mounted.current) setError(errorMessage(e));
    } finally {
      if (mounted.current) setLoading(false);
    }
  }

  return (
    <Card title="New Multi-sig Account">
      <div className="send-form">
        <label htmlFor="ms-label">Label</label>
        <Input
          id="ms-label"
          type="text"
          placeholder="e.g. Treasury"
          value={label}
          onChange={(e) => setLabel(e.target.value)}
          disabled={loading}
        />

        <label htmlFor="ms-threshold">Required signatures (N)</label>
        <Input
          id="ms-threshold"
          type="text"
          inputMode="numeric"
          placeholder="2"
          value={threshold}
          onChange={(e) => setThreshold(e.target.value)}
          disabled={loading}
        />

        {/* Your own participant key requires a seed-derived CIP-1854 key. */}
        {canSign && (
          <div className="ms-mykey">
            <p className="field-label">Your participant key (CIP-1854)</p>
            {myKeyHash ? (
              <>
                <p className="helper-text">Share this key-hash so others can include you.</p>
                <div className="tx-hash-row">
                  <code className="tx-hash">{myKeyHash}</code>
                  <CopyButton value={myKeyHash} ariaLabel="Copy my key hash" />
                </div>
                {myKeyVkey && (
                  <div className="tx-hash-row">
                    <code className="tx-hash">vkey: {myKeyVkey}</code>
                    <CopyButton value={myKeyVkey} ariaLabel="Copy my verification key" />
                  </div>
                )}
                <Button
                  variant="ghost"
                  onClick={addMyself}
                  disabled={
                    loading ||
                    participants.some((p) => p.key_hash_hex.toLowerCase() === myKeyHash?.toLowerCase())
                  }
                >
                  + Add myself
                </Button>
              </>
            ) : (
              <>
                <p className="helper-text">
                  Enter your spending password to reveal your key-hash to share.
                </p>
                <Input
                  type="password"
                  placeholder="Spending password"
                  value={myKeyPassword}
                  onChange={(e) => setMyKeyPassword(e.target.value)}
                  disabled={loadingMyKey}
                  aria-label="Spending password"
                />
                {myKeyError && <ErrorText message={myKeyError} />}
                <Button variant="ghost" onClick={handleRevealMyKey} disabled={loadingMyKey || !myKeyPassword}>
                  {loadingMyKey ? "Deriving…" : "Reveal my key"}
                </Button>
              </>
            )}
          </div>
        )}

        {/* Co-signer participants. */}
        <p className="field-label">Participants ({participants.length})</p>
        {participants.length > 0 && (
          <ul className="signer-list">
            {participants.map((p, idx) => (
              <li key={p.key_hash_hex} className="ms-participant">
                <code className="tx-hash">{p.label ? `${p.label}: ` : ""}{p.key_hash_hex}</code>
                <Button
                  variant="ghost"
                  onClick={() => removeParticipant(idx)}
                  disabled={loading}
                  aria-label={`Remove ${p.label || p.key_hash_hex}`}
                >
                  Remove
                </Button>
              </li>
            ))}
          </ul>
        )}
        <div className="asset-row">
          <Input
            type="text"
            placeholder="label (optional)"
            value={newLabel}
            onChange={(e) => setNewLabel(e.target.value)}
            disabled={loading}
            aria-label="Participant label"
          />
          <Input
            type="text"
            placeholder="co-signer key-hash (56 hex)"
            value={newKeyHash}
            onChange={(e) => setNewKeyHash(e.target.value)}
            disabled={loading}
            aria-label="Participant key hash"
          />
          <Button
            variant="ghost"
            onClick={() => {
              if (addParticipant(newKeyHash, newLabel.trim() || undefined)) {
                setNewKeyHash("");
                setNewLabel("");
              }
            }}
            disabled={loading || !newKeyHash.trim()}
          >
            Add
          </Button>
        </div>

        {/* Optional time-lock. */}
        <p className="field-label">Time-lock (optional, slots)</p>
        <div className="asset-row">
          <Input
            type="text"
            inputMode="numeric"
            placeholder="valid from slot (invalid_before)"
            value={invalidBefore}
            onChange={(e) => setInvalidBefore(e.target.value)}
            disabled={loading}
            aria-label="Invalid before slot"
          />
          <Input
            type="text"
            inputMode="numeric"
            placeholder="valid until slot (invalid_after)"
            value={invalidAfter}
            onChange={(e) => setInvalidAfter(e.target.value)}
            disabled={loading}
            aria-label="Invalid after slot"
          />
        </div>

        {/* Storing the account is a vault write, so it needs the vault
            password — the same one every other add-wallet path asks for. */}
        <label htmlFor="ms-vault-pw">Vault password</label>
        <Input
          id="ms-vault-pw"
          type="password"
          value={vaultPassword}
          onChange={(e) => setVaultPassword(e.target.value)}
          disabled={loading}
        />

        {error && <ErrorText message={error} />}

        <div className="preview-actions">
          <Button variant="ghost" onClick={onCancel} disabled={loading}>
            Cancel
          </Button>
          <Button
            onClick={handleCreate}
            disabled={loading || participants.length === 0 || !vaultPassword}
          >
            {loading ? "Creating…" : "Create wallet"}
          </Button>
        </div>
      </div>
    </Card>
  );
}

// ---------------------------------------------------------------------------
// Spend flow: build → collect witnesses (progress) → submit
// ---------------------------------------------------------------------------

interface MultiSigSpendProps {
  account: MultiSigAccount;
  canSpend: boolean;
  canSign: boolean;
  onSpent: () => void;
}

/**
 * Spends from a multi-signature wallet: build, collect co-signer witnesses,
 * submit.
 *
 * Send routes here when the active wallet is a script one. A plain wallet signs
 * and submits in one step; this one cannot, because the other signatures come
 * from other people — which is the whole difference, and why it is a mode of
 * Send rather than a separate destination.
 */
export function MultiSigSpend({ account, canSpend, canSign, onSpent }: MultiSigSpendProps) {
  const [to, setTo] = useState("");
  const [ada, setAda] = useState("");
  const [built, setBuilt] = useState<MultiSigUnsignedTx | null>(null);
  const [witnesses, setWitnesses] = useState<string[]>([]);
  const [result, setResult] = useState<TxResult | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);

  function reset() {
    setBuilt(null);
    setWitnesses([]);
    setResult(null);
    setError(null);
    setTo("");
    setAda("");
  }

  async function handleBuild() {
    setError(null);
    let lovelace: string;
    try {
      lovelace = parseAda(ada);
    } catch (e) {
      setError(errorMessage(e));
      return;
    }
    setLoading(true);
    try {
      const res = await multiSigBuild(account.id, { to: to.trim(), lovelace });
      setBuilt(res);
      setWitnesses([]);
    } catch (e) {
      setError(errorMessage(e));
    } finally {
      setLoading(false);
    }
  }

  if (!canSpend) {
    return (
      <Card title="Spend">
        <p className="muted">
          Spending needs a fully synced node and a spending-enabled wallet.
        </p>
      </Card>
    );
  }

  if (result) {
    return (
      <Card title="Transaction Submitted">
        <div className="done-details">
          <p>Your multi-sig transaction has been submitted.</p>
          <p className="field-label">Transaction hash</p>
          <div className="tx-hash-row">
            <code className="tx-hash">{result.tx_hash}</code>
            <CopyButton value={result.tx_hash} ariaLabel="Copy transaction hash" />
          </div>
          <Button onClick={reset}>Spend again</Button>
        </div>
      </Card>
    );
  }

  if (built) {
    return (
      <CollectAndSubmit
        accountId={account.id}
        built={built}
        witnesses={witnesses}
        setWitnesses={setWitnesses}
        canSign={canSign}
        onResult={setResult}
        onSpent={onSpent}
        onBack={reset}
      />
    );
  }

  return (
    <Card title="Spend">
      <div className="send-form">
        <label htmlFor="ms-to">Recipient address</label>
        <Input
          id="ms-to"
          type="text"
          placeholder="addr1..."
          value={to}
          onChange={(e) => setTo(e.target.value)}
          disabled={loading}
        />
        <label htmlFor="ms-ada">Amount (ADA)</label>
        <Input
          id="ms-ada"
          type="text"
          placeholder="0.000000"
          value={ada}
          onChange={(e) => setAda(e.target.value)}
          disabled={loading}
        />
        {error && <ErrorText message={error} />}
        <Button onClick={handleBuild} disabled={loading || !to.trim() || !ada.trim()}>
          {loading ? "Building…" : "Build transaction"}
        </Button>
      </div>
    </Card>
  );
}

interface CollectProps {
  accountId: string;
  built: MultiSigUnsignedTx;
  witnesses: string[];
  setWitnesses: Dispatch<SetStateAction<string[]>>;
  canSign: boolean;
  onResult: (r: TxResult) => void;
  onSpent: () => void;
  onBack: () => void;
}

// CollectAndSubmit shows the unsigned tx for export, optionally lets a local
// seed-backed co-signer sign with their password, accepts pasted witnesses from
// other co-signers, tracks "X of N collected", and submits at the threshold.
function CollectAndSubmit({
  accountId,
  built,
  witnesses,
  setWitnesses,
  canSign,
  onResult,
  onSpent,
  onBack,
}: CollectProps) {
  const [password, setPassword] = useState("");
  const [pasteWitness, setPasteWitness] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [signing, setSigning] = useState(false);
  const [submitting, setSubmitting] = useState(false);

  const collected = witnesses.length;
  const met = collected >= built.threshold;

  function addWitness(w: WitnessResult | string) {
    const cbor = (typeof w === "string" ? w : w.witness_cbor).trim();
    if (!cbor) return;
    setWitnesses((prev) => (prev.includes(cbor) ? prev : [...prev, cbor]));
  }

  async function handleSignHere() {
    setError(null);
    setSigning(true);
    try {
      const res = await multiSigSign({ unsigned_tx_cbor: built.unsigned_tx_cbor, password });
      addWitness(res);
      setPassword("");
    } catch (e) {
      setError(errorMessage(e));
    } finally {
      setSigning(false);
    }
  }

  function handlePaste() {
    if (pasteWitness.trim()) {
      addWitness(pasteWitness);
      setPasteWitness("");
    }
  }

  async function handleSubmit() {
    setError(null);
    setSubmitting(true);
    try {
      const res = await multiSigSubmit(accountId, {
        unsigned_tx_cbor: built.unsigned_tx_cbor,
        witnesses,
      });
      onResult(res);
      onSpent();
    } catch (e) {
      setError(errorMessage(e));
    } finally {
      setSubmitting(false);
    }
  }

  return (
    <Card title="Collect Signatures">
      <div className="send-form">
        <p className="helper-text">
          Share this unsigned transaction with co-signers. Each signs with their
          multi-sig key; collect their witnesses below. Submit once
          {" "}{built.threshold} of {built.required_signers.length} have signed.
        </p>

        <p className="field-label">Unsigned transaction (CBOR)</p>
        <div className="tx-hash-row">
          <code className="tx-hash">{built.unsigned_tx_cbor}</code>
          <CopyButton value={built.unsigned_tx_cbor} ariaLabel="Copy unsigned transaction CBOR" />
          <DownloadButton
            value={built.unsigned_tx_cbor}
            filename="multisig-unsigned-tx.cbor"
            label="Download"
          />
        </div>

        <MultiSigProgress threshold={built.threshold} total={built.required_signers.length} signedCount={collected} />

        {/* Sign locally only when the seed-derived CIP-1854 key is available. */}
        {canSign && (
          <>
            <label htmlFor="ms-sign-pw">Sign with this wallet</label>
            <Input
              id="ms-sign-pw"
              type="password"
              placeholder="Spending password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              disabled={signing}
            />
            <Button variant="ghost" onClick={handleSignHere} disabled={signing || !password}>
              {signing ? "Signing…" : "Sign here"}
            </Button>
          </>
        )}

        {/* Paste a witness from another co-signer. */}
        <label htmlFor="ms-paste">Add a co-signer's witness (CBOR)</label>
        <textarea
          id="ms-paste"
          className="field"
          rows={2}
          value={pasteWitness}
          onChange={(e) => setPasteWitness(e.target.value)}
          placeholder="hex…"
          aria-label="Co-signer witness"
        />
        <Button variant="ghost" onClick={handlePaste} disabled={!pasteWitness.trim()}>
          Add witness
        </Button>

        {error && <ErrorText message={error} />}

        <div className="preview-actions">
          <Button variant="ghost" onClick={onBack} disabled={submitting}>
            Back
          </Button>
          <Button onClick={handleSubmit} disabled={submitting || !met}>
            {submitting ? "Submitting…" : met ? "Submit" : `Need ${built.threshold - collected} more`}
          </Button>
        </div>
      </div>
    </Card>
  );
}
