import { useEffect, useState } from "react";
import type { Dispatch, SetStateAction } from "react";
import type {
  MultiSigAccount,
  MultiSigParticipant,
  MultiSigUnsignedTx,
  TxResult,
  WitnessResult,
} from "../api/types";
import {
  listMultiSig,
  createMultiSig,
  deleteMultiSig,
  multiSigMyKey,
  multiSigBalance,
  multiSigBuild,
  multiSigSign,
  multiSigSubmit,
  ApiError,
} from "../api/client";
import { Card } from "../components/Card";
import { Input } from "../components/Input";
import { Button } from "../components/Button";
import { CopyButton } from "../components/CopyButton";
import { DownloadButton } from "../components/DownloadButton";
import { formatAda, parseAda } from "../format";

function errorMessage(err: unknown): string {
  if (err instanceof ApiError) return err.message;
  if (err instanceof Error) return err.message;
  return String(err);
}

// A 28-byte Blake2b-224 key-hash is 56 hex chars; a 32-byte vkey is 64. We accept
// either when adding a participant and normalize to a key-hash via the field the
// user pastes — the backend re-validates length, so this is a UX pre-check only.
const KEY_HASH_RE = /^[0-9a-fA-F]{56}$/;

// ---------------------------------------------------------------------------
// List view
// ---------------------------------------------------------------------------

interface ListViewProps {
  accounts: MultiSigAccount[];
  onCreate: () => void;
  onOpen: (acct: MultiSigAccount) => void;
}

function ListView({ accounts, onCreate, onOpen }: ListViewProps) {
  return (
    <Card title="Multi-sig Accounts">
      <p className="helper-text">
        Saved native-script accounts: an N-of-M signing policy (optionally
        time-locked) with a shared script address. Fund the script address, then
        spend by collecting a threshold of co-signer witnesses.
      </p>
      {accounts.length === 0 ? (
        <p className="muted">No multi-sig accounts yet.</p>
      ) : (
        <ul className="ms-account-list">
          {accounts.map((a) => (
            <li key={a.id} className="ms-account-item">
              <button className="ms-account-open" onClick={() => onOpen(a)}>
                <span className="ms-account-label">{a.label}</span>
                <span className="ms-account-policy">
                  {a.policy.threshold}-of-{a.policy.participants.length}
                  {(a.policy.invalid_before != null || a.policy.invalid_after != null) && " · time-locked"}
                </span>
                <span className="mono ms-account-addr">{a.script_address}</span>
              </button>
            </li>
          ))}
        </ul>
      )}
      <Button onClick={onCreate}>+ New multi-sig account</Button>
    </Card>
  );
}

// ---------------------------------------------------------------------------
// Create view
// ---------------------------------------------------------------------------

interface CreateViewProps {
  onCancel: () => void;
  onCreated: (acct: MultiSigAccount) => void;
}

function CreateView({ onCancel, onCreated }: CreateViewProps) {
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
      setMyKeyHash(mk.key_hash_hex);
      setMyKeyVkey(mk.vkey_hex);
    } catch (e) {
      setMyKeyError(errorMessage(e));
    } finally {
      setLoadingMyKey(false);
    }
  }

  function addParticipant(keyHash: string, partLabel?: string) {
    const kh = keyHash.trim().toLowerCase();
    if (!KEY_HASH_RE.test(kh)) {
      setError("Key hash must be 56 hex characters (28-byte Blake2b-224).");
      return;
    }
    if (participants.some((p) => p.key_hash_hex.toLowerCase() === kh)) {
      setError("That participant is already in the policy.");
      return;
    }
    setError(null);
    setParticipants((prev) => [...prev, { key_hash_hex: kh, ...(partLabel ? { label: partLabel } : {}) }]);
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
      (policy.invalid_before != null && !Number.isInteger(policy.invalid_before)) ||
      (policy.invalid_after != null && !Number.isInteger(policy.invalid_after))
    ) {
      setError("Time-lock slots must be whole numbers.");
      return;
    }
    setLoading(true);
    try {
      const acct = await createMultiSig({ label: label.trim(), policy });
      onCreated(acct);
    } catch (e) {
      setError(errorMessage(e));
    } finally {
      setLoading(false);
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

        {/* Your own participant key, to share and to add to the policy. */}
        <div className="ms-mykey">
          <p className="field-label">Your participant key (CIP-1854)</p>
          {myKeyHash ? (
            <>
              <p className="helper-text">Share this key-hash so others can include you.</p>
              <div className="tx-hash-row">
                <code className="tx-hash">{myKeyHash}</code>
                <CopyButton value={myKeyHash} />
              </div>
              {myKeyVkey && (
                <div className="tx-hash-row">
                  <code className="tx-hash">vkey: {myKeyVkey}</code>
                  <CopyButton value={myKeyVkey} />
                </div>
              )}
              <Button
                variant="ghost"
                onClick={addMyself}
                disabled={loading || participants.some((p) => p.key_hash_hex === myKeyHash)}
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
              {myKeyError && <p role="alert" className="error-text">{myKeyError}</p>}
              <Button variant="ghost" onClick={handleRevealMyKey} disabled={loadingMyKey || !myKeyPassword}>
                {loadingMyKey ? "Deriving…" : "Reveal my key"}
              </Button>
            </>
          )}
        </div>

        {/* Co-signer participants. */}
        <p className="field-label">Participants ({participants.length})</p>
        {participants.length > 0 && (
          <ul className="signer-list">
            {participants.map((p, idx) => (
              <li key={p.key_hash_hex} className="ms-participant">
                <code className="tx-hash">{p.label ? `${p.label}: ` : ""}{p.key_hash_hex}</code>
                <Button variant="ghost" onClick={() => removeParticipant(idx)} disabled={loading}>
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
              addParticipant(newKeyHash, newLabel.trim() || undefined);
              setNewKeyHash("");
              setNewLabel("");
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

        {error && <p role="alert" className="error-text">{error}</p>}

        <div className="preview-actions">
          <Button variant="ghost" onClick={onCancel} disabled={loading}>
            Cancel
          </Button>
          <Button onClick={handleCreate} disabled={loading || participants.length === 0}>
            {loading ? "Creating…" : "Create account"}
          </Button>
        </div>
      </div>
    </Card>
  );
}

// ---------------------------------------------------------------------------
// Detail view (receive address, balance, policy, spend flow)
// ---------------------------------------------------------------------------

interface DetailViewProps {
  account: MultiSigAccount;
  canSpend: boolean;
  onBack: () => void;
  onDeleted: () => void;
}

function DetailView({ account, canSpend, onBack, onDeleted }: DetailViewProps) {
  const [balance, setBalance] = useState<string | null>(null);
  const [balanceError, setBalanceError] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;
    multiSigBalance(account.id)
      .then((b) => {
        if (!cancelled) setBalance(b.lovelace);
      })
      .catch((e) => {
        if (!cancelled) setBalanceError(errorMessage(e));
      });
    return () => {
      cancelled = true;
    };
  }, [account.id]);

  async function handleDelete() {
    try {
      await deleteMultiSig(account.id);
      onDeleted();
    } catch {
      // Surfacing a delete error is low value here; the list refresh on back
      // will reflect the true state.
      onDeleted();
    }
  }

  return (
    <div className="ms-detail">
      <Card title={account.label}>
        <p className="field-label">Script address (receive)</p>
        <p className="mono address-full">{account.script_address}</p>
        <CopyButton value={account.script_address} />

        <dl className="preview-summary">
          <div className="dl-row">
            <dt>Policy</dt>
            <dd>
              {account.policy.threshold}-of-{account.policy.participants.length}
              {account.policy.invalid_before != null && ` · from slot ${account.policy.invalid_before}`}
              {account.policy.invalid_after != null && ` · until slot ${account.policy.invalid_after}`}
            </dd>
          </div>
          <div className="dl-row">
            <dt>Balance</dt>
            <dd>{balanceError ? "—" : balance != null ? `${formatAda(balance)} ADA` : "…"}</dd>
          </div>
        </dl>

        <p className="field-label">Participants</p>
        <ul className="signer-list">
          {account.policy.participants.map((p) => (
            <li key={p.key_hash_hex}>
              <code className="tx-hash">{p.label ? `${p.label}: ` : ""}{p.key_hash_hex}</code>
            </li>
          ))}
        </ul>

        <div className="preview-actions">
          <Button variant="ghost" onClick={onBack}>
            Back
          </Button>
          <Button variant="ghost" onClick={handleDelete}>
            Delete
          </Button>
        </div>
      </Card>

      <SpendFlow account={account} canSpend={canSpend} />
    </div>
  );
}

// ---------------------------------------------------------------------------
// Spend flow: build → collect witnesses (progress) → submit
// ---------------------------------------------------------------------------

interface SpendFlowProps {
  account: MultiSigAccount;
  canSpend: boolean;
}

function SpendFlow({ account, canSpend }: SpendFlowProps) {
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
            <CopyButton value={result.tx_hash} />
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
        onResult={setResult}
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
        {error && <p role="alert" className="error-text">{error}</p>}
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
  onResult: (r: TxResult) => void;
  onBack: () => void;
}

// CollectAndSubmit shows the unsigned tx for export, lets a co-signer on THIS
// instance sign with their password, accepts pasted witnesses from other
// co-signers, tracks "X of N collected", and submits once the threshold is met.
function CollectAndSubmit({ accountId, built, witnesses, setWitnesses, onResult, onBack }: CollectProps) {
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
          <CopyButton value={built.unsigned_tx_cbor} />
          <DownloadButton
            value={built.unsigned_tx_cbor}
            filename="multisig-unsigned-tx.cbor"
            label="Download"
          />
        </div>

        <p className="ms-progress">
          {collected} of {built.threshold} collected
          {collected > 0 && ` (${collected} witness${collected === 1 ? "" : "es"})`}
        </p>

        {/* Sign on this instance. */}
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

        {error && <p role="alert" className="error-text">{error}</p>}

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

// ---------------------------------------------------------------------------
// Top-level screen
// ---------------------------------------------------------------------------

type View = "list" | "create" | "detail";

interface MultiSigProps {
  canSpend: boolean;
}

export function MultiSig({ canSpend }: MultiSigProps) {
  const [view, setView] = useState<View>("list");
  const [accounts, setAccounts] = useState<MultiSigAccount[]>([]);
  const [selected, setSelected] = useState<MultiSigAccount | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);

  function refresh() {
    setLoading(true);
    listMultiSig()
      .then((a) => {
        setAccounts(a);
        setError(null);
      })
      .catch((e) => setError(errorMessage(e)))
      .finally(() => setLoading(false));
  }

  useEffect(refresh, []);

  if (view === "create") {
    return (
      <CreateView
        onCancel={() => setView("list")}
        onCreated={(acct) => {
          setSelected(acct);
          refresh();
          setView("detail");
        }}
      />
    );
  }

  if (view === "detail" && selected) {
    return (
      <DetailView
        account={selected}
        canSpend={canSpend}
        onBack={() => {
          setSelected(null);
          refresh();
          setView("list");
        }}
        onDeleted={() => {
          setSelected(null);
          refresh();
          setView("list");
        }}
      />
    );
  }

  if (loading) return <p>Loading…</p>;
  if (error)
    return (
      <p role="alert" className="error-text">
        {error}
      </p>
    );

  return (
    <ListView
      accounts={accounts}
      onCreate={() => setView("create")}
      onOpen={(a) => {
        setSelected(a);
        setView("detail");
      }}
    />
  );
}
