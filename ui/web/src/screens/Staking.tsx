import { useRef, useState } from "react";
import type {
  DelegationRequest,
  DelegationPreview,
  DelegationVote,
  VoteType,
  PoolInfo,
  DRepInfo,
  TxResult,
  Cert,
} from "../api/types";
import {
  getPool,
  getDRep,
  buildDelegation,
  confirmDelegation,
  ApiError,
} from "../api/client";
import { useDelegation } from "../api/hooks";
import { Card } from "../components/Card";
import { Input } from "../components/Input";
import { Button } from "../components/Button";
import { StatusPill } from "../components/StatusPill";
import { CopyButton } from "../components/CopyButton";
import { ExplorerLink } from "../components/ExplorerLink";
import { formatAda } from "../format";
import { errorMessage } from "../errorMessage";

type Phase = "status" | "compose" | "preview" | "done";

// Percent display for a pool margin fraction (0.02 → "2.0%").
function pct(fraction: number): string {
  return `${(fraction * 100).toFixed(1)}%`;
}

// The four voting-power targets, in mockup order, with their copy.
const VOTE_OPTIONS: { type: VoteType; title: string; sub: string }[] = [
  {
    type: "abstain",
    title: "Always Abstain",
    sub: "Your stake counts toward quorum but abstains on every vote.",
  },
  {
    type: "no_confidence",
    title: "Always No Confidence",
    sub: "Your stake votes “no confidence” on all governance actions.",
  },
  {
    type: "drep",
    title: "A specific DRep",
    sub: "Delegate to a DRep by ID — verified by your node.",
  },
  {
    type: "register_self",
    title: "Register myself as a DRep",
    sub: "Become a DRep and delegate your own vote to yourself.",
  },
];

// --- Status panel (shared header) ---

function StatusPanel({
  poolId,
  active,
  network,
}: {
  poolId: string | null;
  active: boolean;
  network: string;
}) {
  return (
    <Card title="Current status">
      <dl className="delegation-details">
        <div className="dl-row">
          <dt>Stake key</dt>
          <dd>
            {active ? (
              <StatusPill tone="ok">Registered</StatusPill>
            ) : (
              <span className="muted">Not registered</span>
            )}
          </dd>
        </div>
        <div className="dl-row">
          <dt>Delegated pool</dt>
          <dd>
            {poolId ? (
              <>
                {poolId}
                <ExplorerLink network={network} kind="pool" id={poolId} />
              </>
            ) : (
              <span className="muted">—</span>
            )}
          </dd>
        </div>
      </dl>
    </Card>
  );
}

// --- Compose phase ---

interface ComposeProps {
  poolId: string;
  setPoolId: (v: string) => void;
  voteType: VoteType | null;
  setVoteType: (v: VoteType) => void;
  drepId: string;
  setDrepId: (v: string) => void;
  anchorUrl: string;
  setAnchorUrl: (v: string) => void;
  anchorHash: string;
  setAnchorHash: (v: string) => void;
  onPreview: (preview: DelegationPreview) => void;
  network: string;
}

function Compose(props: ComposeProps) {
  const {
    poolId,
    setPoolId,
    voteType,
    setVoteType,
    drepId,
    setDrepId,
    anchorUrl,
    setAnchorUrl,
    anchorHash,
    setAnchorHash,
    onPreview,
    network,
  } = props;

  const [pool, setPool] = useState<PoolInfo | null>(null);
  const [poolError, setPoolError] = useState<string | null>(null);
  const [verifyingPool, setVerifyingPool] = useState(false);
  const latestPoolId = useRef(poolId);
  const poolVerifySeq = useRef(0);
  latestPoolId.current = poolId;

  const [drep, setDrep] = useState<DRepInfo | null>(null);
  const [drepError, setDrepError] = useState<string | null>(null);
  const [verifyingDrep, setVerifyingDrep] = useState(false);
  const latestDrepId = useRef(drepId);
  const drepVerifySeq = useRef(0);
  latestDrepId.current = drepId;

  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);

  // Verify a pasted pool ID against the node; the readout proves it exists.
  async function handleVerifyPool() {
    const id = poolId.trim();
    const seq = ++poolVerifySeq.current;
    setPool(null);
    setPoolError(null);
    if (!id) {
      setVerifyingPool(false);
      return;
    }
    setVerifyingPool(true);
    try {
      const info = await getPool(id);
      if (poolVerifySeq.current !== seq || latestPoolId.current.trim() !== id) return;
      setPool(info);
    } catch (e) {
      if (poolVerifySeq.current !== seq || latestPoolId.current.trim() !== id) return;
      setPoolError(
        e instanceof ApiError && e.status === 404
          ? "Not found by your node"
          : errorMessage(e),
      );
    } finally {
      if (poolVerifySeq.current === seq) setVerifyingPool(false);
    }
  }

  async function handleVerifyDrep() {
    const id = drepId.trim();
    const seq = ++drepVerifySeq.current;
    setDrep(null);
    setDrepError(null);
    if (!id) {
      setVerifyingDrep(false);
      return;
    }
    setVerifyingDrep(true);
    try {
      const info = await getDRep(id);
      if (drepVerifySeq.current !== seq || latestDrepId.current.trim() !== id) return;
      setDrep(info);
    } catch (e) {
      if (drepVerifySeq.current !== seq || latestDrepId.current.trim() !== id) return;
      setDrepError(
        e instanceof ApiError && e.status === 404
          ? "Not found by your node"
          : errorMessage(e),
      );
    } finally {
      if (drepVerifySeq.current === seq) setVerifyingDrep(false);
    }
  }

  async function handleReview() {
    setError(null);

    const req: DelegationRequest = {};
    if (poolId.trim()) req.pool_id = poolId.trim();
    if (voteType) {
      let vote: DelegationVote;
      if (voteType === "abstain" || voteType === "no_confidence") {
        vote = { type: voteType };
      } else if (voteType === "drep") {
        if (!drepId.trim()) {
          setError("Enter a DRep ID to delegate your vote to.");
          return;
        }
        vote = { type: "drep", drep_id: drepId.trim() };
      } else {
        const url = anchorUrl.trim();
        const hash = anchorHash.trim();
        if (url || hash) {
          if (!url) {
            setError("Enter the metadata URL for the metadata hash.");
            return;
          }
          if (!hash) {
            setError("Enter the metadata hash for the metadata URL.");
            return;
          }
          vote = { type: "register_self", anchor: { url, hash } };
        } else {
          vote = { type: "register_self" };
        }
      }
      req.vote = vote;
    }

    if (!req.pool_id && !req.vote) {
      setError("Choose a pool or a voting-power target.");
      return;
    }

    setLoading(true);
    try {
      onPreview(await buildDelegation(req));
    } catch (e) {
      setError(errorMessage(e));
    } finally {
      setLoading(false);
    }
  }

  return (
    <Card title="Set up delegation">
      <div className="staking-form">
        <label htmlFor="pool-id">Stake pool</label>
        <Input
          id="pool-id"
          type="text"
          placeholder="pool1..."
          value={poolId}
          onChange={(e) => {
            poolVerifySeq.current += 1;
            setPoolId(e.target.value);
            setPool(null);
            setPoolError(null);
            setVerifyingPool(false);
          }}
          onBlur={handleVerifyPool}
          disabled={loading}
        />
        {verifyingPool && <p className="helper-text">Verifying pool…</p>}
        {pool && (
          <p className="verified-readout">
            <span className="verified-tick">✓ Verified by your node</span>
            {" · "}margin {pct(pool.margin_cost)}
            {" · "}pledge {formatAda(pool.declared_pledge)} ₳
            {" · "}fixed {formatAda(pool.fixed_cost)} ₳
            {" · "}live stake {formatAda(pool.live_stake)} ₳
            <ExplorerLink network={network} kind="pool" id={pool.pool_id} />
          </p>
        )}
        {poolError && (
          <p role="alert" className="error-text">
            {poolError}
          </p>
        )}

        <p className="field-label">Voting power</p>
        <div className="vote-options">
          {VOTE_OPTIONS.map((opt) => {
            const selected = voteType === opt.type;
            return (
              <div key={opt.type} className={selected ? "vote-opt selected" : "vote-opt"}>
                <label className="vote-opt-label">
                  <input
                    type="radio"
                    name="vote-power"
                    checked={selected}
                    onChange={() => setVoteType(opt.type)}
                    disabled={loading}
                  />
                  <span className="vote-opt-main">
                    <span className="vote-opt-title">{opt.title}</span>
                    <span className="vote-opt-sub">{opt.sub}</span>
                  </span>
                </label>

                {selected && opt.type === "drep" && (
                  <div className="vote-opt-extra">
                    <label htmlFor="drep-id">DRep ID</label>
                    <Input
                      id="drep-id"
                      type="text"
                      placeholder="drep1..."
                      value={drepId}
                      onChange={(e) => {
                        drepVerifySeq.current += 1;
                        setDrepId(e.target.value);
                        setDrep(null);
                        setDrepError(null);
                        setVerifyingDrep(false);
                      }}
                      onBlur={handleVerifyDrep}
                      disabled={loading}
                    />
                    {verifyingDrep && <p className="helper-text">Verifying DRep…</p>}
                    {drep && (
                      <p className="verified-readout">
                        <span className="verified-tick">✓ Verified by your node</span>
                        {drep.registered ? " · registered" : " · not registered"}
                        <ExplorerLink network={network} kind="drep" id={drep.drep_id} />
                      </p>
                    )}
                    {drepError && (
                      <p role="alert" className="error-text">
                        {drepError}
                      </p>
                    )}
                  </div>
                )}

                {selected && opt.type === "register_self" && (
                  <div className="vote-opt-extra">
                    <label htmlFor="anchor-url">Metadata URL (optional)</label>
                    <Input
                      id="anchor-url"
                      type="text"
                      placeholder="https://example.org/my-drep.jsonld"
                      value={anchorUrl}
                      onChange={(e) => setAnchorUrl(e.target.value)}
                      disabled={loading}
                    />
                    <label htmlFor="anchor-hash">Metadata hash (optional)</label>
                    <Input
                      id="anchor-hash"
                      type="text"
                      placeholder="blake2b-256 of the metadata file"
                      value={anchorHash}
                      onChange={(e) => setAnchorHash(e.target.value)}
                      disabled={loading}
                    />
                    <p className="deposit-note">
                      Registering as a DRep may lock a refundable protocol-parameter
                      deposit. Exact deposit amounts are read from your node and shown
                      on the review screen before you confirm.
                    </p>
                  </div>
                )}
              </div>
            );
          })}
        </div>

        {error && (
          <p role="alert" className="error-text">
            {error}
          </p>
        )}

        <Button
          onClick={handleReview}
          disabled={loading || (!poolId.trim() && !voteType)}
        >
          {loading ? "Building…" : "Review delegation"}
        </Button>
      </div>
    </Card>
  );
}

// --- Preview phase (itemized confirm) ---

const CERT_MARK: Record<Cert["kind"], string> = {
  stake_registration: "+",
  stake_delegation: "→",
  vote_delegation: "🗳",
  drep_registration: "★",
  withdrawal: "↓",
};

interface PreviewPhaseProps {
  preview: DelegationPreview;
  onBack: () => void;
  onDone: (result: TxResult) => void;
}

function PreviewPhase({ preview, onBack, onDone }: PreviewPhaseProps) {
  const [password, setPassword] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);

  async function handleConfirm() {
    setError(null);
    setLoading(true);
    try {
      onDone(await confirmDelegation(preview.pending_id, password));
    } catch (e) {
      setError(errorMessage(e));
    } finally {
      setLoading(false);
    }
  }

  return (
    <div className="staking">
      <Card title="This transaction will">
        <div className="cert-list">
          {preview.certs.map((c, i) => (
            <div key={i} className="cert-row">
              <span className="cert-mark">{CERT_MARK[c.kind] ?? "•"}</span>
              <span className="cert-body">{c.summary}</span>
              <span className="cert-amt">
                {c.deposit_lovelace
                  ? `${formatAda(c.deposit_lovelace)} ₳ deposit`
                  : c.amount_lovelace
                    ? `${formatAda(c.amount_lovelace)} ₳`
                    : "—"}
              </span>
            </div>
          ))}
        </div>

        <dl className="preview-summary">
          <div className="dl-row">
            <dt>Network fee</dt>
            <dd>{formatAda(preview.fee)} ₳</dd>
          </div>
          {preview.deposit !== "0" && (
            <div className="dl-row">
              <dt>Refundable deposit</dt>
              <dd>{formatAda(preview.deposit)} ₳</dd>
            </div>
          )}
          {preview.withdrawal && (
            <div className="dl-row">
              <dt>Withdrawal</dt>
              <dd>{formatAda(preview.withdrawal)} ₳</dd>
            </div>
          )}
          <div className="dl-row">
            <dt>Total to confirm</dt>
            <dd className="total-accent">{formatAda(preview.total)} ₳</dd>
          </div>
        </dl>
      </Card>

      <Card title="Spending password">
        <div className="staking-form">
          <label htmlFor="staking-password">Spending password</label>
          <Input
            id="staking-password"
            type="password"
            placeholder="Spending password"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            disabled={loading}
          />
          <p className="helper-text">
            Signs locally; the transaction is submitted through your own node.
          </p>

          {error && (
            <p role="alert" className="error-text">
              {error}
            </p>
          )}

          <div className="preview-actions">
            <Button variant="ghost" onClick={onBack} disabled={loading}>
              Back
            </Button>
            <Button onClick={handleConfirm} disabled={loading || !password}>
              {loading ? "Submitting…" : "Confirm & sign"}
            </Button>
          </div>
        </div>
      </Card>
    </div>
  );
}

// --- Done phase ---

function DonePhase({ result, onReset }: { result: TxResult; onReset: () => void }) {
  return (
    <Card title="Transaction Submitted">
      <div className="done-details">
        <p>Your delegation transaction has been submitted successfully.</p>
        <p className="field-label">Transaction hash</p>
        <div className="tx-hash-row">
          <code className="tx-hash">{result.tx_hash}</code>
          <CopyButton value={result.tx_hash} />
        </div>
        <Button onClick={onReset}>Back to staking</Button>
      </div>
    </Card>
  );
}

// --- Active state: status + withdraw + change ---

interface ActiveProps {
  poolId: string | null;
  withdrawable: string;
  note: string;
  onChange: () => void;
  onWithdraw: (preview: DelegationPreview) => void;
  network: string;
}

function ActiveState({ poolId, withdrawable, note, onChange, onWithdraw, network }: ActiveProps) {
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);
  const canWithdraw = /^\d+$/.test(withdrawable) && BigInt(withdrawable) > 0n;

  async function handleWithdraw() {
    setError(null);
    setLoading(true);
    try {
      onWithdraw(await buildDelegation({ withdraw: true }));
    } catch (e) {
      setError(errorMessage(e));
    } finally {
      setLoading(false);
    }
  }

  return (
    <>
      <StatusPanel poolId={poolId} active={true} network={network} />
      <Card title="Rewards">
        <div className="dl-row">
          <dt className="field-label">Withdrawable</dt>
          <dd className="total-accent mono">{formatAda(withdrawable)} ₳</dd>
        </div>

        {error && (
          <p role="alert" className="error-text">
            {error}
          </p>
        )}

        <div className="preview-actions">
          <Button onClick={handleWithdraw} disabled={loading || !canWithdraw}>
            {loading ? "Building…" : "Withdraw rewards"}
          </Button>
          <Button variant="ghost" onClick={onChange} disabled={loading}>
            Change delegation
          </Button>
        </div>
        {note && <p className="helper-text">{note}</p>}
      </Card>
    </>
  );
}

// --- Top-level Staking screen ---

interface StakingProps {
  // Optional so existing no-prop callers/tests keep working; the app always
  // passes the active wallet's real network when routing to this screen.
  network?: string;
}

export function Staking({ network = "preview" }: StakingProps = {}) {
  const delegation = useDelegation();

  const [phase, setPhase] = useState<Phase>("status");
  const [previewFrom, setPreviewFrom] = useState<Phase>("status");
  const [preview, setPreview] = useState<DelegationPreview | null>(null);
  const [txResult, setTxResult] = useState<TxResult | null>(null);

  // Compose draft lives at the top so Back returns to in-progress entry.
  const [poolId, setPoolId] = useState("");
  const [voteType, setVoteType] = useState<VoteType | null>(null);
  const [drepId, setDrepId] = useState("");
  const [anchorUrl, setAnchorUrl] = useState("");
  const [anchorHash, setAnchorHash] = useState("");

  if (delegation.loading) {
    return <p>Loading…</p>;
  }
  if (delegation.error) {
    return (
      <p role="alert" className="error-text">
        {delegation.error.message}
      </p>
    );
  }

  const del = delegation.data;
  const isActive = del?.active ?? false;

  function goCompose() {
    setPhase("compose");
  }

  function handlePreview(p: DelegationPreview, from: Phase = "compose") {
    setPreview(p);
    setPreviewFrom(from);
    setPhase("preview");
  }

  function handleDone(result: TxResult) {
    setTxResult(result);
    setPhase("done");
  }

  function handleReset() {
    setPreview(null);
    setTxResult(null);
    setPoolId("");
    setVoteType(null);
    setDrepId("");
    setAnchorUrl("");
    setAnchorHash("");
    setPhase("status");
    delegation.refresh();
  }

  if (phase === "done" && txResult) {
    return (
      <div className="staking">
        <DonePhase result={txResult} onReset={handleReset} />
      </div>
    );
  }

  if (phase === "preview" && preview) {
    return (
      <PreviewPhase
        preview={preview}
        onBack={() => setPhase(previewFrom)}
        onDone={handleDone}
      />
    );
  }

  // Status phase. An active wallet shows the active state (withdraw + change);
  // a fresh wallet drops straight into the set-up form.
  if (phase === "status" && isActive && del) {
    return (
      <div className="staking">
        <ActiveState
          poolId={del.pool_id}
          withdrawable={del.withdrawable_amount}
          note={del.provisional ? del.note : ""}
          onChange={goCompose}
          onWithdraw={(p) => handlePreview(p, "status")}
          network={network}
        />
      </div>
    );
  }

  // Compose (set-up / change) form, with the status panel above it.
  return (
    <div className="staking">
      <StatusPanel poolId={del?.pool_id ?? null} active={isActive} network={network} />
      <Compose
        poolId={poolId}
        setPoolId={setPoolId}
        voteType={voteType}
        setVoteType={setVoteType}
        drepId={drepId}
        setDrepId={setDrepId}
        anchorUrl={anchorUrl}
        setAnchorUrl={setAnchorUrl}
        anchorHash={anchorHash}
        setAnchorHash={setAnchorHash}
        onPreview={handlePreview}
        network={network}
      />
    </div>
  );
}
