import { useState } from "react";
import { Card } from "../../components/Card";
import { Input } from "../../components/Input";
import { Button } from "../../components/Button";
import { CopyButton } from "../../components/CopyButton";
import { poolSubmitVote } from "../../api/client";
import type { TxResult } from "../../api/types";
import { errorMessage } from "./shared";

type VoteChoice = "yes" | "no" | "abstain";

// Vote submits a governance action vote as the stake pool operator. It signs
// with the pool cold key and needs a synced node.
export function Vote() {
  const [actionTxId, setActionTxId] = useState("");
  const [actionIndex, setActionIndex] = useState("");
  const [vote, setVote] = useState<VoteChoice>("yes");
  const [anchorUrl, setAnchorUrl] = useState("");
  const [anchorHash, setAnchorHash] = useState("");
  const [password, setPassword] = useState("");
  const [tx, setTx] = useState<TxResult | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);

  function parseActionIndex(): number | null {
    const trimmed = actionIndex.trim();
    if (!/^\d+$/.test(trimmed)) return null;
    const n = Number(trimmed);
    if (!Number.isSafeInteger(n)) return null;
    return n;
  }

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    setError(null);
    setTx(null);

    const trimmedTxId = actionTxId.trim();
    if (!trimmedTxId) {
      setError("Governance action tx id is required");
      return;
    }
    if (!/^[0-9a-fA-F]{64}$/.test(trimmedTxId)) {
      setError("Governance action tx id must be 32 bytes hex");
      return;
    }
    if (!actionIndex.trim()) {
      setError("Action index is required");
      return;
    }
    const actionIndexNum = parseActionIndex();
    if (actionIndexNum === null || actionIndexNum < 0) {
      setError("Action index must be a non-negative integer");
      return;
    }
    if (!password) {
      setError("Spending password is required");
      return;
    }

    const url = anchorUrl.trim();
    const hash = anchorHash.trim();
    if ((url === "") !== (hash === "")) {
      setError("Anchor URL and anchor hash must be provided together or omitted");
      return;
    }
    if (url !== "" && !/^[0-9a-fA-F]{64}$/.test(hash)) {
      setError("Anchor hash must be 32 bytes hex");
      return;
    }

    setLoading(true);
    try {
      const req: {
        password: string;
        action_tx_id: string;
        action_index: number;
        vote: "yes" | "no" | "abstain";
        anchor_url?: string;
        anchor_hash?: string;
      } = {
        password,
        action_tx_id: trimmedTxId,
        action_index: actionIndexNum,
        vote,
      };
      if (url !== "") {
        req.anchor_url = url;
        req.anchor_hash = hash;
      }
      setTx(await poolSubmitVote(req));
    } catch (e) {
      setError(errorMessage(e));
    } finally {
      setLoading(false);
    }
  }

  return (
    <Card title="Pool vote">
      <div className="operate-form">
        <p className="helper-text">
          Cast a governance action vote as the stake pool operator. Requires a
          synced node and the spending password.
        </p>

        <form onSubmit={handleSubmit} noValidate>
          <label htmlFor="vote-action-tx">Governance action tx id (hex)</label>
          <Input
            id="vote-action-tx"
            type="text"
            value={actionTxId}
            onChange={(e) => setActionTxId(e.target.value)}
            placeholder="64 hex chars"
            disabled={loading}
          />

          <label htmlFor="vote-action-index">Action index</label>
          <Input
            id="vote-action-index"
            type="number"
            min="0"
            value={actionIndex}
            onChange={(e) => setActionIndex(e.target.value)}
            placeholder="e.g. 0"
            disabled={loading}
          />

          <label htmlFor="vote-choice">Vote</label>
          <select
            id="vote-choice"
            value={vote}
            onChange={(e) => setVote(e.target.value as VoteChoice)}
            disabled={loading}
            className="input"
          >
            <option value="yes">Yes</option>
            <option value="no">No</option>
            <option value="abstain">Abstain</option>
          </select>

          <label htmlFor="vote-anchor-url">Anchor URL (optional)</label>
          <Input
            id="vote-anchor-url"
            type="text"
            value={anchorUrl}
            onChange={(e) => setAnchorUrl(e.target.value)}
            placeholder="https://..."
            disabled={loading}
          />

          <label htmlFor="vote-anchor-hash">Anchor hash (hex, optional)</label>
          <Input
            id="vote-anchor-hash"
            type="text"
            value={anchorHash}
            onChange={(e) => setAnchorHash(e.target.value)}
            placeholder="64 hex chars"
            disabled={loading}
          />

          <label htmlFor="vote-password">Spending password</label>
          <Input
            id="vote-password"
            type="password"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            placeholder="Spending password"
            aria-label="Spending password"
            disabled={loading}
          />

          {error && (
            <p role="alert" className="error-text">
              {error}
            </p>
          )}

          <div className="preview-actions">
            <Button type="submit" disabled={loading}>
              {loading ? "Submitting…" : "Submit vote"}
            </Button>
          </div>
        </form>

        {tx && (
          <div className="done-details">
            <p>Vote submitted.</p>
            <p className="field-label">Transaction hash</p>
            <div className="tx-hash-row">
              <code className="tx-hash">{tx.tx_hash}</code>
              <CopyButton value={tx.tx_hash} aria-label="Copy vote transaction hash" />
            </div>
          </div>
        )}
      </div>
    </Card>
  );
}
