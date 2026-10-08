import { useState } from "react";
import type { Preview, TxResult } from "../api/types";
import { confirmSend } from "../api/client";
import { Card } from "../components/Card";
import { Button } from "../components/Button";
import { Input } from "../components/Input";
import { CopyButton } from "../components/CopyButton";
import { errorMessage } from "../errorMessage";
import { formatAda } from "../format";

interface SurveyConfirmProps {
  // What publishing does, in a sentence.
  summary: string;
  signedContent: string;
  preview: Preview;
  onBack: () => void;
  onDone: () => void;
}

// SurveyConfirm signs and submits a built survey transaction with the spending
// password, through the same confirm step a send uses.
export function SurveyConfirm({ summary, signedContent, preview, onBack, onDone }: SurveyConfirmProps) {
  const [password, setPassword] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState<TxResult | null>(null);

  async function confirm() {
    setError(null);
    setLoading(true);
    try {
      setResult(await confirmSend(preview.pending_id, password));
    } catch (e) {
      setError(errorMessage(e));
    } finally {
      setLoading(false);
    }
  }

  if (result) {
    return (
      <Card title="Transaction Submitted">
        <div className="done-details">
          <p>{summary} was submitted through your node.</p>
          <p className="field-label">Transaction hash</p>
          <div className="tx-hash-row">
            <code className="tx-hash">{result.tx_hash}</code>
            <CopyButton value={result.tx_hash} ariaLabel="Copy transaction hash" />
          </div>
          <Button onClick={onDone}>Done</Button>
        </div>
      </Card>
    );
  }

  return (
    <Card title="Confirm">
      <div className="staking-form">
        <p>{summary}</p>
        <div>
          <p className="field-label">Content to publish</p>
          <pre className="survey-confirm-content">{signedContent}</pre>
        </div>
        <dl className="preview-summary">
          <div className="dl-row">
            <dt>Network fee</dt>
            <dd>{formatAda(preview.fee)} ADA</dd>
          </div>
        </dl>
        <p className="helper-text">
          This publishes on-chain metadata that anyone can read. Survey transactions are signed with this
          wallet&apos;s own key and cannot be signed on a hardware device.
        </p>
        <label htmlFor="survey-password">Spending password</label>
        <Input
          id="survey-password"
          type="password"
          value={password}
          onChange={(e) => setPassword(e.target.value)}
          disabled={loading}
        />
        {error && (
          <p role="alert" className="error-text">
            {error}
          </p>
        )}
        <div className="preview-actions">
          <Button variant="ghost" onClick={onBack} disabled={loading}>
            Back
          </Button>
          <Button onClick={confirm} disabled={loading || !password}>
            {loading ? "Submitting…" : "Confirm & sign"}
          </Button>
        </div>
      </div>
    </Card>
  );
}
