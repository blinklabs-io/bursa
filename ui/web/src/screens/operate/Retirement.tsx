import { useState } from "react";
import { Card } from "../../components/Card";
import { Input } from "../../components/Input";
import { Button } from "../../components/Button";
import { CopyButton } from "../../components/CopyButton";
import { poolBuildRetirementCert, poolSubmitRetirement } from "../../api/client";
import type { PoolCertResult, TxResult } from "../../api/types";
import { errorMessage } from "./shared";

// Retirement builds a pool retirement certificate for a given epoch and (in the
// seed path) submits it as a transaction witnessed by the cold key. Retirement
// is the one pool operation whose tx is submitted in-app; the certificate can
// also be exported for an air-gapped cold key.
export function Retirement() {
  const [epoch, setEpoch] = useState("");
  const [password, setPassword] = useState("");
  const [cert, setCert] = useState<PoolCertResult | null>(null);
  const [tx, setTx] = useState<TxResult | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);

  async function handleBuild() {
    setError(null);
    setCert(null);
    setTx(null);
    if (!epoch.trim()) {
      setError("Retirement epoch is required");
      return;
    }
    setLoading(true);
    try {
      setCert(await poolBuildRetirementCert({ password, epoch: Number(epoch) }));
    } catch (e) {
      setError(errorMessage(e));
    } finally {
      setLoading(false);
    }
  }

  async function handleSubmit() {
    setError(null);
    setTx(null);
    setLoading(true);
    try {
      setTx(await poolSubmitRetirement({ password, epoch: Number(epoch) }));
    } catch (e) {
      setError(errorMessage(e));
    } finally {
      setLoading(false);
    }
  }

  return (
    <Card title="Pool retirement">
      <div className="operate-form">
        <p className="helper-text">
          Retire the pool at the start of the given epoch. Building shows the
          certificate; submitting broadcasts a retirement transaction signed by
          the cold key (needs a synced node).
        </p>

        <label htmlFor="ret-epoch">Retirement epoch</label>
        <Input
          id="ret-epoch"
          type="number"
          min="0"
          value={epoch}
          onChange={(e) => setEpoch(e.target.value)}
          placeholder="e.g. 520"
          disabled={loading}
        />

        <label htmlFor="ret-password">Spending password</label>
        <Input
          id="ret-password"
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
          <Button variant="ghost" onClick={handleBuild} disabled={loading || !password}>
            {loading ? "Working…" : "Build certificate"}
          </Button>
          <Button onClick={handleSubmit} disabled={loading || !password || !epoch.trim()}>
            {loading ? "Submitting…" : "Build & submit retirement"}
          </Button>
        </div>

        {cert && (
          <div className="cert-result">
            <p className="field-label">Pool ID</p>
            <div className="tx-hash-row">
              <code className="tx-hash accent">{cert.pool_id}</code>
              <CopyButton value={cert.pool_id} />
            </div>
            <p className="field-label">Certificate (CBOR hex)</p>
            <div className="tx-hash-row">
              <code className="tx-hash">{cert.cbor_hex}</code>
              <CopyButton value={cert.cbor_hex} />
            </div>
          </div>
        )}

        {tx && (
          <div className="done-details">
            <p>Retirement transaction submitted.</p>
            <p className="field-label">Transaction hash</p>
            <div className="tx-hash-row">
              <code className="tx-hash">{tx.tx_hash}</code>
              <CopyButton value={tx.tx_hash} />
            </div>
          </div>
        )}
      </div>
    </Card>
  );
}
