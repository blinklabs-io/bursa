import { useState } from "react";
import { Card } from "../components/Card";
import { Input } from "../components/Input";
import { Button } from "../components/Button";
import { CopyButton } from "../components/CopyButton";
import { DownloadButton } from "../components/DownloadButton";
import { MultiSigProgress } from "../components/MultiSigProgress";
import { decodeTx, cosignTx, submitTx, ApiError } from "../api/client";
import type { TxSummary, CosignResult, TxResult } from "../api/types";
import { formatAda } from "../format";

function errorMessage(err: unknown): string {
  if (err instanceof ApiError) return err.message;
  if (err instanceof Error) return err.message;
  return String(err);
}

// ImportTransaction lets the user paste a full transaction CBOR built
// elsewhere (unsigned, partially signed, or complete), decode it into a
// type-aware preview (plain vkey spend vs native multi-sig), add this
// wallet's own signature, and either export the updated CBOR (for the next
// co-signer) or submit it to the network. Decoding never requires a
// password; adding a signature does; submitting is additionally gated on the
// node being ready (canSubmit).
export function ImportTransaction({ canSubmit }: { canSubmit: boolean }) {
  const [cbor, setCbor] = useState("");
  const [summary, setSummary] = useState<TxSummary | null>(null);
  const [current, setCurrent] = useState(""); // the working tx CBOR (updated after cosign)
  const [password, setPassword] = useState("");
  const [result, setResult] = useState<TxResult | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  function reset() {
    setSummary(null);
    setCurrent("");
    setResult(null);
    setError(null);
    setPassword("");
  }

  async function handleDecode() {
    setError(null);
    setResult(null);
    setBusy(true);
    try {
      const s = await decodeTx(cbor.trim());
      setSummary(s);
      setCurrent(cbor.trim());
    } catch (e) {
      setError(errorMessage(e));
      setSummary(null);
    } finally {
      setBusy(false);
    }
  }

  async function handleCosign() {
    setError(null);
    setBusy(true);
    try {
      const r: CosignResult = await cosignTx({ tx_cbor: current, password });
      setCurrent(r.tx_cbor);
      setPassword("");
      // The vkey cosign response already carries a fresh summary — use it
      // directly. The native-multisig response only carries signed_count/
      // threshold (see CosignResult in api/types.ts), so re-decode the merged
      // CBOR in that case to get a full, up-to-date preview.
      if (r.summary) {
        setSummary(r.summary);
      } else {
        const s = await decodeTx(r.tx_cbor);
        setSummary(s);
      }
    } catch (e) {
      setError(errorMessage(e));
    } finally {
      setBusy(false);
    }
  }

  async function handleSubmit() {
    setError(null);
    setBusy(true);
    try {
      const r = await submitTx(current);
      setResult(r);
    } catch (e) {
      setError(errorMessage(e));
    } finally {
      setBusy(false);
    }
  }

  if (result) {
    return (
      <Card title="Transaction Submitted">
        <p>Your transaction has been submitted.</p>
        <p className="field-label">Transaction hash</p>
        <div className="tx-hash-row">
          <code className="tx-hash">{result.tx_hash}</code>
          <CopyButton value={result.tx_hash} ariaLabel="Copy transaction hash" />
        </div>
        <Button
          onClick={() => {
            reset();
            setCbor("");
          }}
        >
          Import another
        </Button>
      </Card>
    );
  }

  const ms = summary?.multisig;
  // wallet_can_add is authoritative for the vkey kind, but the native-multisig
  // builder deliberately never registers participant key-hashes as tx-level
  // required signers, so spend.DecodeTx (which derives wallet_can_add from
  // required-signers/cert credentials) always reports it empty for multisig —
  // fall back to summary.multisig.is_multisig so the affordance still shows.
  // If the wallet isn't actually a participant, cosignTx returns an error,
  // which the screen already surfaces — that's the intended design.
  const canAdd = summary
    ? summary.wallet_can_add.length > 0 || (summary.multisig?.is_multisig ?? false)
    : false;
  const remaining = ms && ms.threshold != null ? Math.max(ms.threshold - ms.signed_count, 0) : 0;
  // is_complete is meaningless for multisig (spend.DecodeTx reads it true
  // immediately since it never sees multisig required-signers) — gate
  // multisig readiness on the authoritative signed_count/threshold instead.
  const readyToSubmit = ms?.is_multisig
    ? ms.signed_count >= (ms.threshold ?? 0)
    : (summary?.is_complete ?? false);

  return (
    <Card title="Import Transaction">
      <p className="helper-text">
        Paste a transaction (CBOR hex) built elsewhere — unsigned, partially signed,
        or complete. Review it, add your signature, then hand the updated CBOR to the
        next co-signer or submit it.
      </p>

      <label htmlFor="import-cbor">Transaction CBOR</label>
      <textarea
        id="import-cbor"
        className="field"
        rows={4}
        value={cbor}
        onChange={(e) => {
          setCbor(e.target.value);
          reset();
        }}
        placeholder="hex…"
        aria-label="Transaction CBOR"
        disabled={busy}
      />
      <Button onClick={handleDecode} disabled={busy || !cbor.trim()}>
        {busy && !summary ? "Decoding…" : "Decode"}
      </Button>

      {summary && (
        <div className="import-preview">
          {summary.kind === "unknown" && (
            <p role="alert" className="warn-text">
              Some parts of this transaction could not be decoded. Review carefully
              before signing.
            </p>
          )}

          <dl className="preview-summary">
            <div className="dl-row">
              <dt>Fee</dt>
              <dd>{formatAda(summary.fee)} ADA</dd>
            </div>
            {summary.ttl ? (
              <div className="dl-row">
                <dt>TTL (slot)</dt>
                <dd>{summary.ttl}</dd>
              </div>
            ) : null}
            {summary.certificates?.length ? (
              <div className="dl-row">
                <dt>Certificates</dt>
                <dd>{summary.certificates.join(", ")}</dd>
              </div>
            ) : null}
            {summary.network_id != null ? (
              <div className="dl-row">
                <dt>Network</dt>
                <dd>{summary.network_id === 1 ? "mainnet (1)" : `testnet (${summary.network_id})`}</dd>
              </div>
            ) : null}
          </dl>

          <p className="field-label">Outputs</p>
          <ul className="signer-list">
            {summary.outputs.map((o, i) => (
              <li key={i}>
                <code className="tx-hash">{o.address}</code> — {formatAda(o.lovelace)} ADA
              </li>
            ))}
          </ul>

          {summary.withdrawals?.length ? (
            <>
              {/* Reward withdrawals move funds out of this wallet's staking
                  rewards just like outputs move funds out of its UTxOs, so they
                  MUST be shown before the user cosigns or submits. */}
              <p className="field-label">Reward withdrawals</p>
              <ul className="signer-list">
                {summary.withdrawals.map((wd, i) => (
                  <li key={i}>
                    <code className="tx-hash">{wd.address}</code> — {formatAda(wd.lovelace)} ADA
                  </li>
                ))}
              </ul>
            </>
          ) : null}

          {ms?.is_multisig ? (
            <MultiSigProgress
              threshold={ms.threshold ?? 0}
              total={ms.participants?.length ?? 0}
              signedCount={ms.signed_count}
              participants={ms.participants}
            />
          ) : (
            <p className="ms-progress">
              {summary.existing_signatures.length} signature(s) present
              {summary.is_complete ? " · complete" : ""}
            </p>
          )}

          {canAdd && (
            <>
              <label htmlFor="import-pw">Spending password</label>
              <Input
                id="import-pw"
                type="password"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                placeholder="Spending password"
                aria-label="Spending password"
                disabled={busy}
              />
              <Button onClick={handleCosign} disabled={busy || !password}>
                {busy ? "Signing…" : "Add my signature"}
              </Button>
            </>
          )}

          <p className="field-label">Transaction CBOR (current)</p>
          <div className="tx-hash-row">
            <code className="tx-hash">{current}</code>
            <CopyButton value={current} ariaLabel="Copy transaction CBOR" />
            <DownloadButton value={current} filename="transaction.cbor" label="Download" />
          </div>

          <Button onClick={handleSubmit} disabled={busy || !canSubmit || !readyToSubmit}>
            {/* The accessible name always starts with "Submit to network" — only
                a parenthetical qualifier changes — so the button can be found by
                that name whether it is enabled or disabled. */}
            Submit to network
            {!canSubmit
              ? " (node syncing…)"
              : !readyToSubmit
                ? remaining > 0
                  ? ` (need ${remaining} more signature(s))`
                  : " (incomplete)"
                : ""}
          </Button>
        </div>
      )}

      {error && (
        <p role="alert" className="error-text">
          {error}
        </p>
      )}
    </Card>
  );
}
