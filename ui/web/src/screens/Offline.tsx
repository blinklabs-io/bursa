import { useState } from "react";
import { Card } from "../components/Card";
import { Input } from "../components/Input";
import { Button } from "../components/Button";
import { CopyButton } from "../components/CopyButton";
import { DownloadButton } from "../components/DownloadButton";
import { signTx, submitSigned, ApiError } from "../api/client";
import type { WitnessResult, TxResult } from "../api/types";

function errorMessage(err: unknown): string {
  if (err instanceof ApiError) return err.message;
  if (err instanceof Error) return err.message;
  return String(err);
}

type Tab = "sign" | "submit";

// SignTab is the air-gapped step: paste the unsigned transaction CBOR exported
// from an online instance and the spending password to derive the key and
// produce a vkey witness. No node is contacted — this is what the offline,
// keyed instance runs.
function SignTab() {
  const [unsignedCbor, setUnsignedCbor] = useState("");
  const [password, setPassword] = useState("");
  const [result, setResult] = useState<WitnessResult | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);

  function clearResult() {
    setResult(null);
    setError(null);
  }

  async function handleSign() {
    setError(null);
    setResult(null);
    setLoading(true);
    try {
      const res = await signTx({ unsigned_tx_cbor: unsignedCbor.trim(), password });
      setResult(res);
    } catch (e) {
      setError(errorMessage(e));
    } finally {
      setLoading(false);
    }
  }

  return (
    <div className="sign-form">
      <p className="helper-text">
        Sign an unsigned transaction offline. Paste the CBOR exported from your
        online instance and your spending password; the resulting witness can be
        carried back to that instance to submit. Nothing is broadcast here.
      </p>

      <label htmlFor="offline-unsigned">Unsigned transaction (CBOR)</label>
      <textarea
        id="offline-unsigned"
        className="field"
        rows={4}
        value={unsignedCbor}
        onChange={(e) => {
          setUnsignedCbor(e.target.value);
          clearResult();
        }}
        placeholder="hex…"
        aria-label="Unsigned transaction"
        disabled={loading}
      />

      <label htmlFor="offline-password">Spending password</label>
      <Input
        id="offline-password"
        type="password"
        value={password}
        onChange={(e) => {
          setPassword(e.target.value);
          clearResult();
        }}
        placeholder="Spending password"
        aria-label="Spending password"
        disabled={loading}
      />

      {error && (
        <p role="alert" className="error-text">
          {error}
        </p>
      )}

      <Button onClick={handleSign} disabled={loading || !unsignedCbor.trim() || !password}>
        {loading ? "Signing…" : "Sign transaction"}
      </Button>

      {result && (
        <div className="sign-result">
          <p className="field-label">Witness (CBOR)</p>
          <div className="tx-hash-row">
            <code className="tx-hash">{result.witness_cbor}</code>
            <CopyButton value={result.witness_cbor} />
            <DownloadButton value={result.witness_cbor} filename="witness.cbor" label="Download" />
          </div>
        </div>
      )}
    </div>
  );
}

// SubmitTab is the final online step: paste the original unsigned transaction
// CBOR plus the witness produced offline. The instance attaches the witness and
// broadcasts. It needs a synced node.
function SubmitTab() {
  const [unsignedCbor, setUnsignedCbor] = useState("");
  const [witnessCbor, setWitnessCbor] = useState("");
  const [result, setResult] = useState<TxResult | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);

  function clearResult() {
    setResult(null);
    setError(null);
  }

  async function handleSubmit() {
    setError(null);
    setResult(null);
    setLoading(true);
    try {
      const res = await submitSigned({
        unsigned_tx_cbor: unsignedCbor.trim(),
        witness_cbor: witnessCbor.trim(),
      });
      setResult(res);
    } catch (e) {
      setError(errorMessage(e));
    } finally {
      setLoading(false);
    }
  }

  return (
    <div className="sign-form">
      <p className="helper-text">
        Submit a transaction signed offline. Paste the original unsigned CBOR and
        the witness from your offline instance; this instance attaches the witness
        and broadcasts it to the network.
      </p>

      <label htmlFor="submit-unsigned">Unsigned transaction (CBOR)</label>
      <textarea
        id="submit-unsigned"
        className="field"
        rows={4}
        value={unsignedCbor}
        onChange={(e) => {
          setUnsignedCbor(e.target.value);
          clearResult();
        }}
        placeholder="hex…"
        aria-label="Unsigned transaction"
        disabled={loading}
      />

      <label htmlFor="submit-witness">Witness (CBOR)</label>
      <textarea
        id="submit-witness"
        className="field"
        rows={3}
        value={witnessCbor}
        onChange={(e) => {
          setWitnessCbor(e.target.value);
          clearResult();
        }}
        placeholder="hex…"
        aria-label="Witness"
        disabled={loading}
      />

      {error && (
        <p role="alert" className="error-text">
          {error}
        </p>
      )}

      <Button
        onClick={handleSubmit}
        disabled={loading || !unsignedCbor.trim() || !witnessCbor.trim()}
      >
        {loading ? "Submitting…" : "Attach witness & submit"}
      </Button>

      {result && (
        <div className="sign-result">
          <p>Your transaction has been submitted successfully.</p>
          <p className="field-label">Transaction hash</p>
          <div className="tx-hash-row">
            <code className="tx-hash">{result.tx_hash}</code>
            <CopyButton value={result.tx_hash} />
          </div>
        </div>
      )}
    </div>
  );
}

// Offline groups the air-gap signing primitives: sign an exported unsigned tx
// (offline instance) and submit a tx signed elsewhere (online instance).
export function Offline() {
  const [tab, setTab] = useState<Tab>("sign");

  return (
    <Card title="Offline Signing">
      <div className="tab-bar" role="tablist">
        <button
          role="tab"
          aria-selected={tab === "sign"}
          className={tab === "sign" ? "tab active" : "tab"}
          onClick={() => setTab("sign")}
        >
          Sign offline
        </button>
        <button
          role="tab"
          aria-selected={tab === "submit"}
          className={tab === "submit" ? "tab active" : "tab"}
          onClick={() => setTab("submit")}
        >
          Submit signed
        </button>
      </div>
      {tab === "sign" ? <SignTab /> : <SubmitTab />}
    </Card>
  );
}
