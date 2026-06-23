import { useState } from "react";
import type { Dispatch, SetStateAction } from "react";
import type { Preview, TxResult, SendAsset } from "../api/types";
import { buildSend, confirmSend, ApiError } from "../api/client";
import { Card } from "../components/Card";
import { Input } from "../components/Input";
import { Button } from "../components/Button";
import { Table } from "../components/Table";
import { CopyButton } from "../components/CopyButton";
import { formatAda, parseAda } from "../format";

type Phase = "compose" | "preview" | "done";

interface AssetRow {
  unit: string;
  quantity: string;
}

function errorMessage(err: unknown): string {
  if (err instanceof ApiError) return err.message;
  if (err instanceof Error) return err.message;
  return String(err);
}

// --- Compose phase ---

interface ComposeProps {
  to: string;
  setTo: (value: string) => void;
  adaAmount: string;
  setAdaAmount: (value: string) => void;
  assetRows: AssetRow[];
  setAssetRows: Dispatch<SetStateAction<AssetRow[]>>;
  onPreview: (preview: Preview) => void;
}

// The compose draft (to/amount/assets) is owned by the parent Send component so
// it survives the round-trip to the preview phase; only the transient per-attempt
// error/loading state lives here.
function Compose({ to, setTo, adaAmount, setAdaAmount, assetRows, setAssetRows, onPreview }: ComposeProps) {
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);

  function addAssetRow() {
    setAssetRows((prev) => [...prev, { unit: "", quantity: "" }]);
  }

  function removeAssetRow(idx: number) {
    setAssetRows((prev) => prev.filter((_, i) => i !== idx));
  }

  function updateAssetRow(idx: number, field: "unit" | "quantity", value: string) {
    setAssetRows((prev) =>
      prev.map((row, i) => (i === idx ? { ...row, [field]: value } : row))
    );
  }

  async function handleReview() {
    setError(null);

    // Validate ADA amount (parseAda returns a decimal lovelace string)
    let lovelace: string;
    try {
      lovelace = parseAda(adaAmount);
    } catch (e) {
      setError(errorMessage(e));
      return;
    }

    // Validate and parse optional assets
    const assets: SendAsset[] = [];
    for (const row of assetRows) {
      if (!row.unit.trim()) {
        setError("Asset unit cannot be empty");
        return;
      }
      // Must be a whole positive token quantity. The value is sent as a decimal
      // string (uint64 server-side), so BigInt validates it without the 2^53
      // ceiling a JS number would impose.
      const q = row.quantity.trim();
      if (!/^\d+$/.test(q) || BigInt(q) <= 0n) {
        setError("Asset quantity must be a positive integer");
        return;
      }
      assets.push({ unit: row.unit.trim(), quantity: q });
    }

    setLoading(true);
    try {
      const preview = await buildSend({
        to: to.trim(),
        lovelace,
        ...(assets.length > 0 ? { assets } : {}),
      });
      onPreview(preview);
    } catch (e) {
      setError(errorMessage(e));
    } finally {
      setLoading(false);
    }
  }

  return (
    <Card title="Send ADA">
      <div className="send-form">
        <label htmlFor="send-to">Recipient address</label>
        <Input
          id="send-to"
          type="text"
          placeholder="addr1..."
          value={to}
          onChange={(e) => setTo(e.target.value)}
          disabled={loading}
        />

        <label htmlFor="send-amount">Amount (ADA)</label>
        <Input
          id="send-amount"
          type="text"
          placeholder="0.000000"
          value={adaAmount}
          onChange={(e) => setAdaAmount(e.target.value)}
          disabled={loading}
        />

        {assetRows.length > 0 && (
          <div className="asset-rows">
            <p className="field-label">Native assets</p>
            {assetRows.map((row, idx) => (
              <div key={idx} className="asset-row">
                <Input
                  type="text"
                  placeholder="asset unit (hex)"
                  value={row.unit}
                  onChange={(e) => updateAssetRow(idx, "unit", e.target.value)}
                  disabled={loading}
                />
                <Input
                  type="text"
                  placeholder="quantity"
                  value={row.quantity}
                  onChange={(e) => updateAssetRow(idx, "quantity", e.target.value)}
                  disabled={loading}
                />
                <Button variant="ghost" onClick={() => removeAssetRow(idx)} disabled={loading}>
                  Remove
                </Button>
              </div>
            ))}
          </div>
        )}

        <Button variant="ghost" onClick={addAssetRow} disabled={loading}>
          + Add native asset
        </Button>

        {error && (
          <p role="alert" className="error-text">
            {error}
          </p>
        )}

        <Button onClick={handleReview} disabled={loading || !to.trim() || !adaAmount.trim()}>
          {loading ? "Building…" : "Review"}
        </Button>
      </div>
    </Card>
  );
}

// --- Preview phase ---

interface PreviewPhaseProps {
  preview: Preview;
  onBack: () => void;
  onDone: (result: TxResult) => void;
}

const OUTPUT_COLUMNS = [
  { key: "address", label: "Address" },
  { key: "lovelace", label: "ADA" },
  { key: "assets", label: "Assets" },
];

function PreviewPhase({ preview, onBack, onDone }: PreviewPhaseProps) {
  const [password, setPassword] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);

  const outputRows = preview.outputs.map((o) => ({
    address: o.address,
    lovelace: formatAda(o.lovelace),
    assets:
      o.assets && o.assets.length > 0
        ? o.assets.map((a) => `${a.unit}: ${a.quantity}`).join(", ")
        : "—",
  }));

  async function handleConfirm() {
    setError(null);
    setLoading(true);
    try {
      const result = await confirmSend(preview.pending_id, password);
      onDone(result);
    } catch (e) {
      setError(errorMessage(e));
    } finally {
      setLoading(false);
    }
  }

  return (
    <Card title="Review Transaction">
      <div className="preview-details">
        <p>
          <strong>{preview.inputs.length} inputs</strong>
        </p>

        <p className="field-label">Outputs</p>
        <Table columns={OUTPUT_COLUMNS} rows={outputRows} />

        <dl className="preview-summary">
          <div className="dl-row">
            <dt>Fee</dt>
            <dd>{formatAda(preview.fee)} ADA</dd>
          </div>
          <div className="dl-row">
            <dt>Change</dt>
            <dd>{formatAda(preview.change)} ADA</dd>
          </div>
        </dl>

        <label htmlFor="spend-password">Spending password</label>
        <Input
          id="spend-password"
          type="password"
          placeholder="Spending password"
          value={password}
          onChange={(e) => setPassword(e.target.value)}
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
          <Button onClick={handleConfirm} disabled={loading || !password}>
            {loading ? "Submitting…" : "Confirm & send"}
          </Button>
        </div>
      </div>
    </Card>
  );
}

// --- Done phase ---

interface DonePhaseProps {
  result: TxResult;
  onReset: () => void;
}

function DonePhase({ result, onReset }: DonePhaseProps) {
  return (
    <Card title="Transaction Submitted">
      <div className="done-details">
        <p>Your transaction has been submitted successfully.</p>
        <p className="field-label">Transaction hash</p>
        <div className="tx-hash-row">
          <code className="tx-hash">{result.tx_hash}</code>
          <CopyButton value={result.tx_hash} />
        </div>
        <Button onClick={onReset}>Send another</Button>
      </div>
    </Card>
  );
}

// --- Top-level Send screen ---

export function Send() {
  const [phase, setPhase] = useState<Phase>("compose");
  const [preview, setPreview] = useState<Preview | null>(null);
  const [txResult, setTxResult] = useState<TxResult | null>(null);

  // Compose draft lives here, not in Compose, so navigating to the preview and
  // back with "Back" returns the user to their in-progress entry rather than a
  // blank form. "Send another" is the only path that clears it.
  const [to, setTo] = useState("");
  const [adaAmount, setAdaAmount] = useState("");
  const [assetRows, setAssetRows] = useState<AssetRow[]>([]);

  function handlePreview(p: Preview) {
    setPreview(p);
    setPhase("preview");
  }

  function handleDone(result: TxResult) {
    setTxResult(result);
    setPhase("done");
  }

  function handleReset() {
    setPreview(null);
    setTxResult(null);
    setTo("");
    setAdaAmount("");
    setAssetRows([]);
    setPhase("compose");
  }

  if (phase === "done" && txResult) {
    return <DonePhase result={txResult} onReset={handleReset} />;
  }

  if (phase === "preview" && preview) {
    return (
      <PreviewPhase
        preview={preview}
        onBack={() => setPhase("compose")}
        onDone={handleDone}
      />
    );
  }

  return (
    <Compose
      to={to}
      setTo={setTo}
      adaAmount={adaAmount}
      setAdaAmount={setAdaAmount}
      assetRows={assetRows}
      setAssetRows={setAssetRows}
      onPreview={handlePreview}
    />
  );
}
