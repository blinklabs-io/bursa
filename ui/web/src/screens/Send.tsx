import { useEffect, useState } from "react";
import type { Dispatch, SetStateAction } from "react";
import type { Preview, TxResult, SendAsset, UnsignedTx, HandleInfo, HardwareSignResponse } from "../api/types";
import {
  buildSend,
  confirmSend,
  exportUnsigned,
  resolveHandle,
  getHardwareSignRequest,
  submitHardware,
  ApiError,
} from "../api/client";
import { useContacts } from "../api/hooks";
import { connectLedger } from "../hw/ledger";
import type { LedgerSession } from "../hw/ledger";
import type { SignTransactionRequest, TxInput, TxOutput } from "@cardano-foundation/ledgerjs-hw-app-cardano";
import {
  AddressType,
  TransactionSigningMode,
  TxOutputDestinationType,
  TxOutputFormat,
  TxRequiredSignerType,
} from "@cardano-foundation/ledgerjs-hw-app-cardano";
import { Card } from "../components/Card";
import { Input } from "../components/Input";
import { Button } from "../components/Button";
import { Table } from "../components/Table";
import { CopyButton } from "../components/CopyButton";
import { DownloadButton } from "../components/DownloadButton";
import { formatAda, parseAda } from "../format";

// parseBip32Path converts a CIP-1852 path string to a numeric array.
// "1852'/1815'/0'/0/3" → [0x80000000+1852, 0x80000000+1815, 0x80000000+0, 0, 3]
function parseBip32Path(pathStr: string): number[] {
  const HARDENED = 0x80000000;
  return pathStr.split("/").map((seg) => {
    const hardened = seg.endsWith("'");
    const n = parseInt(hardened ? seg.slice(0, -1) : seg, 10);
    return hardened ? n + HARDENED : n;
  });
}

// mapToSignRequest converts a HardwareSignResponse (from the backend) to the
// SignTransactionRequest format that ledgerjs expects.
function mapToSignRequest(resp: HardwareSignResponse): SignTransactionRequest {
  const inputs: TxInput[] = resp.inputs.map((inp) => ({
    txHashHex: inp.tx_hash_hex,
    outputIndex: inp.output_index,
    path: inp.path ? parseBip32Path(inp.path) : null,
  }));

  const outputs: TxOutput[] = resp.outputs.map((out) => {
    const destination = out.payment_path && out.stake_path
      ? {
          type: TxOutputDestinationType.DEVICE_OWNED as const,
          params: {
            type: AddressType.BASE_PAYMENT_KEY_STAKE_KEY as const,
            params: {
              spendingPath: parseBip32Path(out.payment_path),
              stakingPath: parseBip32Path(out.stake_path),
            },
          },
        }
      : {
          type: TxOutputDestinationType.THIRD_PARTY as const,
          params: { addressHex: out.address_hex },
        };

    return {
      format: TxOutputFormat.ARRAY_LEGACY,
      destination,
      amount: BigInt(out.lovelace),
      // ledgerjs iterates this field even when the output contains ADA only.
      tokenBundle: [],
    };
  });

  return {
    tx: {
      network: {
        protocolMagic: resp.protocol_magic,
        networkId: resp.network_id,
      },
      inputs,
      outputs,
      fee: BigInt(resp.fee),
      ttl: resp.ttl ? BigInt(resp.ttl) : null,
      requiredSigners: resp.required_signers.map((hashHex) => ({
        type: TxRequiredSignerType.HASH,
        hashHex,
      })),
      includeNetworkId: resp.include_network_id || null,
    },
    signingMode: TransactionSigningMode.ORDINARY_TRANSACTION,
  };
}

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

// How long to wait after the user stops typing a "$handle" before querying
// the node to resolve it — avoids firing a lookup on every keystroke.
const HANDLE_RESOLVE_DEBOUNCE_MS = 400;

// isHandleInput reports whether a recipient input names an ADA Handle (a
// leading '$') rather than a raw address.
function isHandleInput(value: string): boolean {
  return value.trim().startsWith("$");
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
  const contacts = useContacts();
  const [pickerOpen, setPickerOpen] = useState(false);
  const contactPickerListID = "send-contact-picker-list";

  // ADA Handle resolution: when `to` names a handle ($name), debounce a
  // lookup through the node and show the resolved address (or a clean
  // not-found). resolvedHandle.handle is only trusted when it still matches
  // the current input — see the effect below.
  const [resolvedHandle, setResolvedHandle] = useState<HandleInfo | null>(null);
  const [handleError, setHandleError] = useState<string | null>(null);
  const [resolvingHandle, setResolvingHandle] = useState(false);
  const handleInput = isHandleInput(to);
  const trimmedTo = to.trim();

  useEffect(() => {
    setResolvedHandle(null);
    setHandleError(null);
    if (!handleInput) {
      setResolvingHandle(false);
      return;
    }
    let cancelled = false;
    setResolvingHandle(true);
    const timer = setTimeout(() => {
      resolveHandle(trimmedTo)
        .then((info) => {
          if (!cancelled) setResolvedHandle(info);
        })
        .catch((e: unknown) => {
          if (cancelled) return;
          setHandleError(
            e instanceof ApiError && e.status === 404 ? "Handle not found" : errorMessage(e),
          );
        })
        .finally(() => {
          if (!cancelled) setResolvingHandle(false);
        });
    }, HANDLE_RESOLVE_DEBOUNCE_MS);
    return () => {
      cancelled = true;
      clearTimeout(timer);
    };
  }, [trimmedTo, handleInput]);

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

    // A "$handle" recipient must resolve to an address before building the
    // send; use the node-verified address, never the raw handle text.
    let resolvedTo = trimmedTo;
    if (handleInput) {
      if (resolvingHandle) {
        setError("Still resolving the handle — try again in a moment.");
        return;
      }
      if (!resolvedHandle) {
        setError(handleError ?? "Enter a valid, resolvable ADA Handle.");
        return;
      }
      // Guard against a fast edit from one $handle to another landing here
      // with the previous handle's resolved address still in state: only
      // trust resolvedHandle when it matches the current input.
      const normalizedHandle = trimmedTo.replace(/^\$/, "").trim().toLowerCase();
      if (resolvedHandle.handle.toLowerCase() !== normalizedHandle) {
        setError("Still resolving the handle — try again in a moment.");
        return;
      }
      resolvedTo = resolvedHandle.address;
    }

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
        to: resolvedTo,
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
        <label htmlFor="send-to">Recipient address or $handle</label>
        <div className="send-to-row">
          <Input
            id="send-to"
            type="text"
            placeholder="addr1... or $handle"
            value={to}
            onChange={(e) => setTo(e.target.value)}
            disabled={loading}
          />
          {contacts.data && contacts.data.length > 0 && (
            <Button
              variant="ghost"
              onClick={() => setPickerOpen((open) => !open)}
              disabled={loading}
              aria-controls={contactPickerListID}
              aria-expanded={pickerOpen}
            >
              Address book
            </Button>
          )}
        </div>
        {pickerOpen && contacts.data && contacts.data.length > 0 && (
          <ul id={contactPickerListID} className="contact-picker-list" aria-label="Saved contacts">
            {contacts.data.map((c) => (
              <li key={c.id}>
                <button
                  type="button"
                  className="contact-picker-item"
                  disabled={loading}
                  onClick={() => {
                    setTo(c.address);
                    setPickerOpen(false);
                  }}
                >
                  <span className="contact-picker-name">{c.name}</span>
                  <code className="contact-picker-address mono">{c.address}</code>
                </button>
              </li>
            ))}
          </ul>
        )}
        {handleInput && resolvingHandle && (
          <p className="helper-text">Resolving handle…</p>
        )}
        {handleInput && resolvedHandle && (
          <p className="verified-readout">
            <span className="verified-tick">✓ Resolved by your node</span>
            {" · "}${resolvedHandle.handle} → {resolvedHandle.address}
          </p>
        )}
        {handleInput && handleError && (
          <p role="alert" className="error-text">
            {handleError}
          </p>
        )}

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

        <Button
          onClick={handleReview}
          disabled={
            loading ||
            !to.trim() ||
            !adaAmount.trim() ||
            (handleInput && (resolvingHandle || !resolvedHandle))
          }
        >
          {loading ? "Building…" : "Review"}
        </Button>
      </div>
    </Card>
  );
}

// --- Preview phase ---

interface PreviewPhaseProps {
  preview: Preview;
  isHardware?: boolean;
  onBack: () => void;
  onDone: (result: TxResult) => void;
}

const OUTPUT_COLUMNS = [
  { key: "address", label: "Address" },
  { key: "lovelace", label: "ADA" },
  { key: "assets", label: "Assets" },
];

function PreviewPhase({ preview, isHardware, onBack, onDone }: PreviewPhaseProps) {
  // password is only used in the software (!isHardware) confirm path; hooks cannot be conditional.
  const [password, setPassword] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);
  const [exporting, setExporting] = useState(false);
  const [exported, setExported] = useState<UnsignedTx | null>(null);

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

  // Hardware confirm flow: connect Ledger → fetch signing request → signTx → submit.
  // WebHID's device chooser must be requested while the confirm click still
  // carries transient user activation, before yielding to a backend request.
  async function handleHardwareConfirm() {
    setError(null);
    setLoading(true);
    let session: LedgerSession | null = null;
    try {
      // 1. Connect directly from the click handler so a first-time user can
      // grant WebHID permission while browser user activation is still live.
      session = await connectLedger();

      // 2. Fetch the structured signing request once the device is connected.
      const signResp = await getHardwareSignRequest(preview.pending_id);
      if (signResp.unsupported) {
        setError(`This transaction cannot be signed on hardware: ${signResp.unsupported}`);
        return;
      }
      const request = mapToSignRequest(signResp);

      // 3. Sign on the connected Ledger device.
      const witnessCbor = await session.signTx(request);

      // 4. Submit the signed transaction.
      const result = await submitHardware(preview.pending_id, witnessCbor);
      onDone(result);
    } catch (e) {
      setError(errorMessage(e));
    } finally {
      if (session) await session.close().catch(() => {});
      setLoading(false);
    }
  }

  // Export the unsigned tx for offline signing. The result is shown for
  // copy/download so it can be carried to an air-gapped, keyed instance; the
  // pending send is not consumed, so the user may still confirm online instead.
  async function handleExport() {
    setError(null);
    setExported(null);
    setExporting(true);
    try {
      const res = await exportUnsigned(preview.pending_id);
      setExported(res);
    } catch (e) {
      setError(errorMessage(e));
    } finally {
      setExporting(false);
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

        {isHardware ? (
          <p className="helper-text">
            Connect your Ledger and confirm the transaction on the device.
          </p>
        ) : (
          <>
            <label htmlFor="spend-password">Spending password</label>
            <Input
              id="spend-password"
              type="password"
              placeholder="Spending password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
            />
          </>
        )}

        {error && (
          <p role="alert" className="error-text">
            {error}
          </p>
        )}

        <div className="preview-actions">
          <Button variant="ghost" onClick={onBack} disabled={loading || exporting}>
            Back
          </Button>
          {isHardware ? (
            <Button onClick={handleHardwareConfirm} disabled={loading || exporting}>
              {loading ? "Signing…" : "Confirm on Ledger"}
            </Button>
          ) : (
            <Button onClick={handleConfirm} disabled={loading || exporting || !password}>
              {loading ? "Submitting…" : "Confirm & send"}
            </Button>
          )}
        </div>

        {!isHardware && (
          <div className="offline-export">
            <Button variant="ghost" onClick={handleExport} disabled={loading || exporting}>
              {exporting ? "Exporting…" : "Export for offline signing"}
            </Button>
            {exported && (
              <div className="sign-result">
                <p className="helper-text">
                  Carry this unsigned transaction to your offline instance, sign it
                  there, then bring the witness back to Submit signed.
                </p>
                <p className="field-label">Unsigned transaction (CBOR)</p>
                <div className="tx-hash-row">
                  <code className="tx-hash">{exported.unsigned_tx_cbor}</code>
                  <CopyButton value={exported.unsigned_tx_cbor} />
                  <DownloadButton
                    value={exported.unsigned_tx_cbor}
                    filename="unsigned-tx.cbor"
                    label="Download"
                  />
                </div>
                {exported.required_signers.length > 0 && (
                  <>
                    <p className="field-label">Required signers</p>
                    <ul className="signer-list">
                      {exported.required_signers.map((s) => (
                        <li key={s}>
                          <code className="tx-hash">{s}</code>
                        </li>
                      ))}
                    </ul>
                  </>
                )}
              </div>
            )}
          </div>
        )}
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

export function Send({ isHardware }: { isHardware?: boolean } = {}) {
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
        isHardware={isHardware}
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
