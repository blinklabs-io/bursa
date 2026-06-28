import { useState } from "react";
import { Card } from "../../components/Card";
import { Input } from "../../components/Input";
import { Button } from "../../components/Button";
import { CopyButton } from "../../components/CopyButton";
import {
  poolKESPeriod,
  poolIssueOpCert,
  poolRotateKES,
  poolOpCertPayload,
  poolAssembleOpCert,
} from "../../api/client";
import type { OpCert, OpCertPayload, KESPeriodInfo } from "../../api/types";
import { errorMessage } from "./shared";

type Mode = "seed" | "airgap";

function OpCertResult({ opcert }: { opcert: OpCert }) {
  return (
    <div className="opcert-result">
      <dl className="preview-summary">
        <div className="dl-row">
          <dt>Issue number</dt>
          <dd>{opcert.issue_number}</dd>
        </div>
        <div className="dl-row">
          <dt>KES period</dt>
          <dd>{opcert.kes_period}</dd>
        </div>
      </dl>
      <p className="field-label">KES verification key</p>
      <div className="tx-hash-row">
        <code className="tx-hash">{opcert.kes_vkey_hex}</code>
        <CopyButton value={opcert.kes_vkey_hex} />
      </div>
      <p className="field-label">Cold signature</p>
      <div className="tx-hash-row">
        <code className="tx-hash">{opcert.cold_signature_hex}</code>
        <CopyButton value={opcert.cold_signature_hex} />
      </div>
    </div>
  );
}

// OperationalCert issues an operational certificate (binding the KES key to the
// cold key), supports KES rotation (new KES key + incremented issue counter),
// and shows the current KES period (node tip ÷ slots-per-KES-period). It works
// from the wallet seed or via an air-gapped cold key.
export function OperationalCert() {
  const [mode, setMode] = useState<Mode>("seed");
  const [kes, setKes] = useState<KESPeriodInfo | null>(null);
  const [kesError, setKesError] = useState<string | null>(null);

  async function loadKESPeriod() {
    setKesError(null);
    try {
      setKes(await poolKESPeriod());
    } catch (e) {
      setKesError(errorMessage(e));
    }
  }

  return (
    <Card title="Operational certificate">
      <div className="operate-form">
        <div className="kes-period">
          <Button variant="ghost" onClick={loadKESPeriod}>
            Read current KES period
          </Button>
          {kes && (
            <dl className="preview-summary">
              <div className="dl-row">
                <dt>Current KES period</dt>
                <dd className="accent">{kes.current_period}</dd>
              </div>
              <div className="dl-row">
                <dt>Tip slot</dt>
                <dd>{kes.tip_slot}</dd>
              </div>
              <div className="dl-row">
                <dt>Slots / KES period</dt>
                <dd>{kes.slots_per_kes_period}</dd>
              </div>
            </dl>
          )}
          {kesError && (
            <p role="alert" className="error-text">
              {kesError}
            </p>
          )}
        </div>

        <div className="mode-toggle" role="tablist">
          <button
            role="tab"
            aria-selected={mode === "seed"}
            className={mode === "seed" ? "operate-tab active" : "operate-tab"}
            onClick={() => setMode("seed")}
          >
            From wallet seed
          </button>
          <button
            role="tab"
            aria-selected={mode === "airgap"}
            className={mode === "airgap" ? "operate-tab active" : "operate-tab"}
            onClick={() => setMode("airgap")}
          >
            Air-gap
          </button>
        </div>

        {mode === "seed" ? <SeedOpCert /> : <AirGapOpCert />}
      </div>
    </Card>
  );
}

// SeedOpCert issues or rotates an opcert using the wallet seed.
function SeedOpCert() {
  const [rotate, setRotate] = useState(false);
  const [password, setPassword] = useState("");
  const [kesIndex, setKesIndex] = useState("0");
  const [issueNumber, setIssueNumber] = useState("0");
  const [kesPeriod, setKesPeriod] = useState("0");
  const [opcert, setOpcert] = useState<OpCert | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);

  async function handleSubmit() {
    setError(null);
    setOpcert(null);
    setLoading(true);
    try {
      const kesPeriodN = Number(kesPeriod);
      if (rotate) {
        setOpcert(
          await poolRotateKES({
            password,
            new_kes_index: Number(kesIndex),
            prev_issue_number: Number(issueNumber),
            kes_period: kesPeriodN,
          }),
        );
      } else {
        setOpcert(
          await poolIssueOpCert({
            password,
            kes_index: Number(kesIndex),
            issue_number: Number(issueNumber),
            kes_period: kesPeriodN,
          }),
        );
      }
    } catch (e) {
      setError(errorMessage(e));
    } finally {
      setLoading(false);
    }
  }

  return (
    <div className="operate-subform">
      <label className="checkbox-row">
        <input
          type="checkbox"
          checked={rotate}
          onChange={(e) => setRotate(e.target.checked)}
          aria-label="KES rotation"
        />
        KES rotation (new KES key + incremented counter)
      </label>

      <label htmlFor="oc-kes-index">{rotate ? "New KES key index" : "KES key index"}</label>
      <Input
        id="oc-kes-index"
        type="number"
        min="0"
        value={kesIndex}
        onChange={(e) => setKesIndex(e.target.value)}
        disabled={loading}
      />

      <label htmlFor="oc-issue">{rotate ? "Previous issue number" : "Issue number"}</label>
      <Input
        id="oc-issue"
        type="number"
        min="0"
        value={issueNumber}
        onChange={(e) => setIssueNumber(e.target.value)}
        disabled={loading}
      />

      <label htmlFor="oc-period">KES period</label>
      <Input
        id="oc-period"
        type="number"
        min="0"
        value={kesPeriod}
        onChange={(e) => setKesPeriod(e.target.value)}
        disabled={loading}
      />

      <label htmlFor="oc-password">Spending password</label>
      <Input
        id="oc-password"
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

      <Button onClick={handleSubmit} disabled={loading || !password}>
        {loading ? "Working…" : rotate ? "Rotate KES" : "Issue certificate"}
      </Button>

      {opcert && <OpCertResult opcert={opcert} />}
    </div>
  );
}

// AirGapOpCert produces the to-be-signed payload for an offline cold key, then
// assembles an opcert from the externally-produced signature.
function AirGapOpCert() {
  const [kesVKey, setKesVKey] = useState("");
  const [coldVKey, setColdVKey] = useState("");
  const [issueNumber, setIssueNumber] = useState("0");
  const [kesPeriod, setKesPeriod] = useState("0");
  const [signature, setSignature] = useState("");
  const [payload, setPayload] = useState<OpCertPayload | null>(null);
  const [opcert, setOpcert] = useState<OpCert | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);

  async function handlePayload() {
    setError(null);
    setPayload(null);
    setOpcert(null);
    setLoading(true);
    try {
      setPayload(
        await poolOpCertPayload({
          kes_vkey_hex: kesVKey.trim(),
          issue_number: Number(issueNumber),
          kes_period: Number(kesPeriod),
        }),
      );
    } catch (e) {
      setError(errorMessage(e));
    } finally {
      setLoading(false);
    }
  }

  async function handleAssemble() {
    setError(null);
    setOpcert(null);
    setLoading(true);
    try {
      setOpcert(
        await poolAssembleOpCert({
          cold_vkey_hex: coldVKey.trim(),
          kes_vkey_hex: kesVKey.trim(),
          signature_hex: signature.trim(),
          issue_number: Number(issueNumber),
          kes_period: Number(kesPeriod),
        }),
      );
    } catch (e) {
      setError(errorMessage(e));
    } finally {
      setLoading(false);
    }
  }

  return (
    <div className="operate-subform">
      <p className="helper-text">
        Step 1: produce the to-be-signed payload. Step 2: sign it offline with the
        cold key, then paste the signature to assemble the certificate.
      </p>

      <label htmlFor="oc-ag-kesvkey">KES verification key (hex)</label>
      <Input
        id="oc-ag-kesvkey"
        type="text"
        value={kesVKey}
        onChange={(e) => setKesVKey(e.target.value)}
        placeholder="32-byte KES vkey, hex"
        disabled={loading}
      />

      <label htmlFor="oc-ag-issue">Issue number</label>
      <Input
        id="oc-ag-issue"
        type="number"
        min="0"
        value={issueNumber}
        onChange={(e) => setIssueNumber(e.target.value)}
        disabled={loading}
      />

      <label htmlFor="oc-ag-period">KES period</label>
      <Input
        id="oc-ag-period"
        type="number"
        min="0"
        value={kesPeriod}
        onChange={(e) => setKesPeriod(e.target.value)}
        disabled={loading}
      />

      <Button variant="ghost" onClick={handlePayload} disabled={loading || !kesVKey.trim()}>
        {loading ? "Working…" : "Build to-be-signed payload"}
      </Button>

      {payload && (
        <div>
          <p className="field-label">Payload to sign (hex)</p>
          <div className="tx-hash-row">
            <code className="tx-hash">{payload.payload_hex}</code>
            <CopyButton value={payload.payload_hex} />
          </div>
        </div>
      )}

      <label htmlFor="oc-ag-coldvkey">Cold verification key (hex)</label>
      <Input
        id="oc-ag-coldvkey"
        type="text"
        value={coldVKey}
        onChange={(e) => setColdVKey(e.target.value)}
        placeholder="32-byte cold vkey, hex"
        disabled={loading}
      />

      <label htmlFor="oc-ag-sig">Cold signature (hex)</label>
      <Input
        id="oc-ag-sig"
        type="text"
        value={signature}
        onChange={(e) => setSignature(e.target.value)}
        placeholder="64-byte signature, hex"
        disabled={loading}
      />

      {error && (
        <p role="alert" className="error-text">
          {error}
        </p>
      )}

      <Button
        onClick={handleAssemble}
        disabled={loading || !coldVKey.trim() || !signature.trim() || !kesVKey.trim()}
      >
        {loading ? "Working…" : "Assemble certificate"}
      </Button>

      {opcert && <OpCertResult opcert={opcert} />}
    </div>
  );
}
