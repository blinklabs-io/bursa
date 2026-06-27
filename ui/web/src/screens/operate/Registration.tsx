import { useState } from "react";
import type { Dispatch, SetStateAction } from "react";
import { Card } from "../../components/Card";
import { Input } from "../../components/Input";
import { Select } from "../../components/Select";
import { Button } from "../../components/Button";
import { CopyButton } from "../../components/CopyButton";
import { poolBuildRegistration, poolBuildRegistrationAirGap } from "../../api/client";
import type { Account, PoolCertResult, PoolRelayInput } from "../../api/types";
import { errorMessage } from "./shared";

type Mode = "seed" | "airgap";

interface RelayRow {
  type: PoolRelayInput["type"];
  host: string; // ipv4 / ipv6 / hostname depending on type
  port: string;
}

const RELAY_TYPES = [
  { value: "single_host_address", label: "IP address" },
  { value: "single_host_name", label: "DNS name" },
  { value: "multi_host_name", label: "DNS (SRV)" },
];

function toRelayInput(r: RelayRow): PoolRelayInput {
  const out: PoolRelayInput = { type: r.type };
  const host = r.host.trim();
  if (r.type === "single_host_address") {
    // Heuristic: an address containing ":" is IPv6, otherwise IPv4.
    if (host.includes(":")) out.ipv6 = host;
    else out.ipv4 = host;
  } else {
    out.hostname = host;
  }
  if (r.type !== "multi_host_name" && r.port.trim()) {
    out.port = Number(r.port);
  }
  return out;
}

// Registration builds a pool registration (or update — same certificate with
// new params) from pledge/cost/margin, the reward account, owners, relays, and
// optional metadata. It works from the wallet seed or an air-gapped cold vkey
// (plus VRF key hash). The certificate is the canonical CBOR an operator submits
// or hands to an offline cold-key signer.
export function Registration({ account }: { account: Account }) {
  const [mode, setMode] = useState<Mode>("seed");

  // Shared params.
  const [pledge, setPledge] = useState("");
  const [cost, setCost] = useState("340000000");
  const [marginNum, setMarginNum] = useState("3");
  const [marginDenom, setMarginDenom] = useState("100");
  const [rewardAddress, setRewardAddress] = useState("");
  const [owners, setOwners] = useState("");
  const [relays, setRelays] = useState<RelayRow[]>([]);
  const [metadataUrl, setMetadataUrl] = useState("");
  const [metadataHash, setMetadataHash] = useState("");

  // Mode-specific.
  const [password, setPassword] = useState("");
  const [coldVKey, setColdVKey] = useState("");
  const [vrfHash, setVrfHash] = useState("");

  const [result, setResult] = useState<PoolCertResult | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);

  function commonParams() {
    const ownerList = owners
      .split(/[\s,]+/)
      .map((o) => o.trim())
      .filter(Boolean);
    return {
      pledge: Number(pledge),
      cost: Number(cost),
      margin_num: Number(marginNum),
      margin_denom: Number(marginDenom),
      ...(rewardAddress.trim() ? { reward_address: rewardAddress.trim() } : {}),
      ...(ownerList.length > 0 ? { owners: ownerList } : {}),
      ...(relays.length > 0 ? { relays: relays.map(toRelayInput) } : {}),
      ...(metadataUrl.trim() ? { metadata_url: metadataUrl.trim() } : {}),
      ...(metadataHash.trim() ? { metadata_hash: metadataHash.trim() } : {}),
    };
  }

  async function handleBuild() {
    setError(null);
    setResult(null);
    if (!pledge.trim() || !cost.trim()) {
      setError("Pledge and cost are required");
      return;
    }
    setLoading(true);
    try {
      if (mode === "seed") {
        setResult(await poolBuildRegistration({ password, ...commonParams() }));
      } else {
        setResult(
          await poolBuildRegistrationAirGap({
            cold_vkey_hex: coldVKey.trim(),
            vrf_key_hash_hex: vrfHash.trim(),
            ...commonParams(),
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
    <Card title="Pool registration / update">
      <div className="operate-form">
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

        <label htmlFor="reg-pledge">Pledge (lovelace)</label>
        <Input
          id="reg-pledge"
          type="number"
          min="0"
          value={pledge}
          onChange={(e) => setPledge(e.target.value)}
          placeholder="100000000"
          disabled={loading}
        />

        <label htmlFor="reg-cost">Fixed cost per epoch (lovelace)</label>
        <Input
          id="reg-cost"
          type="number"
          min="0"
          value={cost}
          onChange={(e) => setCost(e.target.value)}
          disabled={loading}
        />

        <div className="field-group">
          <div>
            <label htmlFor="reg-margin-num">Margin numerator</label>
            <Input
              id="reg-margin-num"
              type="number"
              min="0"
              value={marginNum}
              onChange={(e) => setMarginNum(e.target.value)}
              disabled={loading}
            />
          </div>
          <div>
            <label htmlFor="reg-margin-denom">Margin denominator</label>
            <Input
              id="reg-margin-denom"
              type="number"
              min="1"
              value={marginDenom}
              onChange={(e) => setMarginDenom(e.target.value)}
              disabled={loading}
            />
          </div>
        </div>

        <label htmlFor="reg-reward">Reward account (defaults to this wallet)</label>
        <Input
          id="reg-reward"
          type="text"
          value={rewardAddress}
          onChange={(e) => setRewardAddress(e.target.value)}
          placeholder={account.stake_address}
          disabled={loading}
        />

        <label htmlFor="reg-owners">
          Owners (stake addresses or key hashes; defaults to this wallet)
        </label>
        <Input
          id="reg-owners"
          type="text"
          value={owners}
          onChange={(e) => setOwners(e.target.value)}
          placeholder="stake1…, stake1… (comma or space separated)"
          disabled={loading}
        />

        <RelayEditor relays={relays} setRelays={setRelays} disabled={loading} />

        <label htmlFor="reg-meta-url">Metadata URL (optional)</label>
        <Input
          id="reg-meta-url"
          type="text"
          value={metadataUrl}
          onChange={(e) => setMetadataUrl(e.target.value)}
          placeholder="https://pool.example/meta.json"
          disabled={loading}
        />

        <label htmlFor="reg-meta-hash">Metadata hash (hex, from the Metadata tab)</label>
        <Input
          id="reg-meta-hash"
          type="text"
          value={metadataHash}
          onChange={(e) => setMetadataHash(e.target.value)}
          placeholder="blake2b-256 hex"
          disabled={loading}
        />

        {mode === "seed" ? (
          <>
            <label htmlFor="reg-password">Spending password</label>
            <Input
              id="reg-password"
              type="password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              placeholder="Spending password"
              aria-label="Spending password"
              disabled={loading}
            />
          </>
        ) : (
          <>
            <label htmlFor="reg-coldvkey">Cold verification key (hex)</label>
            <Input
              id="reg-coldvkey"
              type="text"
              value={coldVKey}
              onChange={(e) => setColdVKey(e.target.value)}
              placeholder="32-byte cold vkey, hex"
              disabled={loading}
            />
            <label htmlFor="reg-vrfhash">VRF key hash (hex)</label>
            <Input
              id="reg-vrfhash"
              type="text"
              value={vrfHash}
              onChange={(e) => setVrfHash(e.target.value)}
              placeholder="32-byte VRF key hash, hex"
              disabled={loading}
            />
          </>
        )}

        {error && (
          <p role="alert" className="error-text">
            {error}
          </p>
        )}

        <Button
          onClick={handleBuild}
          disabled={
            loading ||
            (mode === "seed" ? !password : !coldVKey.trim() || !vrfHash.trim())
          }
        >
          {loading ? "Building…" : "Build certificate"}
        </Button>

        <p className="helper-text">
          Note: building produces the registration certificate (CBOR). Submitting
          a registration transaction in-app is not yet wired (see the in-repo TODO
          on the pool-registration tx path); hand the certificate to your stake-pool
          tooling, or export it for offline cold-key signing.
        </p>

        {result && (
          <div className="cert-result">
            <p className="field-label">Pool ID</p>
            <div className="tx-hash-row">
              <code className="tx-hash accent">{result.pool_id}</code>
              <CopyButton value={result.pool_id} />
            </div>
            <p className="field-label">Certificate (CBOR hex)</p>
            <div className="tx-hash-row">
              <code className="tx-hash">{result.cbor_hex}</code>
              <CopyButton value={result.cbor_hex} />
            </div>
          </div>
        )}
      </div>
    </Card>
  );
}

interface RelayEditorProps {
  relays: RelayRow[];
  setRelays: Dispatch<SetStateAction<RelayRow[]>>;
  disabled: boolean;
}

function RelayEditor({ relays, setRelays, disabled }: RelayEditorProps) {
  function add() {
    setRelays((prev) => [...prev, { type: "single_host_address", host: "", port: "" }]);
  }
  function remove(i: number) {
    setRelays((prev) => prev.filter((_, idx) => idx !== i));
  }
  function update(i: number, field: keyof RelayRow, value: string) {
    setRelays((prev) =>
      prev.map((r, idx) => (idx === i ? { ...r, [field]: value } : r)),
    );
  }

  return (
    <div className="relay-editor">
      <p className="field-label">Relays</p>
      {relays.map((r, i) => (
        <div key={i} className="relay-row">
          <Select
            options={RELAY_TYPES}
            value={r.type}
            onChange={(e) => update(i, "type", e.target.value)}
            aria-label="Relay type"
            disabled={disabled}
          />
          <Input
            type="text"
            value={r.host}
            onChange={(e) => update(i, "host", e.target.value)}
            placeholder={r.type === "single_host_address" ? "IP address" : "hostname"}
            aria-label="Relay host"
            disabled={disabled}
          />
          {r.type !== "multi_host_name" && (
            <Input
              type="number"
              min="0"
              value={r.port}
              onChange={(e) => update(i, "port", e.target.value)}
              placeholder="port"
              aria-label="Relay port"
              disabled={disabled}
            />
          )}
          <Button variant="ghost" onClick={() => remove(i)} disabled={disabled}>
            Remove
          </Button>
        </div>
      ))}
      <Button variant="ghost" onClick={add} disabled={disabled}>
        + Add relay
      </Button>
    </div>
  );
}
