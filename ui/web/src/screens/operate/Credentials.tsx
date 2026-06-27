import { useState } from "react";
import { Card } from "../../components/Card";
import { Input } from "../../components/Input";
import { Button } from "../../components/Button";
import { CopyButton } from "../../components/CopyButton";
import { poolCredentials } from "../../api/client";
import type { PoolCredentials, PoolKeyInfo } from "../../api/types";
import { errorMessage } from "./shared";

function KeyReadout({ label, info }: { label: string; info: PoolKeyInfo }) {
  return (
    <div className="key-readout">
      <p className="field-label">{label} verification key</p>
      <div className="tx-hash-row">
        <code className="tx-hash">{info.vkey_hex}</code>
        <CopyButton value={info.vkey_hex} aria-label={`Copy ${label} verification key`} />
      </div>
      <p className="field-label">{label} key hash</p>
      <div className="tx-hash-row">
        <code className="tx-hash">{info.hash_hex}</code>
        <CopyButton value={info.hash_hex} aria-label={`Copy ${label} key hash`} />
      </div>
    </div>
  );
}

// Credentials derives the active wallet's pool cold/VRF/KES credentials from
// the wallet seed (CIP-1853) and shows the verification keys, key hashes, and
// the derived pool ID. It requires the spending password; no node is needed.
export function Credentials() {
  const [password, setPassword] = useState("");
  const [creds, setCreds] = useState<PoolCredentials | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);

  async function handleGenerate() {
    if (loading || !password) return;
    setError(null);
    setCreds(null);
    setLoading(true);
    try {
      setCreds(await poolCredentials(password));
    } catch (e) {
      setError(errorMessage(e));
    } finally {
      setPassword("");
      setLoading(false);
    }
  }

  return (
    <Card title="Pool credentials">
      <form
        className="operate-form"
        onSubmit={(e) => {
          e.preventDefault();
          void handleGenerate();
        }}
      >
        <p className="helper-text">
          Derive this pool&rsquo;s cold, VRF, and KES keys from the wallet seed and
          show the resulting pool ID. The cold signing key never leaves memory.
        </p>
        <label htmlFor="cred-password">Spending password</label>
        <Input
          id="cred-password"
          type="password"
          value={password}
          onChange={(e) => {
            setPassword(e.target.value);
            setError(null);
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
        <Button type="submit" disabled={loading || !password}>
          {loading ? "Deriving…" : "Generate credentials"}
        </Button>

        {creds && (
          <div className="creds-result">
            <p className="field-label">Pool ID</p>
            <div className="tx-hash-row">
              <code className="tx-hash accent">{creds.pool_id}</code>
              <CopyButton value={creds.pool_id} aria-label="Copy Pool ID" />
            </div>
            <KeyReadout label="Cold" info={creds.cold} />
            <KeyReadout label="VRF" info={creds.vrf} />
            <KeyReadout label="KES" info={creds.kes} />
          </div>
        )}
      </form>
    </Card>
  );
}
