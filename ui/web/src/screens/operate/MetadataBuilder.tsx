import { useState } from "react";
import { Card } from "../../components/Card";
import { Input } from "../../components/Input";
import { Button } from "../../components/Button";
import { CopyButton } from "../../components/CopyButton";
import { poolBuildMetadata } from "../../api/client";
import type { PoolMetadataResult } from "../../api/types";
import { errorMessage } from "./shared";

// MetadataBuilder turns operator-supplied pool metadata (name, ticker, homepage,
// description) into canonical RFC 8785 (JCS) JSON and its Blake2b-256 hash. The
// operator hosts the JSON and references the URL + hash in the registration
// certificate. Nothing is fetched — the metadata is provided here.
export function MetadataBuilder() {
  const [name, setName] = useState("");
  const [ticker, setTicker] = useState("");
  const [homepage, setHomepage] = useState("");
  const [description, setDescription] = useState("");
  const [result, setResult] = useState<PoolMetadataResult | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);

  async function handleBuild() {
    setError(null);
    setResult(null);
    setLoading(true);
    try {
      setResult(
        await poolBuildMetadata({
          name: name.trim(),
          ticker: ticker.trim(),
          homepage: homepage.trim(),
          description: description.trim(),
        }),
      );
    } catch (e) {
      setError(errorMessage(e));
    } finally {
      setLoading(false);
    }
  }

  return (
    <Card title="Pool metadata">
      <div className="operate-form">
        <p className="helper-text">
          Build the metadata document you host and reference in registration. The
          hash below is what goes in the registration certificate.
        </p>

        <label htmlFor="md-name">Name</label>
        <Input
          id="md-name"
          type="text"
          value={name}
          onChange={(e) => setName(e.target.value)}
          placeholder="My Stake Pool"
          disabled={loading}
        />

        <label htmlFor="md-ticker">Ticker</label>
        <Input
          id="md-ticker"
          type="text"
          value={ticker}
          onChange={(e) => setTicker(e.target.value)}
          placeholder="POOL"
          disabled={loading}
        />

        <label htmlFor="md-homepage">Homepage</label>
        <Input
          id="md-homepage"
          type="text"
          value={homepage}
          onChange={(e) => setHomepage(e.target.value)}
          placeholder="https://pool.example"
          disabled={loading}
        />

        <label htmlFor="md-description">Description</label>
        <textarea
          id="md-description"
          className="field"
          rows={3}
          value={description}
          onChange={(e) => setDescription(e.target.value)}
          placeholder="A short description of your pool…"
          aria-label="Description"
          disabled={loading}
        />

        {error && (
          <p role="alert" className="error-text">
            {error}
          </p>
        )}

        <Button onClick={handleBuild} disabled={loading || !name.trim() || !ticker.trim()}>
          {loading ? "Building…" : "Build metadata"}
        </Button>

        {result && (
          <div className="metadata-result">
            <p className="field-label">Metadata hash (Blake2b-256)</p>
            <div className="tx-hash-row">
              <code className="tx-hash accent">{result.hash_hex}</code>
              <CopyButton value={result.hash_hex} />
            </div>
            <p className="field-label">Canonical JSON (host this at your metadata URL)</p>
            <div className="tx-hash-row">
              <code className="tx-hash">{result.json}</code>
              <CopyButton value={result.json} />
            </div>
          </div>
        )}
      </div>
    </Card>
  );
}
