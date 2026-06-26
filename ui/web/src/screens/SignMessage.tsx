import { useState } from "react";
import { Card } from "../components/Card";
import { Input } from "../components/Input";
import { Select } from "../components/Select";
import { Button } from "../components/Button";
import { CopyButton } from "../components/CopyButton";
import { signData, ApiError } from "../api/client";
import type { Account, SignDataResult } from "../api/types";

interface SignMessageProps {
  account: Account;
}

// SignMessage signs an arbitrary message with one of the wallet's keys
// (CIP-8/CIP-30 signData → COSE_Sign1). It is fully offline — no node needed —
// and requires the spending password to unlock the keystore.
export function SignMessage({ account }: SignMessageProps) {
  const [address, setAddress] = useState(account.receive_addresses[0] ?? "");
  const [message, setMessage] = useState("");
  const [password, setPassword] = useState("");
  const [result, setResult] = useState<SignDataResult | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);

  const addressOptions = account.receive_addresses.map((a) => ({ value: a, label: a }));

  async function handleSign() {
    setError(null);
    setResult(null);
    setLoading(true);
    try {
      const res = await signData({ address, message, password });
      setResult(res);
    } catch (e) {
      setError(e instanceof ApiError ? e.message : "An unexpected error occurred");
    } finally {
      setLoading(false);
    }
  }

  return (
    <Card title="Sign Message">
      <div className="sign-form">
        <p className="helper-text">
          Prove you control an address by signing a message with its key. The
          result is a CIP-8 / CIP-30 signature you can hand to a dApp or verifier.
        </p>

        <label htmlFor="sign-address">Signing address</label>
        <Select
          id="sign-address"
          options={addressOptions}
          value={address}
          onChange={(e) => setAddress(e.target.value)}
          disabled={loading}
        />

        <label htmlFor="sign-message">Message</label>
        <textarea
          id="sign-message"
          className="field"
          rows={4}
          value={message}
          onChange={(e) => setMessage(e.target.value)}
          placeholder="Enter a message to sign…"
          aria-label="Message"
          disabled={loading}
        />

        <label htmlFor="sign-password">Spending password</label>
        <Input
          id="sign-password"
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

        <Button onClick={handleSign} disabled={loading || !message.trim() || !password}>
          {loading ? "Signing…" : "Sign message"}
        </Button>

        {result && (
          <div className="sign-result">
            <p className="field-label">Signature (COSE_Sign1)</p>
            <div className="tx-hash-row">
              <code className="tx-hash">{result.signature}</code>
              <CopyButton value={result.signature} />
            </div>
            <p className="field-label">Key (COSE_Key)</p>
            <div className="tx-hash-row">
              <code className="tx-hash">{result.key}</code>
              <CopyButton value={result.key} />
            </div>
          </div>
        )}
      </div>
    </Card>
  );
}
