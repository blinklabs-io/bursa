import { useState } from "react";
import { Card } from "../components/Card";
import { Input } from "../components/Input";
import { Button } from "../components/Button";
import { verifyData, ApiError } from "../api/client";
import type { VerifyDataResult } from "../api/types";

// VerifyMessage verifies a CIP-8 / CIP-30 signData result: a COSE_Sign1
// signature + COSE_Key (the Sign screen's output) over a message. It is fully
// offline (pure crypto — no node, no keystore) and reports whether the
// signature is valid and which address signed it. An optional expected address
// pins the verification to a specific signer.
export function VerifyMessage() {
  const [signature, setSignature] = useState("");
  const [key, setKey] = useState("");
  const [message, setMessage] = useState("");
  const [expectedAddress, setExpectedAddress] = useState("");
  const [result, setResult] = useState<VerifyDataResult | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);

  // Editing any field invalidates a previous result/error so the verdict shown
  // always matches the current inputs.
  function clearResult() {
    setResult(null);
    setError(null);
  }

  async function handleVerify() {
    setError(null);
    setResult(null);
    setLoading(true);
    try {
      const res = await verifyData({
        signature: signature.trim(),
        key: key.trim(),
        message,
        ...(expectedAddress.trim() ? { expected_address: expectedAddress.trim() } : {}),
      });
      setResult(res);
    } catch (e) {
      setError(e instanceof ApiError ? e.message : "An unexpected error occurred");
    } finally {
      setLoading(false);
    }
  }

  return (
    <Card title="Verify Message">
      <div className="sign-form">
        <p className="helper-text">
          Check a CIP-8 / CIP-30 signature. Paste the COSE_Sign1 signature and
          COSE_Key from a Sign result, along with the original message, to confirm
          it is valid and see which address signed it.
        </p>

        <label htmlFor="verify-signature">Signature (COSE_Sign1)</label>
        <textarea
          id="verify-signature"
          className="field"
          rows={3}
          value={signature}
          onChange={(e) => {
            setSignature(e.target.value);
            clearResult();
          }}
          placeholder="hex…"
          aria-label="Signature"
          disabled={loading}
        />

        <label htmlFor="verify-key">Key (COSE_Key)</label>
        <textarea
          id="verify-key"
          className="field"
          rows={2}
          value={key}
          onChange={(e) => {
            setKey(e.target.value);
            clearResult();
          }}
          placeholder="hex…"
          aria-label="Key"
          disabled={loading}
        />

        <label htmlFor="verify-message">Message</label>
        <textarea
          id="verify-message"
          className="field"
          rows={4}
          value={message}
          onChange={(e) => {
            setMessage(e.target.value);
            clearResult();
          }}
          placeholder="The message that was signed…"
          aria-label="Message"
          disabled={loading}
        />

        <label htmlFor="verify-expected">Expected address (optional)</label>
        <Input
          id="verify-expected"
          type="text"
          value={expectedAddress}
          onChange={(e) => {
            setExpectedAddress(e.target.value);
            clearResult();
          }}
          placeholder="addr1… — leave blank to accept any signer"
          aria-label="Expected address"
          disabled={loading}
        />

        {error && (
          <p role="alert" className="error-text">
            {error}
          </p>
        )}

        <Button
          onClick={handleVerify}
          disabled={loading || !signature.trim() || !key.trim()}
        >
          {loading ? "Verifying…" : "Verify signature"}
        </Button>

        {result && (
          <div className="sign-result">
            {result.valid ? (
              <p role="status" className="success-text">
                Valid signature
              </p>
            ) : (
              <p role="status" className="error-text">
                Invalid signature
              </p>
            )}
            {result.address && (
              <>
                <p className="field-label">Signed by</p>
                <div className="tx-hash-row">
                  <code className="tx-hash">{result.address}</code>
                </div>
              </>
            )}
          </div>
        )}
      </div>
    </Card>
  );
}
