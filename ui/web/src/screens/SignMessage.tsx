import { useState } from "react";
import { Card } from "../components/Card";
import { Input } from "../components/Input";
import { Select } from "../components/Select";
import { Button } from "../components/Button";
import { CopyButton } from "../components/CopyButton";
import { signData, getHardwareSignDataRequest, ApiError } from "../api/client";
import type { Account, SignDataResult } from "../api/types";
import { connectHardware } from "../hw";
import type { HardwareKind, HardwareSigner } from "../hw";
import { getStoredDeviceKind } from "../hw/deviceKind";
import { errorMessage } from "../errorMessage";

// Human-readable device names for the hardware picker.
const DEVICE_LABELS: Record<HardwareKind, string> = {
  ledger: "Ledger",
  trezor: "Trezor",
  keystone: "Keystone",
  seedsigner: "SeedSigner",
};

// The devices that can sign a CIP-8 message today. Keystone's and SeedSigner's
// air-gapped QR CIP-8 flows are not wired yet (their capabilities.signMessage
// is false), so neither is offered here — a wallet backed by either shows the
// unsupported state below instead.
const MESSAGE_SIGN_KINDS = ["ledger", "trezor"] as const;

interface SignMessageProps {
  account: Account;
  // When true, the active wallet is hardware-backed: signing happens on the
  // device (no spending password) rather than against the local keystore.
  isHardware?: boolean;
  // The active wallet id, used to look up which device kind backs it.
  walletId?: string;
}

// utf8ToHex hex-encodes the raw UTF-8 bytes of a message — the payload form the
// device expects (and the exact bytes the software path signs, so the two
// produce the same COSE payload).
function utf8ToHex(s: string): string {
  return Array.from(new TextEncoder().encode(s))
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

// SignMessage signs an arbitrary message with one of the wallet's keys
// (CIP-8/CIP-30 signData → COSE_Sign1). For a full wallet it signs offline
// against the keystore (spending password); for a hardware wallet it connects
// the device and signs on-device (no password). Both produce the same
// COSE_Sign1 + COSE_Key result shape.
export function SignMessage({ account, isHardware = false, walletId }: SignMessageProps) {
  const [address, setAddress] = useState(account.receive_addresses[0] ?? "");
  const [message, setMessage] = useState("");
  const [password, setPassword] = useState("");
  const [result, setResult] = useState<SignDataResult | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);

  // Which hardware device backs this wallet. A message-signing-capable stored
  // hint is used directly; a Keystone hint (no CIP-8 yet) or a missing hint
  // routes to the unsupported / picker states below.
  const storedKind = walletId ? getStoredDeviceKind(walletId) : undefined;
  const [chosenKind, setChosenKind] = useState<HardwareKind | undefined>(
    storedKind === "ledger" || storedKind === "trezor" ? storedKind : undefined,
  );
  const [externalConsent, setExternalConsent] = useState(false);

  const deviceKind = chosenKind;
  const needsExternalConsent = deviceKind === "trezor";
  // A Keystone- or SeedSigner-backed wallet cannot sign messages here yet:
  // their air-gapped QR CIP-8 flow is not implemented, so surface a clear
  // unsupported state instead of a picker.
  const storedKindUnsupported =
    storedKind !== undefined &&
    !(MESSAGE_SIGN_KINDS as readonly string[]).includes(storedKind);
  const keystoneUnsupported = isHardware && storedKindUnsupported;
  // Show the device picker when the wallet is hardware, is not an unsupported
  // stored device, and no message-capable device kind is known yet.
  const showDevicePicker = isHardware && !keystoneUnsupported && deviceKind === undefined;

  const addressOptions = account.receive_addresses.map((a) => ({ value: a, label: a }));

  // Editing any field invalidates a previous result/error — clear it so the
  // displayed signature always matches the current inputs.
  function clearResult() {
    setResult(null);
    setError(null);
  }

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

  // Hardware sign flow: connect the device → resolve the seedless signing paths
  // for the chosen address → sign on-device → show the COSE result. The connect
  // happens first, directly in the handler, so WebHID/WebUSB permission can be
  // requested while browser user activation is still live.
  async function handleHardwareSign() {
    setError(null);
    setResult(null);
    if (deviceKind === undefined) {
      setError("Choose which hardware device backs this wallet to continue.");
      return;
    }
    const kind = deviceKind;
    setLoading(true);
    let session: HardwareSigner | null = null;
    try {
      // For a local device (Ledger) the consent callback is ignored; for Trezor
      // it reports the already-ticked approval and connectTrezor enforces it.
      session = await connectHardware(kind, async () => externalConsent);
      if (!session.capabilities.signMessage) {
        setError(`Message signing is not supported on ${DEVICE_LABELS[kind]}.`);
        return;
      }
      const req = await getHardwareSignDataRequest(address);
      const signed = await session.signMessage({
        messageHex: utf8ToHex(message),
        signingPath: req.signing_path,
        stakePath: req.stake_path,
        networkId: req.network_id,
        protocolMagic: req.protocol_magic,
      });
      setResult(signed);
    } catch (e) {
      setError(errorMessage(e));
    } finally {
      if (session) await session.close().catch(() => {});
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

        {keystoneUnsupported ? (
          <p role="alert" className="error-text">
            Message signing is not supported on{" "}
            {storedKind ? DEVICE_LABELS[storedKind] : "this device"} yet. Use a
            Ledger or Trezor hardware wallet, or a full (seed) wallet, to sign
            a message.
          </p>
        ) : (
          <>
            <label htmlFor="sign-address">Signing address</label>
            <Select
              id="sign-address"
              options={addressOptions}
              value={address}
              onChange={(e) => {
                setAddress(e.target.value);
                clearResult();
              }}
              disabled={loading}
            />

            <label htmlFor="sign-message">Message</label>
            <textarea
              id="sign-message"
              className="field"
              rows={4}
              value={message}
              onChange={(e) => {
                setMessage(e.target.value);
                clearResult();
              }}
              placeholder="Enter a message to sign…"
              aria-label="Message"
              disabled={loading}
            />

            {isHardware ? (
              <>
                {showDevicePicker && (
                  <fieldset
                    className="field-group"
                    style={{ border: "none", padding: 0, margin: 0 }}
                  >
                    <legend className="field-label">Which device backs this wallet?</legend>
                    <p className="helper-text">
                      Choose the hardware wallet you used to add this account.
                    </p>
                    {MESSAGE_SIGN_KINDS.map((k) => (
                      <label className="checkbox-row" key={k}>
                        <input
                          type="radio"
                          name="sign-hw-device"
                          value={k}
                          checked={deviceKind === k}
                          onChange={() => {
                            setChosenKind(k);
                            clearResult();
                          }}
                          aria-label={DEVICE_LABELS[k]}
                        />
                        {DEVICE_LABELS[k]}
                      </label>
                    ))}
                  </fieldset>
                )}
                {deviceKind !== undefined && (
                  <p className="helper-text">
                    Connect your {DEVICE_LABELS[deviceKind]} and confirm the
                    message on the device.
                  </p>
                )}
                {needsExternalConsent && (
                  <label className="checkbox-row">
                    <input
                      type="checkbox"
                      checked={externalConsent}
                      onChange={(e) => setExternalConsent(e.target.checked)}
                      aria-label="Approve contacting connect.trezor.io to sign on Trezor"
                    />
                    I understand this connects to connect.trezor.io to reach my
                    Trezor, which leaves my node.
                  </label>
                )}
              </>
            ) : (
              <>
                <label htmlFor="sign-password">Spending password</label>
                <Input
                  id="sign-password"
                  type="password"
                  value={password}
                  onChange={(e) => {
                    setPassword(e.target.value);
                    clearResult();
                  }}
                  aria-label="Spending password"
                  disabled={loading}
                />
              </>
            )}

            {error && (
              <p role="alert" className="error-text">
                {error}
              </p>
            )}

            {isHardware ? (
              <Button
                onClick={handleHardwareSign}
                disabled={
                  loading ||
                  !message.trim() ||
                  deviceKind === undefined ||
                  (needsExternalConsent && !externalConsent)
                }
              >
                {loading
                  ? "Signing…"
                  : deviceKind === undefined
                    ? "Choose a device"
                    : `Sign on ${DEVICE_LABELS[deviceKind]}`}
              </Button>
            ) : (
              <Button onClick={handleSign} disabled={loading || !message.trim() || !password}>
                {loading ? "Signing…" : "Sign message"}
              </Button>
            )}

            {result && (
              <div className="sign-result">
                <p className="field-label">Signature (COSE_Sign1)</p>
                <div className="tx-hash-row">
                  <code className="tx-hash">{result.signature}</code>
                  <CopyButton value={result.signature} ariaLabel="Copy signature" />
                </div>
                <p className="field-label">Key (COSE_Key)</p>
                <div className="tx-hash-row">
                  <code className="tx-hash">{result.key}</code>
                  <CopyButton value={result.key} ariaLabel="Copy COSE key" />
                </div>
              </div>
            )}
          </>
        )}
      </div>
    </Card>
  );
}
