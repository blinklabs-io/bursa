// Copyright 2026 Blink Labs Software
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//   http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// ConnectorApproval renders a floating overlay whenever the dApp connector has
// pending consent requests. It subscribes to the SSE stream, maintains its own
// pending queue, and calls decide() on Approve / Reject.
//
// The component is mounted globally in app.tsx so it appears on top of whatever
// screen is currently active — the user does not need to navigate away.

import { useState, useEffect, useLayoutEffect, useRef } from "react";
import { Card } from "../components/Card";
import { Button } from "../components/Button";
import { Input } from "../components/Input";
import { ApiError } from "../api/client";
import { subscribePending, decide } from "../api/connector";
import { notifyPending } from "../connectorNotify";
import type { ConnectorRequest } from "../api/types";

const FOCUSABLE_SELECTOR =
  'a[href], button:not([disabled]), textarea:not([disabled]), input:not([disabled]), select:not([disabled]), [tabindex]:not([tabindex="-1"])';

function requestTime(req: ConnectorRequest): number {
  const parsed = Date.parse(req.created);
  return Number.isNaN(parsed) ? Number.MAX_SAFE_INTEGER : parsed;
}

function orderPending(requests: ConnectorRequest[]): ConnectorRequest[] {
  return [...requests].sort(
    (a, b) => requestTime(a) - requestTime(b) || a.id.localeCompare(b.id),
  );
}

// methodSummary returns a human-readable one-line description of what a CIP-30
// method does, so the user understands what they are approving or rejecting.
function methodSummary(req: ConnectorRequest): string {
  switch (req.method) {
    case "enable":
      return `Grant wallet access to ${req.origin}`;
    case "signTx":
      return "Sign a transaction";
    case "signData":
      return "Sign a data payload (CIP-8)";
    case "submitTx":
      return "Submit a transaction";
    case "getPubDRepKey":
    case "cip95.getPubDRepKey":
      return "Reveal DRep public key (CIP-95)";
    case "getRegisteredPubStakeKeys":
    case "cip95.getRegisteredPubStakeKeys":
      return "Reveal registered stake keys (CIP-95)";
    case "getUnregisteredPubStakeKeys":
    case "cip95.getUnregisteredPubStakeKeys":
      return "Reveal unregistered stake keys (CIP-95)";
    default:
      return req.method;
  }
}

// needsPassword returns true for methods that require the spending password.
function needsPassword(method: string): boolean {
  return [
    "signTx",
    "signData",
    "getPubDRepKey",
    "getRegisteredPubStakeKeys",
    "getUnregisteredPubStakeKeys",
    "cip95.getPubDRepKey",
    "cip95.getRegisteredPubStakeKeys",
    "cip95.getUnregisteredPubStakeKeys",
  ].includes(method);
}

function formatParams(params: unknown): string {
  try {
    const formatted = JSON.stringify(params, null, 2);
    return formatted === undefined ? String(params) : formatted;
  } catch {
    return String(params);
  }
}

export function ConnectorApproval() {
  // pending holds the ordered queue of requests awaiting a decision.
  // Decided requests are removed from the head; new ones arrive at the tail.
  const [pending, setPending] = useState<ConnectorRequest[]>([]);
  const [password, setPassword] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  // needsReReview is set when the head request is replaced while the overlay is
  // open, so a click intended for the request the user was reading cannot land
  // on a substituted one. See the swap-detection layout effect below.
  const [needsReReview, setNeedsReReview] = useState(false);

  // Track IDs we have already notified so we don't re-notify on re-renders.
  const notifiedIds = useRef<Set<string>>(new Set());
  const dialogRef = useRef<HTMLDivElement>(null);
  const previouslyFocused = useRef<HTMLElement | null>(null);
  // The request ID the user has actually been shown, used to detect a swap.
  const shownID = useRef<string | null>(null);

  useEffect(() => {
    const unsub = subscribePending((snapshot) => {
      const ordered = orderPending(snapshot);
      setPending(ordered);

      for (const req of ordered) {
        if (!notifiedIds.current.has(req.id)) {
          notifiedIds.current.add(req.id);
          notifyPending(req);
        }
      }
    });
    return unsub;
  }, []);

  // The request at the head of the queue is the one we prompt for.
  const current = pending[0];
  const currentID = current?.id;
  const hasCurrent = current !== undefined;

  // Detect a request substitution: the head request being replaced by a
  // different one while the overlay is already open (an external timeout, a
  // decision made in another tab, or the previous request resolving). When that
  // happens, force a fresh review so an in-flight click cannot be converted into
  // an approval of a request the user never saw. This runs in a layout effect so
  // the gate is set synchronously, before the browser can dispatch a pending
  // click on the newly-rendered button. Password methods are already protected
  // by the password-clear below; this extends the same protection to the
  // no-password methods (enable, submitTx).
  useLayoutEffect(() => {
    if (currentID === undefined) {
      shownID.current = null;
      setNeedsReReview(false);
      return;
    }
    if (shownID.current !== null && shownID.current !== currentID) {
      setNeedsReReview(true);
    }
    shownID.current = currentID;
  }, [currentID]);

  useEffect(() => {
    if (currentID === undefined) return;
    setPassword("");
    setError(null);
    if (!previouslyFocused.current) {
      previouslyFocused.current = document.activeElement as HTMLElement | null;
    }
    const dialog = dialogRef.current;
    const firstFocusable = dialog?.querySelector<HTMLElement>(FOCUSABLE_SELECTOR);
    (firstFocusable ?? dialog)?.focus();
  }, [currentID]);

  useEffect(() => {
    if (current) return;
    previouslyFocused.current?.focus();
    previouslyFocused.current = null;
  }, [current]);

  useEffect(() => {
    if (!hasCurrent) return;
    function handleKeyDown(event: KeyboardEvent) {
      if (event.key !== "Tab" || !dialogRef.current) return;
      const focusable = Array.from(
        dialogRef.current.querySelectorAll<HTMLElement>(FOCUSABLE_SELECTOR),
      );
      if (focusable.length === 0) {
        event.preventDefault();
        dialogRef.current.focus();
        return;
      }
      const first = focusable[0];
      const last = focusable[focusable.length - 1];
      if (event.shiftKey && document.activeElement === first) {
        event.preventDefault();
        last.focus();
      } else if (!event.shiftKey && document.activeElement === last) {
        event.preventDefault();
        first.focus();
      }
    }
    document.addEventListener("keydown", handleKeyDown);
    return () => document.removeEventListener("keydown", handleKeyDown);
  }, [hasCurrent]);

  useEffect(
    () => () => {
      previouslyFocused.current?.focus();
    },
    [],
  );

  if (!current) return null;

  async function handleDecide(approved: boolean) {
    if (!current) return;
    // Refuse to approve a request that was substituted in and not yet
    // re-reviewed, even if a click somehow raced ahead of the disabled state.
    if (approved && needsReReview) return;
    setBusy(true);
    setError(null);
    try {
      const decisionPassword = approved && needsPassword(current.method) ? password : undefined;
      await decide(current.id, approved, decisionPassword);
      // Remove the decided request from the queue.
      setPending((prev) => prev.filter((r) => r.id !== current.id));
      setPassword("");
    } catch (err) {
      if (err instanceof ApiError && err.status === 404) {
        setPending((prev) => prev.filter((r) => r.id !== current.id));
        setPassword("");
        return;
      }
      setError(err instanceof Error ? err.message : "Unknown error");
    } finally {
      setBusy(false);
    }
  }

  const requiresPassword = needsPassword(current.method);
  // signTx/signData carry raw CBOR/hex that Bursa cannot yet decode into a
  // human-readable summary, so consent here is not fully informed. Flag the
  // payload prominently so the raw bytes are not mistaken for a reviewed action.
  const isRawSigning = current.method === "signTx" || current.method === "signData";

  return (
    <div
      className="connector-approval-overlay"
      role="dialog"
      aria-modal="true"
      aria-label="dApp request approval"
      style={{
        position: "fixed",
        inset: 0,
        zIndex: 1000,
        display: "flex",
        alignItems: "center",
        justifyContent: "center",
        background: "rgba(0, 0, 0, 0.55)",
        padding: "1rem",
      }}
    >
      <div
        ref={dialogRef}
        tabIndex={-1}
        style={{ width: "100%", maxWidth: "420px" }}
      >
        <Card title="dApp Request">
          <dl className="stat-list" style={{ marginBottom: "1rem" }}>
            <dt>Origin</dt>
            <dd>
              <code className="mono" style={{ fontSize: "0.85em", wordBreak: "break-all" }}>
                {current.origin}
              </code>
            </dd>
            <dt>Action</dt>
            <dd>{methodSummary(current)}</dd>
            {current.params !== undefined && (
              <>
                <dt>Params</dt>
                <dd>
                  {isRawSigning && (
                    <p
                      role="alert"
                      style={{
                        margin: "0 0 0.5rem",
                        padding: "0.5rem 0.6rem",
                        border: "1px solid var(--warning-border, #b8860b)",
                        background: "var(--warning-bg, rgba(184, 134, 11, 0.12))",
                        color: "var(--warning-text, #8a6d00)",
                        borderRadius: "4px",
                        fontSize: "0.8em",
                      }}
                    >
                      ⚠ Contents unverified — raw {current.method === "signTx" ? "transaction" : "data payload"}.
                      Bursa cannot decode what is shown below, so it may not reflect what you expect
                      (e.g. how much it sends or where). Only approve if you trust {current.origin} and
                      understand exactly what you are signing.
                    </p>
                  )}
                  <pre
                    className="mono"
                    style={{
                      margin: 0,
                      whiteSpace: "pre-wrap",
                      wordBreak: "break-word",
                      fontSize: "0.8em",
                    }}
                  >
                    {formatParams(current.params)}
                  </pre>
                </dd>
              </>
            )}
            {pending.length > 1 && (
              <>
                <dt>Queue</dt>
                <dd>{pending.length} pending</dd>
              </>
            )}
          </dl>

          {requiresPassword && (
            <div style={{ marginBottom: "1rem" }}>
              <label
                htmlFor="connector-password"
                style={{ display: "block", fontSize: "0.85em", marginBottom: "0.3rem" }}
              >
                Spending password
              </label>
              <Input
                id="connector-password"
                type="password"
                placeholder="Enter spending password"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                disabled={busy}
                autoFocus
                style={{ width: "100%" }}
              />
            </div>
          )}

          {error && (
            <p style={{ color: "var(--error, #c00)", fontSize: "0.85em", marginBottom: "0.75rem" }}>
              {error}
            </p>
          )}

          {needsReReview && (
            <div
              role="alert"
              style={{
                marginBottom: "0.75rem",
                padding: "0.5rem 0.6rem",
                border: "1px solid var(--warning-border, #b8860b)",
                background: "var(--warning-bg, rgba(184, 134, 11, 0.12))",
                color: "var(--warning-text, #8a6d00)",
                borderRadius: "4px",
                fontSize: "0.85em",
                display: "flex",
                alignItems: "center",
                justifyContent: "space-between",
                gap: "0.5rem",
              }}
            >
              <span>This request changed. Review the details above before approving.</span>
              <Button variant="ghost" onClick={() => setNeedsReReview(false)}>
                Reviewed
              </Button>
            </div>
          )}

          <div style={{ display: "flex", gap: "0.5rem", justifyContent: "flex-end" }}>
            <Button
              variant="ghost"
              disabled={busy}
              onClick={() => void handleDecide(false)}
            >
              Reject
            </Button>
            <Button
              variant="primary"
              disabled={busy || needsReReview || (requiresPassword && !password)}
              onClick={() => void handleDecide(true)}
            >
              {busy ? "Processing…" : "Approve"}
            </Button>
          </div>
        </Card>
      </div>
    </div>
  );
}
