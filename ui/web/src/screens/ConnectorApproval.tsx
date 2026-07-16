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

import { useState, useEffect, useRef } from "react";
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

  // Track IDs we have already notified so we don't re-notify on re-renders.
  const notifiedIds = useRef<Set<string>>(new Set());
  const dialogRef = useRef<HTMLDivElement>(null);
  const previouslyFocused = useRef<HTMLElement | null>(null);

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
              disabled={busy || (requiresPassword && !password)}
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
