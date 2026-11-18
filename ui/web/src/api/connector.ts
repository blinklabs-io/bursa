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

// connector.ts — SPA-facing API client for the CIP-30 dApp connector.

import { apiGet, apiPost } from "./client";
import type { ConnectorState, ConnectorRequest, PendingPairing } from "./types";

// getConnectorState fetches the current connector status: paired extension,
// granted origins, and paired boolean.
export function getConnectorState(): Promise<ConnectorState> {
  return apiGet<ConnectorState>("/connector/grants");
}

// revokeGrant revokes the grant for the given origin.
export function revokeGrant(origin: string): Promise<void> {
  return apiPost<void>("/connector/grants/revoke", { origin });
}

// decide approves or rejects the pending consent request identified by id.
// password is only required for signing/submission methods.
export function decide(
  id: string,
  approved: boolean,
  password?: string,
): Promise<void> {
  return apiPost<void>("/connector/decide", { id, approved, password: password ?? "" });
}

// unpair disconnects the currently paired extension.
export function unpair(): Promise<void> {
  return apiPost<void>("/connector/unpair");
}

// pendingPairings fetches extensions that have called BeginPair but have not
// yet confirmed. The server returns codes only when a vault password is supplied.
export function pendingPairings(password?: string): Promise<PendingPairing[]> {
  return apiPost<PendingPairing[]>(
    "/connector/pending-pairings",
    password ? { password } : undefined,
  );
}

interface PendingSnapshotEvent {
  type: "snapshot";
  pending: ConnectorRequest[];
}

// subscribePending opens a Server-Sent Events stream at /connector/events and
// replaces the consumer's local state with each authoritative queue snapshot.
// Returns an unsubscribe function that closes the stream.
//
// The optional onError callback surfaces the stream's health so the UI can show
// a "reconnecting" indicator: it is invoked with degraded=true when the browser
// signals a connection error, and degraded=false once the stream (re)opens. The
// callback is optional so existing callers that only care about snapshots keep
// working unchanged.
export function subscribePending(
  onSnapshot: (pending: ConnectorRequest[]) => void,
  onError?: (degraded: boolean) => void,
): () => void {
  let es: EventSource | undefined;
  let stopped = false;
  let degraded = false;
  let retryTimer: ReturnType<typeof setTimeout> | undefined;

  const setDegraded = (next: boolean) => {
    if (degraded === next) return;
    degraded = next;
    onError?.(next);
  };

  const scheduleRetry = () => {
    if (stopped || retryTimer !== undefined) return;
    retryTimer = setTimeout(() => {
      retryTimer = undefined;
      void connect();
    }, 1_000);
  };

  const connect = async () => {
    try {
      const { ticket } = await apiPost<{ ticket: string }>("/session/events-ticket");
      if (stopped) return;

      const stream = new EventSource(`/connector/events?ticket=${encodeURIComponent(ticket)}`);
      es = stream;

      stream.onmessage = (evt) => {
        try {
          const event = JSON.parse(evt.data) as PendingSnapshotEvent;
          if (event.type === "snapshot" && Array.isArray(event.pending)) {
            onSnapshot(event.pending);
          }
        } catch {
          // Ignore malformed events (keepalive comments never produce onmessage).
        }
      };

      stream.onerror = () => {
        if (stopped || es !== stream) return;
        stream.close();
        es = undefined;
        setDegraded(true);
        scheduleRetry();
      };
      stream.onopen = () => {
        if (!stopped && es === stream) setDegraded(false);
      };
    } catch {
      if (!stopped) {
        setDegraded(true);
        scheduleRetry();
      }
    }
  };

  void connect();

  return () => {
    stopped = true;
    if (retryTimer !== undefined) clearTimeout(retryTimer);
    es?.close();
  };
}

export function confirmPairing(extensionID: string, code: string, password: string): Promise<void> {
  return apiPost<void>("/connector/confirm-pair", { extension_id: extensionID, code, password });
}
