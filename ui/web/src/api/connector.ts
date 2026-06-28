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

// pendingPairings fetches the list of extensions that have called BeginPair but
// have not yet confirmed the code. Each entry has an extension_id and the 6-digit
// code the user must enter in the extension.
export function pendingPairings(): Promise<PendingPairing[]> {
  return apiGet<PendingPairing[]>("/connector/pending-pairings");
}

// subscribePending opens a Server-Sent Events stream at /connector/events and
// calls onRequest for each ConnectorRequest event received. Returns an
// unsubscribe function that closes the stream.
export function subscribePending(
  onRequest: (req: ConnectorRequest) => void,
): () => void {
  const es = new EventSource("/connector/events");

  es.onmessage = (evt) => {
    try {
      const req = JSON.parse(evt.data) as ConnectorRequest;
      onRequest(req);
    } catch {
      // Ignore malformed events (keepalive comments never produce onmessage).
    }
  };

  return () => es.close();
}
