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

import {
  getConnectorState,
  revokeGrant,
  decide,
  unpair,
  pendingPairings,
  subscribePending,
} from "./connector";
import type { ConnectorRequest, ConnectorState, PendingPairing } from "./types";

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function mockFetch(status: number, body: unknown) {
  globalThis.fetch = vi.fn().mockResolvedValue({
    ok: status >= 200 && status < 300,
    status,
    json: async () => body,
    text: async () => JSON.stringify(body),
  }) as unknown as typeof fetch;
}

// ---------------------------------------------------------------------------
// getConnectorState
// ---------------------------------------------------------------------------

test("getConnectorState returns parsed ConnectorState", async () => {
  const state: ConnectorState = {
    paired: true,
    extension_id: "chrome-extension://abc",
    origins: ["https://app.sundae.fi"],
  };
  mockFetch(200, state);
  const result = await getConnectorState();
  expect(result).toEqual(state);
  expect(globalThis.fetch).toHaveBeenCalledWith(
    "/connector/grants",
    expect.objectContaining({ method: "GET" }),
  );
});

// ---------------------------------------------------------------------------
// revokeGrant
// ---------------------------------------------------------------------------

test("revokeGrant POSTs to /connector/grants/revoke with the given origin", async () => {
  mockFetch(200, { ok: true });
  await revokeGrant("https://app.sundae.fi");
  expect(globalThis.fetch).toHaveBeenCalledWith(
    "/connector/grants/revoke",
    expect.objectContaining({
      method: "POST",
      body: JSON.stringify({ origin: "https://app.sundae.fi" }),
    }),
  );
});

// ---------------------------------------------------------------------------
// decide
// ---------------------------------------------------------------------------

test("decide POSTs approved=true with password", async () => {
  mockFetch(200, { ok: true });
  await decide("req-1", true, "s3cr3t");
  expect(globalThis.fetch).toHaveBeenCalledWith(
    "/connector/decide",
    expect.objectContaining({
      method: "POST",
      body: JSON.stringify({ id: "req-1", approved: true, password: "s3cr3t" }),
    }),
  );
});

test("decide POSTs approved=false with empty password when omitted", async () => {
  mockFetch(200, { ok: true });
  await decide("req-2", false);
  expect(globalThis.fetch).toHaveBeenCalledWith(
    "/connector/decide",
    expect.objectContaining({
      method: "POST",
      body: JSON.stringify({ id: "req-2", approved: false, password: "" }),
    }),
  );
});

// ---------------------------------------------------------------------------
// unpair
// ---------------------------------------------------------------------------

test("unpair POSTs to /connector/unpair", async () => {
  mockFetch(200, { ok: true });
  await unpair();
  expect(globalThis.fetch).toHaveBeenCalledWith(
    "/connector/unpair",
    expect.objectContaining({ method: "POST" }),
  );
});

// ---------------------------------------------------------------------------
// pendingPairings
// ---------------------------------------------------------------------------

test("pendingPairings returns an array of PendingPairing", async () => {
  const pairings: PendingPairing[] = [
    { extension_id: "chrome-extension://xyz", code: "123456" },
  ];
  mockFetch(200, pairings);
  const result = await pendingPairings();
  expect(result).toEqual(pairings);
  expect(globalThis.fetch).toHaveBeenCalledWith(
    "/connector/pending-pairings",
    expect.objectContaining({ method: "GET" }),
  );
});

// ---------------------------------------------------------------------------
// subscribePending (EventSource-based)
// ---------------------------------------------------------------------------

class FakeEventSource {
  static instances: FakeEventSource[] = [];
  url: string;
  onmessage: ((evt: { data: string }) => void) | null = null;
  closed = false;

  constructor(url: string) {
    this.url = url;
    FakeEventSource.instances.push(this);
  }

  // Simulate a message event.
  emit(data: string) {
    this.onmessage?.({ data });
  }

  close() {
    this.closed = true;
  }
}

// Capture the real EventSource so we can restore it after these tests and avoid
// leaking the fake into other test files.
const realEventSource = globalThis.EventSource;

beforeEach(() => {
  FakeEventSource.instances = [];
  // Replace global EventSource with our fake.
  globalThis.EventSource = FakeEventSource as unknown as typeof EventSource;
});

afterEach(() => {
  vi.restoreAllMocks();
  globalThis.EventSource = realEventSource;
});

test("subscribePending opens an EventSource at /connector/events", () => {
  const unsub = subscribePending(() => {});
  expect(FakeEventSource.instances).toHaveLength(1);
  expect(FakeEventSource.instances[0].url).toBe("/connector/events");
  unsub();
});

test("subscribePending calls onRequest with parsed ConnectorRequest for each message", () => {
  const received: ConnectorRequest[] = [];
  subscribePending((req) => received.push(req));

  const req: ConnectorRequest = {
    id: "r1",
    origin: "https://app.minswap.org",
    method: "signTx",
    created: "2026-06-27T00:00:00Z",
  };

  FakeEventSource.instances[0].emit(JSON.stringify(req));

  expect(received).toHaveLength(1);
  expect(received[0]).toEqual(req);
});

test("subscribePending closes the EventSource when unsubscribed", () => {
  const unsub = subscribePending(() => {});
  const es = FakeEventSource.instances[0];
  expect(es.closed).toBe(false);
  unsub();
  expect(es.closed).toBe(true);
});

test("subscribePending silently ignores malformed data", () => {
  const received: ConnectorRequest[] = [];
  expect(() => {
    subscribePending((req) => received.push(req));
    FakeEventSource.instances[0].emit("not-valid-json{{{");
  }).not.toThrow();
  expect(received).toHaveLength(0);
});
