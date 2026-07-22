import { apiDelete, apiGet, ApiError, decodeTx, cosignTx, submitTx } from "./client";

function mockFetch(status: number, body: unknown) {
  globalThis.fetch = vi.fn().mockResolvedValue({
    ok: status >= 200 && status < 300,
    status,
    json: async () => body,
    text: async () => JSON.stringify(body),
  }) as unknown as typeof fetch;
}

test("apiGet returns the parsed body on 200", async () => {
  mockFetch(200, { lovelace: "1500000", assets: [] });
  await expect(apiGet("/wallet/balance")).resolves.toEqual({ lovelace: "1500000", assets: [] });
});

test("apiGet throws ApiError with the server message + status on failure", async () => {
  mockFetch(409, { error: "no wallet set" });
  await expect(apiGet("/wallet/balance")).rejects.toMatchObject({ status: 409, message: "no wallet set" });
  await expect(apiGet("/wallet/balance")).rejects.toBeInstanceOf(ApiError);
});

// --- Retry / backoff tests ---------------------------------------------------

test("a flaky fetch (rejects once with TypeError then resolves) is retried and succeeds", async () => {
  let calls = 0;
  globalThis.fetch = vi.fn().mockImplementation(async () => {
    calls++;
    if (calls === 1) throw new TypeError("Failed to fetch");
    return {
      ok: true,
      status: 200,
      json: async () => ({ lovelace: "1000000", assets: [] }),
    };
  }) as unknown as typeof fetch;

  const result = await apiGet("/wallet/balance");
  expect(result).toEqual({ lovelace: "1000000", assets: [] });
  expect(calls).toBe(2);
});

test("a fetch returning HTTP 500 is NOT retried — one call, error surfaced immediately", async () => {
  let calls = 0;
  globalThis.fetch = vi.fn().mockImplementation(async () => {
    calls++;
    return {
      ok: false,
      status: 500,
      json: async () => ({ error: "internal server error" }),
    };
  }) as unknown as typeof fetch;

  await expect(apiGet("/wallet/balance")).rejects.toMatchObject({ status: 500 });
  expect(calls).toBe(1);
});

test("a persistent network error (TypeError every attempt) exhausts retries and throws", async () => {
  let calls = 0;
  globalThis.fetch = vi.fn().mockImplementation(async () => {
    calls++;
    throw new TypeError("Failed to fetch");
  }) as unknown as typeof fetch;

  await expect(apiGet("/wallet/balance")).rejects.toBeInstanceOf(ApiError);
  // RETRY_ATTEMPTS=3: 1 initial + 2 retries = 3 total calls.
  expect(calls).toBe(3);
});

test("apiDelete is not retried after a network error", async () => {
  let calls = 0;
  globalThis.fetch = vi.fn().mockImplementation(async () => {
    calls++;
    throw new TypeError("Failed to fetch");
  }) as unknown as typeof fetch;

  await expect(apiDelete("/wallet/test-wallet")).rejects.toBeInstanceOf(ApiError);
  expect(calls).toBe(1);
});

// --- Import-transaction (decode / cosign / submit) --------------------------

test("decodeTx posts tx_cbor and returns the parsed TxSummary", async () => {
  mockFetch(200, {
    kind: "vkey",
    outputs: [],
    fee: "170000",
    existing_signatures: [],
    wallet_can_add: [],
    is_complete: false,
  });
  await expect(decodeTx("84a4")).resolves.toEqual({
    kind: "vkey",
    outputs: [],
    fee: "170000",
    existing_signatures: [],
    wallet_can_add: [],
    is_complete: false,
  });
});

test("cosignTx posts tx_cbor + password and returns a CosignResult", async () => {
  mockFetch(200, { tx_cbor: "84beef", added: [{ key_hash: "abc" }] });
  await expect(cosignTx({ tx_cbor: "84a4", password: "pw" })).resolves.toEqual({
    tx_cbor: "84beef",
    added: [{ key_hash: "abc" }],
  });
});

test("submitTx posts tx_cbor and returns a TxResult", async () => {
  mockFetch(200, { tx_hash: "abc123" });
  await expect(submitTx("84beef")).resolves.toEqual({ tx_hash: "abc123" });
});
