import { apiDelete, apiGet, ApiError, decodeTx, cosignTx, submitTx } from "./client";

function mockFetch(status: number, body: unknown) {
  const fn = vi.fn().mockResolvedValue({
    ok: status >= 200 && status < 300,
    status,
    json: async () => body,
    text: async () => JSON.stringify(body),
  });
  globalThis.fetch = fn as unknown as typeof fetch;
  return fn;
}

// lastRequest returns the (url, init) the mocked fetch was called with, so a
// test can assert the endpoint, HTTP method, and serialized body actually sent
// — otherwise a wrong URL/method/payload would still pass, since the mock
// accepts every request.
function lastRequest(fn: ReturnType<typeof vi.fn>): { url: string; method: string; body: unknown } {
  expect(fn).toHaveBeenCalledTimes(1);
  const [url, init] = fn.mock.calls[0] as [string, RequestInit];
  return {
    url,
    method: init.method ?? "GET",
    body: init.body ? JSON.parse(init.body as string) : undefined,
  };
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

test("decodeTx POSTs tx_cbor to /wallet/decode-tx and returns the parsed TxSummary", async () => {
  const fn = mockFetch(200, {
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
  expect(lastRequest(fn)).toEqual({
    url: "/wallet/decode-tx",
    method: "POST",
    body: { tx_cbor: "84a4" },
  });
});

test("cosignTx POSTs tx_cbor + password to /wallet/cosign-tx and returns a CosignResult", async () => {
  const fn = mockFetch(200, { tx_cbor: "84beef", added: [{ key_hash: "abc" }] });
  await expect(cosignTx({ tx_cbor: "84a4", password: "pw" })).resolves.toEqual({
    tx_cbor: "84beef",
    added: [{ key_hash: "abc" }],
  });
  expect(lastRequest(fn)).toEqual({
    url: "/wallet/cosign-tx",
    method: "POST",
    body: { tx_cbor: "84a4", password: "pw" },
  });
});

test("submitTx POSTs tx_cbor to /wallet/submit-tx and returns a TxResult", async () => {
  const fn = mockFetch(200, { tx_hash: "abc123" });
  await expect(submitTx("84beef")).resolves.toEqual({ tx_hash: "abc123" });
  expect(lastRequest(fn)).toEqual({
    url: "/wallet/submit-tx",
    method: "POST",
    body: { tx_cbor: "84beef" },
  });
});
