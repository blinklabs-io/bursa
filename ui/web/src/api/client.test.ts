import { apiGet, ApiError } from "./client";

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
