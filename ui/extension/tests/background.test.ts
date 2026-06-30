// @vitest-environment jsdom
import { describe, it, expect, vi, beforeEach } from 'vitest';

// Set up chrome mock BEFORE any module import so side effects see the mock
const storageMock: Record<string, unknown> = {};
const chromeMock = {
  storage: {
    local: {
      get: vi.fn(async (keys: string[]) => {
        const result: Record<string, unknown> = {};
        for (const k of keys) if (k in storageMock) result[k] = storageMock[k];
        return result;
      }),
      set: vi.fn(async (data: Record<string, unknown>) => {
        Object.assign(storageMock, data);
      }),
    },
  },
  runtime: {
    onMessage: { addListener: vi.fn() },
  },
};
(globalThis as unknown as Record<string, unknown>).chrome = chromeMock;

// Dynamic import to ensure chrome mock is installed before module loads
const { handleRequest } = await import('../src/background');

describe('background worker', () => {
  beforeEach(() => {
    // Reset storage and mocks between tests
    for (const key of Object.keys(storageMock)) {
      delete storageMock[key];
    }
    vi.clearAllMocks();
    // Re-install chrome mock after clearAllMocks (clearAllMocks only clears call records, not implementations)
    chromeMock.storage.local.get.mockImplementation(async (keys: string[]) => {
      const result: Record<string, unknown> = {};
      for (const k of keys) if (k in storageMock) result[k] = storageMock[k];
      return result;
    });
    chromeMock.storage.local.set.mockImplementation(async (data: Record<string, unknown>) => {
      Object.assign(storageMock, data);
    });
  });

  it('sends a POST request with correct URL, method, headers, and body shape', async () => {
    storageMock['token'] = 'test-token';

    const fetchMock = vi.fn(async () => ({
      ok: true,
      json: async () => ({ result: 1 }),
    }));
    vi.stubGlobal('fetch', fetchMock);

    // senderOrigin is passed as the second argument (browser-verified); no
    // page-supplied origin field in the message.
    await handleRequest(
      { id: '1', method: 'getNetworkId', params: [] },
      'https://app.example.com',
    );

    expect(fetchMock).toHaveBeenCalledOnce();
    const callArgs = fetchMock.mock.calls[0] as unknown as [string, RequestInit];
    const [url, opts] = callArgs;
    expect(url).toBe('http://127.0.0.1:8090/connector/request');
    expect(opts.method).toBe('POST');
    expect((opts.headers as Record<string, string>)['X-Bursa-Token']).toBe('test-token');
    const body = JSON.parse(opts.body as string);
    expect(body.origin).toBe('https://app.example.com');
    expect(body.method).toBe('getNetworkId');
    expect(body.params).toEqual([]);
  });

  it('resolves with {id, result} on a successful {result} response', async () => {
    storageMock['token'] = 'test-token';

    const fetchMock = vi.fn(async () => ({
      ok: true,
      json: async () => ({ result: 1 }),
    }));
    vi.stubGlobal('fetch', fetchMock);

    const response = await handleRequest(
      { id: '1', method: 'getNetworkId', params: [] },
      'https://app.example.com',
    );

    expect(response).toEqual({ id: '1', result: 1 });
  });

  it('resolves with {id, error} when backend returns {error_code: -3}', async () => {
    storageMock['token'] = 'test-token';

    const fetchMock = vi.fn(async () => ({
      ok: false,
      json: async () => ({ error_code: -3, info: 'User refused' }),
    }));
    vi.stubGlobal('fetch', fetchMock);

    const response = await handleRequest(
      { id: '1', method: 'signTx', params: ['deadbeef'] },
      'https://app.example.com',
    );

    expect(response).toEqual({ id: '1', error: { code: -3, info: 'User refused' } });
  });

  it('returns error {code: -3, info: "Not paired..."} when no token is stored', async () => {
    // storageMock has no token key

    const response = await handleRequest(
      { id: '2', method: 'getNetworkId', params: [] },
      'https://app.example.com',
    );

    expect(response.id).toBe('2');
    expect(response.error).toMatchObject({ code: -3 });
    expect((response.error as { info: string }).info).toMatch(/Not paired/);
  });

  it('uses the custom port from storage when fetching', async () => {
    storageMock['token'] = 'test-token';
    storageMock['port'] = 9999;

    const fetchMock = vi.fn(async () => ({
      ok: true,
      json: async () => ({ result: 42 }),
    }));
    vi.stubGlobal('fetch', fetchMock);

    await handleRequest(
      { id: '3', method: 'getBalance', params: [] },
      'https://app.example.com',
    );

    expect(fetchMock).toHaveBeenCalledOnce();
    const [url] = fetchMock.mock.calls[0] as unknown as [string, RequestInit];
    expect(url).toBe('http://127.0.0.1:9999/connector/request');
  });

  it('rejects invalid stored ports without sending the token', async () => {
    storageMock['token'] = 'test-token';
    storageMock['port'] = '9999.evil';

    const fetchMock = vi.fn();
    vi.stubGlobal('fetch', fetchMock);

    const response = await handleRequest(
      { id: 'bad-port', method: 'getBalance', params: [] },
      'https://app.example.com',
    );

    expect(fetchMock).not.toHaveBeenCalled();
    expect(response).toEqual({
      id: 'bad-port',
      error: { code: -2, info: 'Invalid Bursa port configuration' },
    });
  });

  // Cross-layer contract test: verifies that the origin used in the POST body
  // comes from the browser-verified sender argument, NOT any page-supplied field.
  // This matches how chrome.runtime.onMessage passes sender to the listener in
  // background.ts. A page cannot forge sender.origin — it is set by the browser.
  it('uses sender origin (not page-supplied origin) in the POST body', async () => {
    storageMock['token'] = 'test-token';

    const fetchMock = vi.fn(async () => ({
      ok: true,
      json: async () => ({ result: true }),
    }));
    vi.stubGlobal('fetch', fetchMock);

    // No page-supplied origin in the message; senderOrigin comes from the browser sender.
    await handleRequest(
      { id: '4', method: 'isEnabled', params: [] },
      'https://dapp.example', // senderOrigin — the only trusted origin source
    );

    expect(fetchMock).toHaveBeenCalledOnce();
    const [, opts] = fetchMock.mock.calls[0] as unknown as [string, RequestInit];
    const body = JSON.parse(opts.body as string);
    // Must be the sender origin, never "unknown" or any page-supplied value.
    expect(body.origin).toBe('https://dapp.example');
  });

  // Cross-layer contract test: when the sender provides no origin (edge case),
  // the fallback is "unknown" — never a page-controlled value.
  it('falls back to "unknown" when sender provides no origin', async () => {
    storageMock['token'] = 'test-token';

    const fetchMock = vi.fn(async () => ({
      ok: true,
      json: async () => ({ result: true }),
    }));
    vi.stubGlobal('fetch', fetchMock);

    // senderOrigin undefined simulates a sender with no origin/url.
    await handleRequest(
      { id: '5', method: 'isEnabled', params: [] },
      undefined, // senderOrigin absent
    );

    expect(fetchMock).toHaveBeenCalledOnce();
    const [, opts] = fetchMock.mock.calls[0] as unknown as [string, RequestInit];
    const body = JSON.parse(opts.body as string);
    expect(body.origin).toBe('unknown');
  });
});
