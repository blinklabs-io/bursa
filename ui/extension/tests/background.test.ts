// @vitest-environment jsdom
import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';

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

type RelayedMessage = { id: string; method: string; params: unknown; origin?: string };
type MessageSenderLike = { origin?: string; url?: string };
type MessageListener = (
  message: RelayedMessage,
  sender: MessageSenderLike,
  sendResponse: (response: unknown) => void,
) => boolean;

// The module registers its onMessage listener as an import side effect, so the
// mock's recorded call is the only handle on it — and it is the production
// registration, not a test-only export. Capture it before any beforeEach clears
// the call record.
const registeredListener = chromeMock.runtime.onMessage.addListener.mock.calls[0]?.[0] as
  | MessageListener
  | undefined;

// Drive the listener the way chrome.runtime does: message, sender, sendResponse.
function invokeListener(
  message: RelayedMessage,
  sender: MessageSenderLike,
): { kept: boolean; response: Promise<unknown> } {
  if (!registeredListener) throw new Error('background.ts registered no onMessage listener');
  let settle!: (value: unknown) => void;
  const response = new Promise<unknown>((resolve) => {
    settle = resolve;
  });
  const kept = registeredListener(message, sender, settle);
  return { kept, response };
}

function okFetch(result: unknown) {
  return vi.fn(async () => ({ ok: true, json: async () => ({ result }) }));
}

function postedBody(fetchMock: ReturnType<typeof okFetch>): Record<string, unknown> {
  const [, opts] = fetchMock.mock.calls[0] as unknown as [string, RequestInit];
  return JSON.parse(opts.body as string);
}

describe('background worker', () => {
  beforeEach(() => {
    vi.unstubAllGlobals();
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


  it('reports HTTP status when a failing response carries no error_code or info', async () => {
    storageMock['token'] = 'test-token';

    const fetchMock = vi.fn(async () => ({
      ok: false,
      status: 502,
      json: async () => ({}),
    }));
    vi.stubGlobal('fetch', fetchMock);

    const response = await handleRequest(
      { id: 'malformed', method: 'getBalance', params: [] },
      'https://dapp.example',
    );

    expect(response).toEqual({ id: 'malformed', error: { code: -2, info: 'HTTP 502' } });
  });

  // Every test above hands handleRequest an origin that is already trusted, so
  // none of them exercises where that origin comes from. These drive the
  // registered onMessage listener, which is the only place the origin is
  // derived, and the only place a page could try to influence it.
  describe('chrome.runtime.onMessage listener', () => {
    it('registers a listener when the module loads', () => {
      expect(registeredListener).toBeTypeOf('function');
    });

    it('keeps the message channel open for the async reply', () => {
      storageMock['token'] = 'test-token';
      vi.stubGlobal('fetch', okFetch(1));

      const { kept } = invokeListener(
        { id: 'keep-open', method: 'getNetworkId', params: [] },
        { origin: 'https://dapp.example', url: 'https://dapp.example/app' },
      );

      // Returning anything but true closes the port before handleRequest
      // resolves, and every CIP-30 call hangs in the page.
      expect(kept).toBe(true);
    });

    it('ignores a page-supplied origin in the message and uses the sender origin', async () => {
      storageMock['token'] = 'test-token';
      const fetchMock = okFetch(true);
      vi.stubGlobal('fetch', fetchMock);

      // content.ts relays the page's message object verbatim, so a hostile page
      // can put any origin field it likes in it. Only the sender is browser-set.
      const { response } = invokeListener(
        {
          id: 'spoof',
          method: 'signTx',
          params: ['deadbeef'],
          origin: 'https://already-granted.example',
        },
        { origin: 'https://evil.example', url: 'https://evil.example/drain' },
      );
      await response;

      const body = postedBody(fetchMock);
      expect(body.origin).toBe('https://evil.example');
      // The forged value must not reach the connector in any field, not merely
      // be outranked in this one.
      expect(JSON.stringify(body)).not.toContain('already-granted.example');
    });

    it('prefers sender.origin over sender.url when the two disagree', async () => {
      storageMock['token'] = 'test-token';
      const fetchMock = okFetch(true);
      vi.stubGlobal('fetch', fetchMock);

      // Chrome documents sender.origin as the field to make trust decisions on
      // and says it "can vary from the url property (e.g., about:blank)". An
      // about:blank or srcdoc frame inherits its parent's origin, which only
      // sender.origin reports; new URL('about:blank').origin is opaque.
      const { response } = invokeListener(
        { id: 'about-blank', method: 'isEnabled', params: [] },
        { origin: 'https://parent.example', url: 'about:blank' },
      );
      await response;

      expect(postedBody(fetchMock).origin).toBe('https://parent.example');
    });

    it('falls back to the sender URL origin, stripped of path, query and fragment', async () => {
      storageMock['token'] = 'test-token';
      const fetchMock = okFetch(true);
      vi.stubGlobal('fetch', fetchMock);

      const { response } = invokeListener(
        { id: 'url-only', method: 'isEnabled', params: [] },
        { url: 'https://frame.example:8443/deep/path?token=secret#frag' },
      );
      await response;

      const body = postedBody(fetchMock);
      expect(body.origin).toBe('https://frame.example:8443');
      expect(JSON.stringify(body)).not.toContain('secret');
    });

    it('sends "unknown" when the sender carries neither origin nor url', async () => {
      storageMock['token'] = 'test-token';
      const fetchMock = okFetch(true);
      vi.stubGlobal('fetch', fetchMock);

      const { response } = invokeListener(
        { id: 'no-sender-origin', method: 'isEnabled', params: [] },
        {},
      );
      await response;

      // validDAppOrigin rejects a value with no scheme or host, so "unknown"
      // can never be granted by the connector.
      expect(postedBody(fetchMock).origin).toBe('unknown');
    });

    it('replies with the original request id when handleRequest rejects', async () => {
      chromeMock.storage.local.get.mockRejectedValueOnce(new Error('storage unavailable'));

      const { response } = invokeListener(
        { id: 'rejected', method: 'getNetworkId', params: [] },
        { origin: 'https://dapp.example' },
      );

      // Without the id the page cannot match the reply and the call hangs.
      expect(await response).toMatchObject({ id: 'rejected' });
    });
  });

  describe('the 125s request timeout', () => {
    beforeEach(() => {
      vi.useFakeTimers();
    });

    afterEach(() => {
      vi.useRealTimers();
    });

    // Reject with the signal's own reason, which is the DOMException real fetch
    // surfaces, rather than a hand-made error that only looks like one.
    function abortAwareFetch() {
      return vi.fn(
        (_url: string, opts: RequestInit) =>
          new Promise((_resolve, reject) => {
            opts.signal?.addEventListener('abort', () => reject(opts.signal?.reason));
          }),
      );
    }

    it('aborts at 125s and reports a timeout rather than a generic error', async () => {
      storageMock['token'] = 'test-token';
      vi.stubGlobal('fetch', abortAwareFetch());

      const pending = handleRequest(
        { id: 'slow', method: 'signTx', params: ['deadbeef'] },
        'https://dapp.example',
      );
      const stillPending = Symbol('still-pending');
      const settledYet = () => Promise.race([pending, Promise.resolve(stillPending)]);

      await vi.advanceTimersByTimeAsync(124_999);
      expect(await settledYet()).toBe(stillPending);

      await vi.advanceTimersByTimeAsync(1);
      expect(await pending).toEqual({
        id: 'slow',
        error: { code: -2, info: 'Request timed out after 125s' },
      });
    });

    it('reports a non-abort fetch failure as the stringified error', async () => {
      storageMock['token'] = 'test-token';
      vi.stubGlobal(
        'fetch',
        vi.fn(async () => {
          throw new TypeError('Failed to fetch');
        }),
      );

      expect(
        await handleRequest({ id: 'netfail', method: 'isEnabled', params: [] }, 'https://dapp.example'),
      ).toEqual({ id: 'netfail', error: { code: -2, info: 'TypeError: Failed to fetch' } });
    });

    it('clears the abort timer once the request completes', async () => {
      storageMock['token'] = 'test-token';
      vi.stubGlobal('fetch', okFetch(1));

      await handleRequest({ id: 'fast', method: 'getNetworkId', params: [] }, 'https://dapp.example');

      // A leaked 125s timer keeps an MV3 service worker alive after its work is
      // done, and fires abort() on a controller nothing is listening to.
      expect(vi.getTimerCount()).toBe(0);
    });
  });

  describe('stored port parsing', () => {
    it.each([
      ['9999', 'http://127.0.0.1:9999/connector/request'],
      [' 9999 ', 'http://127.0.0.1:9999/connector/request'],
      ['1', 'http://127.0.0.1:1/connector/request'],
      ['65535', 'http://127.0.0.1:65535/connector/request'],
    ])('accepts the numeric-string port %j from storage', async (port, expected) => {
      storageMock['token'] = 'test-token';
      storageMock['port'] = port;
      const fetchMock = okFetch(1);
      vi.stubGlobal('fetch', fetchMock);

      await handleRequest({ id: 'p', method: 'getNetworkId', params: [] }, 'https://dapp.example');

      const [url] = fetchMock.mock.calls[0] as unknown as [string, RequestInit];
      expect(url).toBe(expected);
    });

    it.each([['0'], ['65536'], ['70000'], [0], [65536], [8090.5]])(
      'rejects the out-of-range stored port %j without sending the token',
      async (port) => {
        storageMock['token'] = 'test-token';
        storageMock['port'] = port;
        const fetchMock = vi.fn();
        vi.stubGlobal('fetch', fetchMock);

        const response = await handleRequest(
          { id: 'bad', method: 'getNetworkId', params: [] },
          'https://dapp.example',
        );

        expect(fetchMock).not.toHaveBeenCalled();
        expect(response).toEqual({
          id: 'bad',
          error: { code: -2, info: 'Invalid Bursa port configuration' },
        });
      },
    );
  });
});
