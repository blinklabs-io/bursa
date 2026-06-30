// @vitest-environment jsdom
import { describe, it, expect, vi, beforeAll, beforeEach } from 'vitest';

// Set up chrome mock BEFORE any module import so side effects see the mock
const sendMessageCallbacks: ((response: unknown) => void)[] = [];
const chromeMock = {
  runtime: {
    getURL: vi.fn((path: string) => `chrome-extension://fake-id/${path}`),
    sendMessage: vi.fn((_message: unknown, callback: (response: unknown) => void) => {
      sendMessageCallbacks.push(callback);
    }),
  },
};
(globalThis as Record<string, unknown>).chrome = chromeMock;

describe('content script', () => {
  // Capture injection details before beforeEach clears mocks
  let injectedSrc: string | undefined;

  beforeAll(async () => {
    // Dynamic import so the module runs AFTER chrome mock is installed
    await import('../src/content');
    // Capture which src was passed to getURL at injection time
    if (chromeMock.runtime.getURL.mock.calls.length > 0) {
      injectedSrc = chromeMock.runtime.getURL.mock.calls[0][0] as string;
    }
  });

  beforeEach(() => {
    vi.clearAllMocks();
    sendMessageCallbacks.length = 0;
  });

  it('injects a script tag with injected.js src', () => {
    // In jsdom, onload does not fire so the script tag remains in the DOM
    const scripts = document.querySelectorAll('script');
    const injectedScript = Array.from(scripts).find((s) =>
      s.src.includes('injected.js')
    );
    expect(injectedScript).toBeDefined();
    // Also verify getURL was called with 'injected.js' (captured before mock clear)
    expect(injectedSrc).toBe('injected.js');
  });

  it('relays bursa-cip30 messages to chrome.runtime.sendMessage', () => {
    const msg = { source: 'bursa-cip30', id: '1', method: 'getNetworkId' };
    window.dispatchEvent(
      new MessageEvent('message', { data: msg, source: window })
    );
    expect(chromeMock.runtime.sendMessage).toHaveBeenCalledWith(
      msg,
      expect.any(Function)
    );
  });

  it('relays the background response back to the page via postMessage', () => {
    const postMessageSpy = vi.spyOn(window, 'postMessage');

    const msg = { source: 'bursa-cip30', id: '1', method: 'getNetworkId' };
    window.dispatchEvent(
      new MessageEvent('message', { data: msg, source: window })
    );

    // Simulate background calling the callback
    sendMessageCallbacks[0]({ id: '1', result: 1 });

    expect(postMessageSpy).toHaveBeenCalledWith(
      { source: 'bursa-cip30-reply', id: '1', result: 1 },
      '*'
    );
  });

  it('ignores messages with a different source', () => {
    window.dispatchEvent(
      new MessageEvent('message', {
        data: { source: 'other-extension', id: '2', method: 'getNetworkId' },
        source: window,
      })
    );
    expect(chromeMock.runtime.sendMessage).not.toHaveBeenCalled();
  });
});
