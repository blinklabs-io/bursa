// @vitest-environment jsdom
import { describe, it, expect, vi, beforeAll, beforeEach } from 'vitest';

// Set up chrome mock BEFORE any module import so side effects see the mock
const sendMessageCallbacks: ((response: unknown) => void)[] = [];
const chromeMock = {
  runtime: {
    sendMessage: vi.fn((_message: unknown, callback: (response: unknown) => void) => {
      sendMessageCallbacks.push(callback);
    }),
  },
};
(globalThis as Record<string, unknown>).chrome = chromeMock;
const jsdomEnv = globalThis as typeof globalThis & {
  jsdom: {
    reconfigure(settings: { url?: string }): void;
  };
};

describe('content script', () => {
  let providerRegistrationFailure: unknown;

  beforeAll(async () => {
    vi.useFakeTimers();
    const postMessageSpy = vi.spyOn(window, 'postMessage').mockImplementation(() => undefined);
    vi.spyOn(console, 'error').mockImplementation(() => undefined);
    // Dynamic import so the module runs AFTER chrome mock is installed
    await import('../src/content');
    await vi.advanceTimersByTimeAsync(2_000);
    providerRegistrationFailure = postMessageSpy.mock.calls
      .map(([message]) => message)
      .find(
        (message) =>
          typeof message === 'object' &&
          message !== null &&
          'source' in message &&
          message.source === 'bursa-cip30-provider-status' &&
          'status' in message &&
          message.status === 'error',
      );
    vi.useRealTimers();
  });

  beforeEach(() => {
    vi.restoreAllMocks();
    vi.clearAllMocks();
    jsdomEnv.jsdom.reconfigure({ url: 'https://dapp.example/' });
    sendMessageCallbacks.length = 0;
  });

  it('reports when the provider does not register in the page main world', () => {
    expect(providerRegistrationFailure).toEqual({
      source: 'bursa-cip30-provider-status',
      status: 'error',
      error: 'Bursa provider failed to register in the page main world',
    });
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

  it('relays the background response back to the page via exact-origin postMessage', () => {
    const postMessageSpy = vi.spyOn(window, 'postMessage').mockImplementation(() => undefined);

    const msg = { source: 'bursa-cip30', id: '1', method: 'getNetworkId' };
    window.dispatchEvent(
      new MessageEvent('message', { data: msg, source: window })
    );

    // Simulate background calling the callback
    sendMessageCallbacks[0]({ id: '1', result: 1 });

    expect(postMessageSpy).toHaveBeenCalledWith(
      { source: 'bursa-cip30-reply', id: '1', result: 1 },
      'https://dapp.example'
    );
  });

  it('relays file URL requests and replies with a wildcard target origin', () => {
    const postMessageSpy = vi.spyOn(window, 'postMessage').mockImplementation(() => undefined);
    jsdomEnv.jsdom.reconfigure({ url: 'file:///tmp/sample-dapp.html' });

    const msg = { source: 'bursa-cip30', id: '1', method: 'getNetworkId' };
    window.dispatchEvent(
      new MessageEvent('message', { data: msg, source: window, origin: 'null' })
    );

    expect(chromeMock.runtime.sendMessage).toHaveBeenCalledWith(
      msg,
      expect.any(Function)
    );

    sendMessageCallbacks[0]({ id: '1', result: 1 });
    expect(postMessageSpy).toHaveBeenCalledWith(
      { source: 'bursa-cip30-reply', id: '1', result: 1 },
      '*'
    );
  });

  it('pins async replies to the origin captured when the request was received', () => {
    const postMessageSpy = vi.spyOn(window, 'postMessage').mockImplementation(() => undefined);
    jsdomEnv.jsdom.reconfigure({ url: 'https://first.example/request' });

    const msg = { source: 'bursa-cip30', id: '1', method: 'getNetworkId' };
    window.dispatchEvent(
      new MessageEvent('message', { data: msg, source: window })
    );

    jsdomEnv.jsdom.reconfigure({ url: 'https://later.example/navigation' });
    sendMessageCallbacks[0]({ id: '1', result: 1 });

    expect(postMessageSpy).toHaveBeenCalledWith(
      { source: 'bursa-cip30-reply', id: '1', result: 1 },
      'https://first.example'
    );
  });

  it('relays background failures to the same exact origin', () => {
    const postMessageSpy = vi.spyOn(window, 'postMessage').mockImplementation(() => undefined);

    const msg = { source: 'bursa-cip30', id: '1', method: 'getNetworkId' };
    window.dispatchEvent(
      new MessageEvent('message', { data: msg, source: window })
    );

    sendMessageCallbacks[0](undefined);

    expect(postMessageSpy).toHaveBeenCalledWith(
      {
        source: 'bursa-cip30-reply',
        id: '1',
        error: {
          code: -2,
          info: 'No response from Bursa background',
        },
      },
      'https://dapp.example'
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
