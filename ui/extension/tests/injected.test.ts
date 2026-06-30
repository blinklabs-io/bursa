import { describe, it, expect, vi, beforeEach } from 'vitest';

// Import the module to trigger the side effect that sets window.cardano.bursa
import '../src/injected';

describe('injected provider', () => {
  beforeEach(() => {
    vi.restoreAllMocks();
  });

  it('sets window.cardano.bursa with name === "Bursa"', () => {
    expect(window.cardano?.bursa).toBeDefined();
    const provider = window.cardano?.bursa as { name: string };
    expect(provider.name).toBe('Bursa');
  });

  it('postMessage shape: getNetworkId posts correct message', async () => {
    const postMessageSpy = vi.spyOn(window, 'postMessage');

    const provider = window.cardano?.bursa as {
      enable(): Promise<{
        getNetworkId(): Promise<number>;
      }>;
    };

    // Call enable() first to get the API (we need to supply a reply for it)
    const enablePromise = provider.enable();

    // Capture the enable message and reply to it
    const enableCall = postMessageSpy.mock.calls[0][0] as {
      source: string;
      id: string;
      method: string;
      params: unknown;
    };
    expect(enableCall.source).toBe('bursa-cip30');
    expect(enableCall.method).toBe('enable');
    expect(enableCall.params).toEqual({ origin: window.location.origin });

    window.dispatchEvent(
      new MessageEvent('message', {
        data: { source: 'bursa-cip30-reply', id: enableCall.id, result: true },
        source: window,
      })
    );

    const api = await enablePromise;

    // Now call getNetworkId
    postMessageSpy.mockClear();
    const networkIdPromise = api.getNetworkId();

    const call = postMessageSpy.mock.calls[0][0] as {
      source: string;
      id: string;
      method: string;
      params: unknown;
    };
    expect(call.source).toBe('bursa-cip30');
    expect(typeof call.id).toBe('string');
    expect(call.method).toBe('getNetworkId');

    // Reply to resolve the promise
    window.dispatchEvent(
      new MessageEvent('message', {
        data: { source: 'bursa-cip30-reply', id: call.id, result: 1 },
        source: window,
      })
    );

    const result = await networkIdPromise;
    expect(result).toBe(1);
  });

  it('reply resolves promise with result', async () => {
    const postMessageSpy = vi.spyOn(window, 'postMessage');

    const provider = window.cardano?.bursa as {
      enable(): Promise<{
        getNetworkId(): Promise<number>;
      }>;
    };

    const enablePromise = provider.enable();
    const enableCall = postMessageSpy.mock.calls[0][0] as { id: string };
    window.dispatchEvent(
      new MessageEvent('message', {
        data: { source: 'bursa-cip30-reply', id: enableCall.id, result: true },
        source: window,
      })
    );
    const api = await enablePromise;

    postMessageSpy.mockClear();
    const networkIdPromise = api.getNetworkId();
    const call = postMessageSpy.mock.calls[0][0] as { id: string };

    window.dispatchEvent(
      new MessageEvent('message', {
        data: { source: 'bursa-cip30-reply', id: call.id, result: 1 },
        source: window,
      })
    );

    await expect(networkIdPromise).resolves.toBe(1);
  });

  it('error reply rejects with CIP-30 error object', async () => {
    const postMessageSpy = vi.spyOn(window, 'postMessage');

    const provider = window.cardano?.bursa as {
      enable(): Promise<{
        getNetworkId(): Promise<number>;
      }>;
    };

    const enablePromise = provider.enable();
    const enableCall = postMessageSpy.mock.calls[0][0] as { id: string };
    window.dispatchEvent(
      new MessageEvent('message', {
        data: { source: 'bursa-cip30-reply', id: enableCall.id, result: true },
        source: window,
      })
    );
    const api = await enablePromise;

    postMessageSpy.mockClear();
    const networkIdPromise = api.getNetworkId();
    const call = postMessageSpy.mock.calls[0][0] as { id: string };

    const cip30Error = { code: -3, info: 'User declined' };
    window.dispatchEvent(
      new MessageEvent('message', {
        data: { source: 'bursa-cip30-reply', id: call.id, error: cip30Error },
        source: window,
      })
    );

    await expect(networkIdPromise).rejects.toEqual(cip30Error);
  });

  it('enable() rejects with CIP-30 error when user declines connection', async () => {
    const postMessageSpy = vi.spyOn(window, 'postMessage');

    const provider = window.cardano?.bursa as {
      enable(): Promise<unknown>;
    };

    const enablePromise = provider.enable();

    // Capture the enable message and reply with an error for its id.
    const enableCall = postMessageSpy.mock.calls[0][0] as {
      source: string;
      id: string;
      method: string;
      params: unknown;
    };
    expect(enableCall.source).toBe('bursa-cip30');
    expect(enableCall.method).toBe('enable');
    expect(enableCall.params).toEqual({ origin: window.location.origin });

    const cip30Error = { code: -3, info: 'User declined connection' };
    window.dispatchEvent(
      new MessageEvent('message', {
        data: { source: 'bursa-cip30-reply', id: enableCall.id, error: cip30Error },
        source: window,
      })
    );

    // wrapError passes through objects that already have code+info unchanged.
    await expect(enablePromise).rejects.toEqual(cip30Error);
  });

  it('isEnabled posts with method: "isEnabled"', async () => {
    const postMessageSpy = vi.spyOn(window, 'postMessage');

    const provider = window.cardano?.bursa as {
      isEnabled(): Promise<boolean>;
    };

    const isEnabledPromise = provider.isEnabled();

    const call = postMessageSpy.mock.calls[0][0] as {
      source: string;
      id: string;
      method: string;
      params: unknown;
    };
    expect(call.source).toBe('bursa-cip30');
    expect(call.method).toBe('isEnabled');
    expect(call.params).toEqual({ origin: window.location.origin });

    // Reply to clean up the listener
    window.dispatchEvent(
      new MessageEvent('message', {
        data: { source: 'bursa-cip30-reply', id: call.id, result: false },
        source: window,
      })
    );

    await expect(isEnabledPromise).resolves.toBe(false);
  });
});
