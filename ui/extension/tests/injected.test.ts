import { describe, it, expect, vi, beforeEach } from 'vitest';

// Import the module to trigger the side effect that sets window.cardano.bursa
import '../src/injected';

const jsdomEnv = globalThis as typeof globalThis & {
  jsdom: {
    reconfigure(settings: { url?: string }): void;
  };
};

interface TestExtension {
  cip: number;
}

interface TestCIP30API {
  getExtensions(): Promise<TestExtension[]>;
  getNetworkId(): Promise<number>;
  getUtxos(amount?: string, paginate?: { page: number; limit: number }): Promise<string[] | null>;
  getBalance(): Promise<string>;
  getCollateral(params?: { amount: string }): Promise<string[] | null>;
  getUsedAddresses(paginate?: { page: number; limit: number }): Promise<string[]>;
  getUnusedAddresses(): Promise<string[]>;
  getChangeAddress(): Promise<string>;
  getRewardAddresses(): Promise<string[]>;
  signTx(tx: string, partialSign?: boolean): Promise<string>;
  signData(addr: string, payload: string): Promise<{ signature: string; key: string }>;
  submitTx(tx: string): Promise<string>;
  cip95?: {
    getPubDRepKey(): Promise<string>;
    getRegisteredPubStakeKeys(): Promise<string[]>;
    getUnregisteredPubStakeKeys(): Promise<string[]>;
  };
}

interface TestProvider {
  apiVersion: string;
  supportedExtensions: TestExtension[];
  enable(options?: { extensions?: TestExtension[] }): Promise<TestCIP30API>;
}

type PostedRequest = {
  id: string;
  method: string;
  params: unknown;
};

async function enableProvider(
  postMessageSpy: ReturnType<typeof vi.spyOn>,
  options?: { extensions?: TestExtension[] },
): Promise<TestCIP30API> {
  const provider = window.cardano?.bursa as TestProvider;
  const enablePromise = provider.enable(options);
  const enableCall = postMessageSpy.mock.calls.at(-1)?.[0] as PostedRequest;
  window.dispatchEvent(
    new MessageEvent('message', {
      data: { source: 'bursa-cip30-reply', id: enableCall.id, result: true },
      source: window,
    }),
  );
  return enablePromise;
}

function replyToLatestRequest(
  postMessageSpy: ReturnType<typeof vi.spyOn>,
  result: unknown,
): PostedRequest {
  const call = postMessageSpy.mock.calls.at(-1)?.[0] as PostedRequest;
  window.dispatchEvent(
    new MessageEvent('message', {
      data: { source: 'bursa-cip30-reply', id: call.id, result },
      source: window,
    }),
  );
  return call;
}

describe('injected provider', () => {
  beforeEach(() => {
    vi.restoreAllMocks();
    jsdomEnv.jsdom.reconfigure({ url: 'https://dapp.example/' });
  });

  it('sets window.cardano.bursa with name === "Bursa"', () => {
    expect(window.cardano?.bursa).toBeDefined();
    const provider = window.cardano?.bursa as { name: string };
    expect(provider.name).toBe('Bursa');
  });

  it('publishes the CIP-30 v1 provider metadata', () => {
    const provider = window.cardano?.bursa as TestProvider;

    expect(provider.apiVersion).toBe('1');
    expect(provider.supportedExtensions).toEqual([{ cip: 95 }]);
  });

  it('negotiates requested extensions and exposes their API surface', async () => {
    const postMessageSpy = vi.spyOn(window, 'postMessage');
    const provider = window.cardano?.bursa as TestProvider;
    const requestedExtensions = [{ cip: 95 }, { cip: 142 }, { cip: 95 }];

    const enablePromise = provider.enable({ extensions: requestedExtensions });
    const enableCall = postMessageSpy.mock.calls[0][0] as {
      id: string;
      method: string;
      params: unknown;
    };
    expect(enableCall.method).toBe('enable');
    expect(enableCall.params).toEqual({ extensions: requestedExtensions });

    window.dispatchEvent(
      new MessageEvent('message', {
        data: { source: 'bursa-cip30-reply', id: enableCall.id, result: true },
        source: window,
      })
    );

    const api = await enablePromise;
    await expect(api.getExtensions()).resolves.toEqual([{ cip: 95 }]);
    expect(api.cip95?.getPubDRepKey).toBeTypeOf('function');

    const returnedExtensions = await api.getExtensions();
    returnedExtensions.push({ cip: 142 });
    await expect(api.getExtensions()).resolves.toEqual([{ cip: 95 }]);
  });

  it('returns the base API when no extensions are requested', async () => {
    const postMessageSpy = vi.spyOn(window, 'postMessage');
    const provider = window.cardano?.bursa as TestProvider;

    const enablePromise = provider.enable();
    const enableCall = postMessageSpy.mock.calls[0][0] as {
      id: string;
      params: unknown;
    };
    expect(enableCall.params).toBeUndefined();

    window.dispatchEvent(
      new MessageEvent('message', {
        data: { source: 'bursa-cip30-reply', id: enableCall.id, result: true },
        source: window,
      })
    );

    const api = await enablePromise;
    await expect(api.getExtensions()).resolves.toEqual([]);
    expect(api.cip95).toBeUndefined();
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
    // enable() deliberately sends no page-controlled origin: the backend
    // authorizes on the browser-verified sender origin.
    expect(enableCall.params).toBeUndefined();

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
    // Requests are posted to our own origin, never '*'.
    expect(postMessageSpy.mock.calls[0][1]).toBe(window.location.origin);

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

  it('uses a wildcard postMessage target for file URLs', async () => {
    jsdomEnv.jsdom.reconfigure({ url: 'file:///tmp/sample-dapp.html' });
    const postMessageSpy = vi.spyOn(window, 'postMessage').mockImplementation(() => undefined);
    const provider = window.cardano?.bursa as {
      isEnabled(): Promise<boolean>;
    };

    const isEnabledPromise = provider.isEnabled();
    const call = postMessageSpy.mock.calls[0][0] as { id: string };

    expect(postMessageSpy.mock.calls[0][1]).toBe('*');

    window.dispatchEvent(
      new MessageEvent('message', {
        data: { source: 'bursa-cip30-reply', id: call.id, result: false },
        source: window,
      })
    );
    await expect(isEnabledPromise).resolves.toBe(false);
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
    // enable() deliberately sends no page-controlled origin: the backend
    // authorizes on the browser-verified sender origin.
    expect(enableCall.params).toBeUndefined();

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
    // isEnabled() sends no page-controlled origin (see enable()).
    expect(call.params).toBeUndefined();

    // Reply to clean up the listener
    window.dispatchEvent(
      new MessageEvent('message', {
        data: { source: 'bursa-cip30-reply', id: call.id, result: false },
        source: window,
      })
    );

    await expect(isEnabledPromise).resolves.toBe(false);
  });

  it('forwards every CIP-30 method with its contract parameters', async () => {
    const postMessageSpy = vi.spyOn(window, 'postMessage');
    const api = await enableProvider(postMessageSpy);
    postMessageSpy.mockClear();

    const cases: Array<{
      name: string;
      invoke: () => Promise<unknown>;
      method: string;
      params: unknown;
      result: unknown;
    }> = [
      {
        name: 'getNetworkId',
        invoke: () => api.getNetworkId(),
        method: 'getNetworkId',
        params: undefined,
        result: 1,
      },
      {
        name: 'getUtxos',
        invoke: () => api.getUtxos('100', { page: 2, limit: 3 }),
        method: 'getUtxos',
        params: { amount: '100', paginate: { page: 2, limit: 3 } },
        result: ['utxo'],
      },
      {
        name: 'getBalance',
        invoke: () => api.getBalance(),
        method: 'getBalance',
        params: undefined,
        result: 'balance-cbor',
      },
      {
        name: 'getCollateral',
        invoke: () => api.getCollateral({ amount: '42' }),
        method: 'getCollateral',
        params: { amount: '42' },
        result: ['collateral'],
      },
      {
        name: 'getUsedAddresses',
        invoke: () => api.getUsedAddresses({ page: 1, limit: 5 }),
        method: 'getUsedAddresses',
        params: { paginate: { page: 1, limit: 5 } },
        result: ['used-address'],
      },
      {
        name: 'getUnusedAddresses',
        invoke: () => api.getUnusedAddresses(),
        method: 'getUnusedAddresses',
        params: undefined,
        result: ['unused-address'],
      },
      {
        name: 'getChangeAddress',
        invoke: () => api.getChangeAddress(),
        method: 'getChangeAddress',
        params: undefined,
        result: 'change-address',
      },
      {
        name: 'getRewardAddresses',
        invoke: () => api.getRewardAddresses(),
        method: 'getRewardAddresses',
        params: undefined,
        result: ['reward-address'],
      },
      {
        name: 'signTx',
        invoke: () => api.signTx('tx-cbor', true),
        method: 'signTx',
        params: { tx: 'tx-cbor', partialSign: true },
        result: 'witness-cbor',
      },
      {
        name: 'signData',
        invoke: () => api.signData('address', 'payload-cbor'),
        method: 'signData',
        params: { addr: 'address', payload: 'payload-cbor' },
        result: { signature: 'signature', key: 'key' },
      },
      {
        name: 'submitTx',
        invoke: () => api.submitTx('tx-cbor'),
        method: 'submitTx',
        params: { tx: 'tx-cbor' },
        result: 'tx-hash',
      },
    ];

    for (const testCase of cases) {
      const resultPromise = testCase.invoke();
      const call = postMessageSpy.mock.calls.at(-1)?.[0] as PostedRequest;
      expect(call, testCase.name).toMatchObject({
        source: 'bursa-cip30',
        method: testCase.method,
      });
      expect(call.params, testCase.name).toEqual(testCase.params);
      replyToLatestRequest(postMessageSpy, testCase.result);
      await expect(resultPromise, testCase.name).resolves.toEqual(testCase.result);
    }
  });

  it('forwards every negotiated CIP-95 method and returns its result', async () => {
    const postMessageSpy = vi.spyOn(window, 'postMessage');
    const api = await enableProvider(postMessageSpy, { extensions: [{ cip: 95 }] });
    postMessageSpy.mockClear();

    const cases: Array<{
      invoke: () => Promise<unknown>;
      method: string;
      result: unknown;
    }> = [
      {
        invoke: () => api.cip95!.getPubDRepKey(),
        method: 'cip95.getPubDRepKey',
        result: 'drep-key',
      },
      {
        invoke: () => api.cip95!.getRegisteredPubStakeKeys(),
        method: 'cip95.getRegisteredPubStakeKeys',
        result: ['registered-key'],
      },
      {
        invoke: () => api.cip95!.getUnregisteredPubStakeKeys(),
        method: 'cip95.getUnregisteredPubStakeKeys',
        result: ['unregistered-key'],
      },
    ];

    for (const testCase of cases) {
      const resultPromise = testCase.invoke();
      const call = postMessageSpy.mock.calls.at(-1)?.[0] as PostedRequest;
      expect(call).toMatchObject({
        source: 'bursa-cip30',
        method: testCase.method,
        params: undefined,
      });
      replyToLatestRequest(postMessageSpy, testCase.result);
      await expect(resultPromise).resolves.toEqual(testCase.result);
    }
  });
});
