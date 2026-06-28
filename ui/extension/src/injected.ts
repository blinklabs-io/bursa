// CIP-30 injected window provider for Bursa

// Declare this module as an ES module and augment Window
export {};

declare global {
  interface Window {
    cardano?: Record<string, unknown>;
  }
}

interface Paginate {
  page: number;
  limit: number;
}

interface CIP30Error {
  code: number;
  info: string;
}

interface CIP30API {
  getNetworkId(): Promise<number>;
  getUtxos(amount?: string, paginate?: Paginate): Promise<string[] | null>;
  getBalance(): Promise<string>;
  getCollateral(params?: { amount: string }): Promise<string[]>;
  getUsedAddresses(paginate?: Paginate): Promise<string[]>;
  getUnusedAddresses(): Promise<string[]>;
  getChangeAddress(): Promise<string>;
  getRewardAddresses(): Promise<string[]>;
  signTx(tx: string, partialSign?: boolean): Promise<string>;
  signData(addr: string, payload: string): Promise<{ signature: string; key: string }>;
  submitTx(tx: string): Promise<string>;
  cip95: {
    getPubDRepKey(): Promise<string>;
    getRegisteredPubStakeKeys(): Promise<string[]>;
    getUnregisteredPubStakeKeys(): Promise<string[]>;
  };
}

// Slightly longer than the background's 125s fetch timeout so a real (slow)
// reply is preferred over our local timeout when both are in flight.
const REPLY_TIMEOUT_MS = 130_000;

function sendRequest(method: string, params?: unknown): Promise<unknown> {
  return new Promise((resolve, reject) => {
    // The id is an unguessable uuidv4 nonce. Replies arrive via window.postMessage
    // from the content script, which is the same window the page can also post to,
    // so we cannot use a private cryptographic channel here. The accepted mitigation
    // is: (1) the id is an unguessable nonce, (2) we accept only the FIRST matching
    // reply then immediately tear down the listener, and (3) a timeout guarantees the
    // listener is always removed and the promise always settles. A forged reply would
    // therefore have to guess the per-call nonce before the genuine reply arrives.
    const id = crypto.randomUUID();

    const cleanup = () => {
      window.removeEventListener('message', handler);
      clearTimeout(timer);
    };

    const handler = (event: MessageEvent) => {
      if (event.source !== window) return;
      const data = event.data as { source?: string; id?: string; result?: unknown; error?: unknown };
      if (data?.source !== 'bursa-cip30-reply' || data?.id !== id) return;
      cleanup();
      if (data.error) {
        reject(data.error);
      } else {
        resolve(data.result);
      }
    };

    const timer = setTimeout(() => {
      cleanup();
      reject({ code: -2, info: 'No response from Bursa extension' });
    }, REPLY_TIMEOUT_MS);

    window.addEventListener('message', handler);
    window.postMessage({ source: 'bursa-cip30', id, method, params }, '*');
  });
}

function wrapError(err: unknown): CIP30Error {
  if (
    err !== null &&
    typeof err === 'object' &&
    'code' in err &&
    'info' in err
  ) {
    return err as CIP30Error;
  }
  return { code: -2, info: String(err) };
}

async function safeRequest(method: string, params?: unknown): Promise<unknown> {
  try {
    return await sendRequest(method, params);
  } catch (err) {
    throw wrapError(err);
  }
}

function buildCIP30API(): CIP30API {
  return {
    async getNetworkId(): Promise<number> {
      return safeRequest('getNetworkId') as Promise<number>;
    },
    async getUtxos(amount?: string, paginate?: Paginate): Promise<string[] | null> {
      return safeRequest('getUtxos', { amount, paginate }) as Promise<string[] | null>;
    },
    async getBalance(): Promise<string> {
      return safeRequest('getBalance') as Promise<string>;
    },
    async getCollateral(params?: { amount: string }): Promise<string[]> {
      return safeRequest('getCollateral', params) as Promise<string[]>;
    },
    async getUsedAddresses(paginate?: Paginate): Promise<string[]> {
      return safeRequest('getUsedAddresses', { paginate }) as Promise<string[]>;
    },
    async getUnusedAddresses(): Promise<string[]> {
      return safeRequest('getUnusedAddresses') as Promise<string[]>;
    },
    async getChangeAddress(): Promise<string> {
      return safeRequest('getChangeAddress') as Promise<string>;
    },
    async getRewardAddresses(): Promise<string[]> {
      return safeRequest('getRewardAddresses') as Promise<string[]>;
    },
    async signTx(tx: string, partialSign?: boolean): Promise<string> {
      return safeRequest('signTx', { tx, partialSign }) as Promise<string>;
    },
    async signData(addr: string, payload: string): Promise<{ signature: string; key: string }> {
      return safeRequest('signData', { addr, payload }) as Promise<{ signature: string; key: string }>;
    },
    async submitTx(tx: string): Promise<string> {
      return safeRequest('submitTx', { tx }) as Promise<string>;
    },
    cip95: {
      async getPubDRepKey(): Promise<string> {
        return safeRequest('cip95.getPubDRepKey') as Promise<string>;
      },
      async getRegisteredPubStakeKeys(): Promise<string[]> {
        return safeRequest('cip95.getRegisteredPubStakeKeys') as Promise<string[]>;
      },
      async getUnregisteredPubStakeKeys(): Promise<string[]> {
        return safeRequest('cip95.getUnregisteredPubStakeKeys') as Promise<string[]>;
      },
    },
  };
}

const bursaProvider = {
  apiVersion: '0.1.0',
  name: 'Bursa',
  icon: 'data:image/svg+xml,%3Csvg xmlns%3D%22http%3A%2F%2Fwww.w3.org%2F2000%2Fsvg%22 width%3D%221%22 height%3D%221%22%2F%3E',
  supportedExtensions: [{ cip: 95 }],

  async isEnabled(): Promise<boolean> {
    // Use safeRequest for parity with enable(): rejections become CIP-30
    // {code, info} errors rather than raw values.
    return safeRequest('isEnabled', { origin: window.location.origin }) as Promise<boolean>;
  },

  async enable(): Promise<CIP30API> {
    try {
      await sendRequest('enable', { origin: window.location.origin });
      return buildCIP30API();
    } catch (err) {
      throw wrapError(err);
    }
  },
};

if (!window.cardano) {
  window.cardano = {};
}
window.cardano.bursa = bursaProvider;
