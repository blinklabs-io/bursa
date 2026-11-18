import { loadIdentity, signRequest } from './identity';

/**
 * MV3 service workers can be suspended by the browser at any time.
 * An in-flight fetch will be dropped if the worker is killed mid-request.
 * The dApp should retry on no-response. The 125s AbortController timeout
 * guards against indefinitely-hanging requests.
 */
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  // Derive the true origin from the SENDER (unspoofable — set by the browser
  // from the page's actual URL). Never trust a page-supplied origin field:
  // any content a page posts to window could forge message.origin.
  const senderOrigin =
    sender.origin ?? (sender.url ? new URL(sender.url).origin : undefined);
  handleRequest(message, senderOrigin).then(sendResponse).catch((err) => {
    sendResponse({ id: message.id, error: err });
  });
  return true; // keep channel open for async
});

export async function handleRequest(
  message: {
    id: string;
    method: string;
    params: unknown;
  },
  senderOrigin?: string,
): Promise<{ id: string; result?: unknown; error?: unknown }> {
  const [{ port = 8090, paired = false }, identity] = await Promise.all([
    chrome.storage.local.get(['port', 'paired']),
    loadIdentity(),
  ]);
  const parsedPort = parsePort(port);

  if (!identity || !paired) {
    return {
      id: message.id,
      error: { code: -3, info: 'Not paired with Bursa. Open the extension popup to pair.' },
    };
  }
  if (parsedPort === null) {
    return { id: message.id, error: { code: -2, info: 'Invalid Bursa port configuration' } };
  }

  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), 125_000); // 125s

  try {
    const baseURL = `http://127.0.0.1:${parsedPort}`;
    const requestURL = new URL('/connector/request', baseURL);
    const requestBody = JSON.stringify({
      // Use the browser-verified sender origin; fall back to 'unknown' only
      // if the runtime did not provide one (should not happen for content scripts).
      origin: senderOrigin ?? 'unknown',
      method: message.method,
      params: message.params,
    });
    const challengeResponse = await fetch(new URL('/connector/challenge', baseURL).toString(), {
      method: 'POST',
      signal: controller.signal,
    });
    if (!challengeResponse.ok) {
      return { id: message.id, error: { code: -3, info: 'Not paired with Bursa.' } };
    }
    const { challenge } = (await challengeResponse.json()) as { challenge: string };
    const signature = await signRequest(
      identity,
      challenge,
      'POST',
      '/connector/request',
      requestBody,
    );
    const response = await fetch(requestURL.toString(), {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-Bursa-Challenge': challenge,
        'X-Bursa-Signature': signature,
      },
      body: requestBody,
      signal: controller.signal,
    });

    const body = await response.json();

    if (!response.ok || body.error_code !== undefined) {
      const code = body.error_code ?? -2;
      const info = body.info ?? `HTTP ${response.status}`;
      return { id: message.id, error: { code, info } };
    }

    return { id: message.id, result: body.result };
  } catch (err) {
    if ((err as Error).name === 'AbortError') {
      return { id: message.id, error: { code: -2, info: 'Request timed out after 125s' } };
    }
    return { id: message.id, error: { code: -2, info: String(err) } };
  } finally {
    clearTimeout(timeout);
  }
}

function parsePort(value: unknown): number | null {
  if (typeof value === 'number' && Number.isInteger(value)) {
    return value >= 1 && value <= 65535 ? value : null;
  }
  if (typeof value === 'string' && /^\d+$/.test(value.trim())) {
    const parsed = Number(value.trim());
    return parsed >= 1 && parsed <= 65535 ? parsed : null;
  }
  return null;
}
