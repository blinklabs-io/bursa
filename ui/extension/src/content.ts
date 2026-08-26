function normalizeExactOrigin(origin: string): string | null {
  if (!origin || origin === 'null') {
    return null;
  }
  try {
    const parsedOrigin = new URL(origin).origin;
    return parsedOrigin === 'null' ? null : parsedOrigin;
  } catch {
    return null;
  }
}

const PROVIDER_STATUS_SOURCE = 'bursa-cip30-provider-status';
const PROVIDER_REGISTRATION_TIMEOUT_MS = 1_000;

function pageTargetOrigin(): string | null {
  if (window.location.protocol === 'file:' || window.location.origin === 'null') {
    return '*';
  }
  return normalizeExactOrigin(window.location.origin);
}

function monitorProviderRegistration(): void {
  const handleProviderStatus = (event: MessageEvent) => {
    if (event.source !== window) return;
    if (event.data?.source !== PROVIDER_STATUS_SOURCE) return;
    if (event.data?.status !== 'ready') return;

    clearTimeout(timeout);
    window.removeEventListener('message', handleProviderStatus);
  };

  const timeout = window.setTimeout(() => {
    window.removeEventListener('message', handleProviderStatus);
    const error = 'Bursa provider failed to register in the page main world';
    console.error(error);
    const targetOrigin = pageTargetOrigin();
    if (!targetOrigin) return;
    window.postMessage(
      {
        source: PROVIDER_STATUS_SOURCE,
        status: 'error',
        error,
      },
      targetOrigin,
    );
  }, PROVIDER_REGISTRATION_TIMEOUT_MS);

  window.addEventListener('message', handleProviderStatus);
}

// The manifest runs this isolated-world relay before the MAIN-world provider.
// The ready handshake makes a missing or failed provider injection observable.
monitorProviderRegistration();

// Relay page → background
window.addEventListener('message', (event) => {
  if (event.source !== window) return;
  if (event.data?.source !== 'bursa-cip30') return;
  const pageHasOpaqueOrigin =
    window.location.protocol === 'file:' || window.location.origin === 'null';
  // Opaque origins cannot be expressed as a postMessage target origin. The
  // wildcard is required for file:// pages; replies still target this same window.
  const replyTargetOrigin = pageHasOpaqueOrigin
    ? '*'
    : normalizeExactOrigin(window.location.origin) ?? normalizeExactOrigin(event.origin);
  if (!replyTargetOrigin) return;

  chrome.runtime.sendMessage(event.data, (response) => {
    // If the service worker is unavailable or did not respond, chrome.runtime.lastError
    // is set and response is undefined. Without this guard the page's CIP-30 call hangs
    // forever, so relay an error reply carrying the ORIGINAL request id.
    if (chrome.runtime.lastError || !response) {
      window.postMessage(
        {
          source: 'bursa-cip30-reply',
          id: event.data.id,
          error: {
            code: -2,
            info: chrome.runtime.lastError?.message ?? 'No response from Bursa background',
          },
        },
        replyTargetOrigin,
      );
      return;
    }
    // Relay reply back to the page
    window.postMessage({ source: 'bursa-cip30-reply', ...response }, replyTargetOrigin);
  });
});

export {};
