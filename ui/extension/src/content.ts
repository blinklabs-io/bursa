// Inject the provider script into the page's main world
const script = document.createElement('script');
script.src = chrome.runtime.getURL('injected.js');
script.type = 'module';
(document.head || document.documentElement).appendChild(script);
script.onload = () => script.remove();

// Relay page → background
window.addEventListener('message', (event) => {
  if (event.source !== window) return;
  if (event.data?.source !== 'bursa-cip30') return;
  chrome.runtime.sendMessage(event.data, (response) => {
    // If the service worker is unavailable or did not respond, chrome.runtime.lastError
    // is set and response is undefined. Without this guard the page's CIP-30 call hangs
    // forever, so relay an error reply carrying the ORIGINAL request id.
    if (chrome.runtime.lastError || !response) {
      const targetOrigin = window.location.origin;
      window.postMessage(
        {
          source: 'bursa-cip30-reply',
          id: event.data.id,
          error: {
            code: -2,
            info: chrome.runtime.lastError?.message ?? 'No response from Bursa background',
          },
        },
        targetOrigin,
      );
      return;
    }
    // Relay reply back to the page
    window.postMessage({ source: 'bursa-cip30-reply', ...response }, window.location.origin);
  });
});

export {};
