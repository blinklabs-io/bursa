// Read current state from storage on load
async function init() {
  const { token, port = 8090 } = await chrome.storage.local.get(['token', 'port']);

  const statusBar = document.getElementById('status-bar')!;
  const pairSection = document.getElementById('pair-section')!;
  const sitesSection = document.getElementById('sites-section')!;
  const portInput = document.getElementById('port-input') as HTMLInputElement;

  portInput.value = String(port);

  if (token) {
    statusBar.textContent = 'Connected';
    statusBar.className = 'status connected';
    pairSection.hidden = true;
    sitesSection.hidden = false;
    // (connected-sites list is populated by the background on future tasks; for now just show section)
  } else {
    statusBar.textContent = 'Not paired';
    statusBar.className = 'status disconnected';
  }
}

// Pair button: step 1 — POST /connector/pair {extension_id}
document.getElementById('pair-btn')!.addEventListener('click', async () => {
  const portInput = document.getElementById('port-input') as HTMLInputElement;
  const port = parseInt(portInput.value, 10) || 8090;
  const pairError = document.getElementById('pair-error')!;
  const codeSection = document.getElementById('code-section')!;

  pairError.hidden = true;

  try {
    const resp = await fetch(`http://127.0.0.1:${port}/connector/pair`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ extension_id: chrome.runtime.id }),
    });

    if (resp.status !== 202) {
      throw new Error(`Expected 202, got ${resp.status}`);
    }

    await chrome.storage.local.set({ port });
    codeSection.hidden = false;
  } catch (err) {
    pairError.textContent = `Pair failed: ${String(err)}`;
    pairError.hidden = false;
  }
});

// Confirm button: step 2 — POST /connector/pair {extension_id, code} → token
document.getElementById('confirm-btn')!.addEventListener('click', async () => {
  const { port = 8090 } = await chrome.storage.local.get(['port']);
  const codeInput = document.getElementById('code-input') as HTMLInputElement;
  const codeError = document.getElementById('code-error')!;
  const code = codeInput.value.trim();

  codeError.hidden = true;

  if (!code) {
    codeError.textContent = 'Enter the pairing code from Bursa Settings.';
    codeError.hidden = false;
    return;
  }

  try {
    const resp = await fetch(`http://127.0.0.1:${port}/connector/pair`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ extension_id: chrome.runtime.id, code }),
    });

    if (!resp.ok) {
      throw new Error(`Pairing failed: ${resp.status}`);
    }

    const { token } = await resp.json();
    await chrome.storage.local.set({ token });

    // Re-init to show connected state
    await init();
  } catch (err) {
    codeError.textContent = `Confirm failed: ${String(err)}`;
    codeError.hidden = false;
  }
});

// Revoke: POST /connector/self-revoke — an extension-facing, token-gated route.
// /connector/grants/revoke is the separate SPA-facing route; it requires a
// strict same-origin browser request and would reject this popup's fetch
// (whose Origin is chrome-extension://<id>, not the API's own host).
async function revokeOrigin(origin: string) {
  const { token, port = 8090 } = await chrome.storage.local.get(['token', 'port']);
  await fetch(`http://127.0.0.1:${port}/connector/self-revoke`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'X-Bursa-Token': token as string,
    },
    body: JSON.stringify({ origin }),
  });
  // Refresh sites list (not implemented here — placeholder)
}

// Export for testing
export { revokeOrigin };

init();
