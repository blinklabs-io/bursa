import { loadIdentity, loadOrCreateIdentity, pairingCode, challengeHeaders } from './identity';

// Read current state from storage on load.
async function init() {
  const [{ port = 8090, paired = false }, identity] = await Promise.all([
    chrome.storage.local.get(['port', 'paired']),
    loadIdentity(),
  ]);

  const statusBar = document.getElementById('status-bar')!;
  const pairSection = document.getElementById('pair-section')!;
  const portInput = document.getElementById('port-input') as HTMLInputElement;

  portInput.value = String(port);

  if (identity && paired) {
    statusBar.textContent = 'Connected';
    statusBar.className = 'status connected';
    pairSection.hidden = true;
  } else {
    statusBar.textContent = 'Not paired';
    statusBar.className = 'status disconnected';
  }
}

// The extension origin (chrome-extension://<id> or moz-extension://<uuid>) is the
// identity the backend later sees in the Origin header; Firefox's runtime.id is a
// manifest string that never appears there.

document.getElementById('pair-btn')!.addEventListener('click', async () => {
  const portInput = document.getElementById('port-input') as HTMLInputElement;
  const port = parseInt(portInput.value, 10) || 8090;
  const pairError = document.getElementById('pair-error')!;
  const codeSection = document.getElementById('code-section')!;

  pairError.hidden = true;

  try {
    const identity = await loadOrCreateIdentity();
    const resp = await fetch(`http://127.0.0.1:${port}/connector/pair`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ extension_id: location.origin, public_key: identity.publicKey }),
    });

    if (resp.status !== 202) {
      throw new Error(`Expected 202, got ${resp.status}`);
    }

    await chrome.storage.local.set({ port });
    (document.getElementById('code-input') as HTMLOutputElement).value = await pairingCode(identity.publicKey);
    codeSection.hidden = false;
  } catch (err) {
    pairError.textContent = `Pair failed: ${String(err)}`;
    pairError.hidden = false;
  }
});

// A signed challenge succeeds only after the desktop has bound this key.
document.getElementById('confirm-btn')!.addEventListener('click', async () => {
  const { port = 8090 } = await chrome.storage.local.get(['port']);
  const codeError = document.getElementById('code-error')!;
  codeError.hidden = true;
  try {
    const identity = await loadOrCreateIdentity();
    const resp = await fetch(`http://127.0.0.1:${port}/connector/challenge`, {
      method: 'POST',
      headers: await challengeHeaders(identity),
    });

    if (!resp.ok) {
      throw new Error(`Pairing failed: ${resp.status}`);
    }

    await chrome.storage.local.set({ paired: true });

    // Re-init to show connected state
    await init();
  } catch (err) {
    codeError.textContent = `Confirm failed: ${String(err)}`;
    codeError.hidden = false;
  }
});

init();

export {};
