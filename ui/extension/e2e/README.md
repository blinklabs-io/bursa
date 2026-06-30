# CIP-30 Extension — Manual E2E Test Harness

This directory contains a static sample dApp (`sample-dapp.html`) for manually
verifying the end-to-end flow of the Bursa browser extension.  There are no
automated tests here — the purpose is to confirm that real browser
extension ↔ Bursa daemon ↔ dApp communication works as expected.

---

## Prerequisites

- Google Chrome (or a Chromium-based browser that supports MV3 extensions)
- Node.js 22 (for building the extension)
- A running Bursa daemon with the CIP-30 connector enabled

---

## Step 1 — Build the extension

```sh
cd ui/extension
npm ci
npm run build
```

The output is written to `ui/extension/dist/`.

---

## Step 2 — Load the extension in Chrome

1. Open Chrome and navigate to `chrome://extensions`.
2. Enable **Developer mode** (toggle in the top-right corner).
3. Click **Load unpacked** and select the `ui/extension/dist/` directory.
4. The **Bursa** extension icon should appear in the toolbar.

---

## Step 3 — Start Bursa with the connector enabled

Start the Bursa daemon.  The connector listens on `localhost` by default and
requires a pairing code to authorise dApps.  Consult the Bursa documentation
for the exact flag/config key.

Example (adjust flags as needed):

```sh
bursa serve --connector
```

---

## Step 4 — Pair the extension with Bursa

1. Click the Bursa extension icon in the Chrome toolbar to open the popup.
2. In the popup, confirm the Bursa port and click **Pair with Bursa**.
3. In the Bursa app, open **Settings → dApp Connector**, reveal the pending
   pairing code, then enter that code in the extension popup.
4. Click **Confirm Pairing** in the popup.
5. The popup should display a "Connected" status.

---

## Step 5 — Open the sample dApp

Open `sample-dapp.html` in Chrome via a local HTTP server:

```sh
python3 -m http.server 8090 --directory ui/extension/e2e
# then navigate to http://localhost:8090/sample-dapp.html
```

You can also open it as a `file://` URL, but only after enabling
**Allow access to file URLs** for the Bursa extension in `chrome://extensions`.

After the page loads you should see:

> `window.cardano.bursa detected (extension loaded)`

If you see an error instead, reload the page — the content script may not have
injected yet on the very first load after installing the extension.

---

## Step 6 — Run the buttons in order

Work through the buttons top-to-bottom:

| Button | Expected behaviour |
|--------|--------------------|
| `isEnabled()` | Returns `false` (not yet approved) |
| `enable()` | Bursa shows an **Approve Connection** prompt; accept it. Returns the CIP-30 API object. |
| `getNetworkId()` | Returns `0` (testnet) or `1` (mainnet) |
| `getBalance()` | Returns a CBOR-hex encoded `Value` |
| `getUsedAddresses()` | Returns an array of bech32 addresses (may be empty) |
| `getUnusedAddresses()` | Returns an array of bech32 addresses |
| `getChangeAddress()` | Returns a single bech32 address |
| `getRewardAddresses()` | Returns an array of reward (stake) addresses |
| `getUtxos()` | Returns an array of CBOR-hex encoded UTxOs (may be null) |
| `getCollateral()` | Returns an array of CBOR-hex UTxOs (may be empty) |
| `signData(addr, payload)` | Bursa shows a **Sign Data** prompt; accept it. Returns `{ signature, key }`. |
| `signTx(dummyTx)` | Bursa shows a **Sign Transaction** prompt; accept it. The dummy tx is invalid so Bursa may return an error after the prompt — that is expected. |
| `submitTx(dummyTx)` | Expected to fail with a Bursa/node error (dummy tx is not valid). Verifies the call reaches the daemon. |
| `cip95.getPubDRepKey()` | Returns a hex-encoded DRep public key |
| `cip95.getRegisteredPubStakeKeys()` | Returns an array of hex-encoded registered stake keys |
| `cip95.getUnregisteredPubStakeKeys()` | Returns an array of hex-encoded unregistered stake keys |

Each result (or error) is printed to the **Output Log** section of the page.

---

## Troubleshooting

- **`window.cardano.bursa` not found** — make sure the extension is loaded and
  the page has been reloaded after loading the extension.
- **`enable()` hangs / no prompt** — check that the Bursa daemon is running and
  the extension is successfully paired (see Step 4).
- **`signTx` / `submitTx` error after prompt** — this is expected for the dummy
  transaction payload.  What matters is that the approval prompt appeared.
- **Stale content script** — after rebuilding and reloading the extension
  (`chrome://extensions` → reload button), also reload the sample-dapp tab.
