# CIP-30 Extension E2E Tests

`cip30.test.mjs` runs the same scenario in a real Chromium and a real Firefox
against a stand-in Bursa connector backend (`fake-bursa.mjs`). It checks:

- installation of the unpacked Chrome tree and of the Firefox package;
- provider registration at `document_start`, including on a page whose CSP blocks
  all scripts, the CIP-30 `apiVersion` and extension negotiation, and no
  extension storage in the page main world;
- popup pairing and persistence of the pairing across popup reloads;
- `enable()` approval followed by a CIP-30 request, with the backend seeing the
  browser-verified page origin;
- the unpaired error, a rejected approval, no authorization reuse across page
  origins, and an unreachable backend;
- a request served after the background is suspended;
- a prompt `-2` error from a build whose background registers no listener.

```sh
cd ui/extension
npm ci
npm exec playwright install --with-deps --no-shell chromium
npm run test:e2e:chrome    # needs `npm run build` first
npm run test:e2e:firefox   # needs `npm run build` first
npm run test:e2e           # builds, then runs both
```

Set `CHROMIUM_PATH` or `FIREFOX_PATH` to use an existing executable. The Firefox
run needs `geckodriver` and a Firefox of at least the minimum version below. A
snap-packaged `geckodriver` can drive only the snap Firefox; use an upstream
`geckodriver` release with any other Firefox build.

## Supported browsers

| Browser | Minimum version | Reason |
|---------|-----------------|--------|
| Chrome / Chromium | 111 | `content_scripts[].world` |
| Firefox | 140 (Android 142) | `content_scripts[].world` needs 128; `data_collection_permissions` needs 140 |

## Build, lint, and package

```sh
cd ui/extension
npm run build           # dist/chrome, dist/firefox and one zip per browser in dist/
npm run lint:firefox    # web-ext lint --warnings-as-errors on dist/firefox
npm run package         # build, then lint:firefox
```

`manifest.json` is the single manifest source. The build derives the Chrome
manifest (`background.service_worker`) and the Firefox manifest
(`background.scripts`, `browser_specific_settings`) from it. Each package has
`manifest.json` at its root and is byte-identical across repeated builds.
Signing and publication are separate release work.

The static sample dApp (`sample-dapp.html`) remains available for manually
verifying the complete extension ↔ Bursa daemon ↔ dApp flow.

---

## Prerequisites

- Google Chrome 111 or later (or a compatible Chromium-based browser), or Firefox 140 or later
- Node.js 22 (for building the extension)
- A running Bursa daemon with the CIP-30 connector enabled

---

## Step 1 — Build the extension

```sh
cd ui/extension
npm ci
npm run build
```

The Chrome tree is written to `ui/extension/dist/chrome/` and the Firefox tree to
`ui/extension/dist/firefox/`.

---

## Step 2 — Load the extension

### Chrome

1. Open Chrome and navigate to `chrome://extensions`.
2. Enable **Developer mode** (toggle in the top-right corner).
3. Click **Load unpacked** and select the `ui/extension/dist/chrome/` directory.
4. The **Bursa** extension icon should appear in the toolbar.

### Firefox

1. Open `about:debugging#/runtime/this-firefox`.
2. Click **Load Temporary Add-on...** and select
   `ui/extension/dist/firefox/manifest.json` (or the Firefox zip in `dist/`).

## Step 3 — Start Bursa with the connector enabled

Build and start the Bursa wallet with the connector opt-in enabled. The
connector listens on `localhost` and requires a pairing code to authorise
dApps:

```sh
# From the repository root:
make wallet
BURSA_CONNECTOR=1 ./ui/bursa-wallet
```

---

## Step 4 — Pair the extension with Bursa

1. Click the Bursa extension icon in the browser toolbar to open the popup.
2. In the popup, confirm the Bursa port and click **Pair with Bursa**.
3. In the Bursa app, open **Settings → dApp Connector**, reveal the pending
   pairing code, then enter that code in the extension popup.
4. Click **Confirm Pairing** in the popup.
5. The popup should display a "Connected" status.

---

## Step 5 — Open the sample dApp

Open `sample-dapp.html` in Chrome via a local HTTP server:

```sh
python3 -m http.server 8080 --directory ui/extension/e2e
# then navigate to http://localhost:8080/sample-dapp.html
```

Use the HTTP server for this test. Do not open the sample as a `file://` URL:
file pages have an opaque (`null`) origin, and the Bursa connector accepts only
an exact `http://` or `https://` origin with a host and no path, query,
fragment, or user information. Enabling **Allow access to file URLs** lets the
extension inject into the page, but it does not make the page origin valid for
connector authorization.

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
| `enable()` | Requests CIP-95. Bursa shows an **Approve Connection** prompt; accept it. Returns the CIP-30 API object. |
| `getExtensions()` | Returns `[{ "cip": 95 }]` |
| `getNetworkId()` | Returns `0` (testnet) or `1` (mainnet) |
| `getBalance()` | Returns a CBOR-hex encoded `Value` |
| `getUsedAddresses()` | Returns an array of hex-encoded raw address bytes (may be empty) |
| `getUnusedAddresses()` | Returns an array of hex-encoded raw address bytes |
| `getChangeAddress()` | Returns one hex-encoded raw address |
| `getRewardAddresses()` | Returns an array of hex-encoded raw reward (stake) address bytes |
| `getUtxos()` | Returns an array of CBOR-hex encoded UTxOs (may be null) |
| `getCollateral()` | Returns an array of CBOR-hex UTxOs (may be empty) |
| `signData(addr, payload)` | Pass the hex address returned by an address method. Bursa shows a **Sign Data** prompt; accept it. Returns `{ signature, key }`. |
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
