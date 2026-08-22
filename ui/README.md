# Bursa Wallet

A full-node Cardano wallet: one binary that embeds and supervises a
[Dingo](https://github.com/blinklabs-io/dingo) node and serves a wallet
interface over loopback.

There is no wallet backend to trust. Balances, transaction history, staking and
governance state are read from a Cardano node running on your own machine, and
your keys never leave it. Nothing is sent anywhere else unless you turn it on.

- [Install](#install)
- [Running it](#running-it)
- [What it does](#what-it-does)
- [Hardware wallets](#hardware-wallets)
- [Security model](#security-model)
- [Configuration](#configuration)
- [dApp connector](#dapp-connector)
- [Building from source](#building-from-source)
- [Troubleshooting](#troubleshooting)

## Install

Download an installer from the
[releases page](https://github.com/blinklabs-io/bursa/releases). Assets are
named `bursa-wallet-<version>-<os>-<arch>.<ext>`:

| Platform | Asset | Notes |
| --- | --- | --- |
| macOS — arm64 (Apple Silicon) | `.pkg` | Signed and notarized; installs `Bursa.app` |
| Windows — amd64, arm64 | `.msi` | Signed |
| Linux — amd64, arm64 | `.tar.gz` | Native window |
| FreeBSD — amd64, arm64 | `.tar.gz` | Headless; serve the interface to a browser |

Every release binary carries a
[build attestation](https://github.com/blinklabs-io/bursa/attestations).

## Running it

Launch `Bursa` from your applications menu, or run the binary:

```bash
bursa-wallet
```

The desktop build opens a native window. The headless build serves the same
interface at <http://127.0.0.1:8090> for you to open in a browser.

**The first launch syncs a node.** By default the wallet bootstraps from a
[Mithril](https://mithril.network) snapshot rather than replaying the chain from
genesis, which turns the initial sync from days into a fraction of that. The
Syncing screen shows progress, and there is an escape hatch to open the vault
read-only while it catches up.

**The default network is `preview`,** not mainnet — set `BURSA_NETWORK=mainnet`
for real funds. See [Configuration](#configuration).

Data lives in `~/.bursa-wallet/<network>/`, logs in that directory under
`logs/bursa-wallet.log`.

## What it does

The interface has nine destinations. Everything else is an action on the screen
it belongs to.

**Wallets and accounts.** The sidebar holds every wallet in your vault, and
under the active one, its BIP44 accounts — separate address sets under a single
recovery phrase, each with its own balance. Switch wallet or account there and
the whole interface follows.

**Portfolio** is home: your balance, native tokens with their on-chain
CIP-25/68 metadata, NFTs, and your delegation at a glance. **Send** and
**Receive** are the two buttons on the balance — receiving shows a QR code, and
sending resolves ADA Handles (`$name`) and offers your address book.

**Activity** is your transaction history, searchable and filterable, with a
detail drawer per transaction and CSV export.

**Stake** covers everything staking in one place: your delegation, reward
history epoch by epoch, and a searchable directory of every stake pool your node
has indexed — with a Delegate action on each row, so choosing a pool and
delegating to it is one flow rather than two screens and a clipboard.

**Swap** gets DEX quotes computed from your own node.

**Multi-sig** builds and tracks native-script transactions across cosigners.
**Import Tx** takes a transaction someone else built — unsigned, partially
signed or complete — decodes it, adds your witness and submits it. **Offline**
carries a transaction to and from an air-gapped signer.

**Operate** is the stake-pool operator toolkit: cold/VRF/KES credentials,
operational certificates, registration, retirement and pool metadata, either
from the wallet's seed or air-gapped.

**Settings** holds the rest — network and sync status, auto-lock, lean storage,
NFT media, hardware security, the dApp connector, your **address book**,
**message signing and verification** (CIP-8), and node **diagnostics** with log
export.

Conway-era governance is a first-class part of the wallet: DRep delegation and
voting build on the CIP-105/CIP-129 key chains the Bursa library implements.

**NFT images** need fetching from IPFS, so they are off by default and only
available in builds compiled with `-tags nftmedia`. When you opt in, retrieval
is direct peer-to-peer through an embedded libp2p client — no third-party
gateway, and nothing touches the IPFS network until you enable it.

## Hardware wallets

Four devices, one signing flow:

| Device | Transport |
| --- | --- |
| Ledger | USB (WebHID) |
| Trezor | USB |
| Keystone | Air-gapped QR |
| SeedSigner | Air-gapped QR |

The air-gapped devices exchange unsigned transactions and witnesses purely as QR
codes, so the signing device never connects to anything.

Device capabilities genuinely differ — not every device can sign every
certificate or governance action. The wallet reflects that rather than papering
over it: unsupported combinations are disabled up front instead of failing at
signing time.

## Security model

**Layered unlock.** One vault password unlocks the instance and grants read-only
access across all your wallets — balances, addresses, history, staking — with no
per-wallet prompt and no seed re-entry on later launches. *Spending*
additionally requires that wallet's own spending password, which decrypts its
seed just long enough to derive a signing key. A seed never exists unencrypted
at rest.

**Encryption.** scrypt + AES-256-GCM throughout. The vault index is encrypted
under a per-vault random Vault Encryption Key, itself wrapped by a key
protector — so re-keying rewraps one small key instead of re-encrypting
everything.

**TPM sealing.** On a machine with a TPM, the vault key can be sealed to it
rather than resting on a password alone.

**Auto-lock** relocks the vault after a period of inactivity.

**Loopback only, with a same-origin guard.** The control surface binds to
`127.0.0.1` and rejects cross-origin requests, so a web page you happen to have
open cannot reach your wallet by DNS rebinding.

**Explicit consent.** Anything leaving your machine — submitting a transaction,
fetching NFT media, requesting a DEX quote — happens because you asked for it,
never as a background default.

## Configuration

Environment variables seed the wallet's behaviour. Settings also exposed in the
interface are persisted after the first run, and the stored value wins from then
on.

| Variable | Default | Meaning |
| --- | --- | --- |
| `BURSA_NETWORK` | `preview` | Cardano network; also selects the data directory. |
| `BURSA_SYNC` | `mithril` | `genesis` replays the chain from the start instead of bootstrapping from a Mithril snapshot. |
| `BURSA_LEAN` | `false` | Seeds the lean-node profile, which prunes historical chain data to keep the on-disk footprint down. |
| `BURSA_CONNECTOR` | `false` | Enables the dApp connector backend. |

The desktop binary serves on `127.0.0.1:8090`.

## dApp connector

`extension/` is the Bursa Connector browser extension: a CIP-30 provider (with
CIP-95 for governance) that bridges web dApps to your local wallet.

It is **off by default**. Start the wallet with `BURSA_CONNECTOR=true`, then
load the extension. Every dApp connection is granted explicitly and every
signing request surfaces in the wallet for approval — the extension holds no
keys.

## Building from source

Requires Go 1.26+ (what `ui/go.mod` declares) and Node 22 (what CI builds with).
From the repository root:

```bash
make wallet
```

That builds the web bundle and then the default pure-Go binary at
`ui/bursa-wallet`, which serves the interface over loopback and cross-compiles
cleanly.

For the native-window build:

```bash
make wallet-webview
```

This one uses CGO and the platform's system webview (WKWebView on macOS,
WebView2 on Windows, webkit2gtk on Linux), so it **cannot be cross-compiled** —
build it on a machine of the target architecture with a C toolchain and the
webview development headers. On Linux the Makefile generates a pkg-config shim
when only `webkit2gtk-4.1` is present, since the upstream webview binding still
asks for `4.0`.

Optional build tag: `nftmedia` compiles in the embedded IPFS client for NFT
images.

Installers:

```bash
make bundle-macos    # ad-hoc-signed .pkg for local testing
make pkg-macos       # signed + notarized .pkg (needs the Apple secrets)
```

Tests:

```bash
cd ui && go test ./...
cd ui/web && npm test
```

## Troubleshooting

**Sync is slow or stuck.** Settings → Diagnostics shows node health, peers and
sync state, and exports the logs. They are also at
`~/.bursa-wallet/<network>/logs/bursa-wallet.log`.

**The window is blank on Linux.** The webview build needs webkit2gtk. Without
it, use the default `make wallet` build and open <http://127.0.0.1:8090> in a
browser.

**Disk usage is too high.** Turn on lean storage in Settings (or start with
`BURSA_LEAN=true` on a first run) to expire historical chain data.

**A hardware device will not connect.** WebHID (Ledger) needs a browser context
permitting HID access, and on Linux usually a udev rule for the device.
Air-gapped devices need no connection at all — if QR scanning fails it is
normally a camera permission.

## License

Apache 2.0, as with the rest of Bursa. See [LICENSE](../LICENSE).
