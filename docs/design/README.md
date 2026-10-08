# Bursa UI review

The wallet uses a plain gold wordmark, compact asset rows, grouped wallets and accounts, token logos, NFT media states, pool metrics and a quote-only swap flow.

## Current screenshots

Captured October 8, 2026 from the production SPA build after rebasing onto `main` at `9909075`. These are the actual React screens with synthetic API data. Desktop captures are 1440 × 900; mobile captures are 390 × 844 at device scale 1. Each image is a viewport capture. Longer screens continue below the viewport.

| Screen | Desktop | Mobile |
| --- | --- | --- |
| Portfolio | [Desktop](screenshots/current/portfolio-desktop.png) | [Mobile](screenshots/current/portfolio-mobile.png) |
| NFTs | [Desktop](screenshots/current/nfts-desktop.png) | [Mobile](screenshots/current/nfts-mobile.png) |
| Send details | [Desktop](screenshots/current/send-desktop.png) | [Mobile](screenshots/current/send-mobile.png) |
| Send review | [Desktop](screenshots/current/send-review-desktop.png) | [Mobile](screenshots/current/send-review-mobile.png) |
| Send result | [Desktop](screenshots/current/send-sent-desktop.png) | [Mobile](screenshots/current/send-sent-mobile.png) |
| Receive | [Desktop](screenshots/current/receive-desktop.png) | [Mobile](screenshots/current/receive-mobile.png) |
| Receive with unknown usage | [Desktop](screenshots/current/receive-unknown-desktop.png) | [Mobile](screenshots/current/receive-unknown-mobile.png) |
| Activity | [Desktop](screenshots/current/activity-desktop.png) | [Mobile](screenshots/current/activity-mobile.png) |
| Staking | [Desktop](screenshots/current/stake-desktop.png) | [Mobile](screenshots/current/stake-mobile.png) |
| Pool directory | [Desktop](screenshots/current/pools-desktop.png) | [Mobile](screenshots/current/pools-mobile.png) |
| Settings | [Desktop](screenshots/current/settings-desktop.png) | [Mobile](screenshots/current/settings-mobile.png) |
| Import transaction | [Desktop](screenshots/current/import-desktop.png) | [Mobile](screenshots/current/import-mobile.png) |
| Swap quote | [Desktop](screenshots/current/swap-desktop.png) | [Mobile](screenshots/current/swap-mobile.png) |
| Create vault | [Desktop](screenshots/current/vault-create-desktop.png) | [Mobile](screenshots/current/vault-create-mobile.png) |
| Add first wallet | [Desktop](screenshots/current/add-wallet-desktop.png) | [Mobile](screenshots/current/add-wallet-mobile.png) |
| Recovery phrase layout | [Desktop](screenshots/current/recovery-phrase-desktop.png) | [Mobile](screenshots/current/recovery-phrase-mobile.png) |
| Wallet setup | [Desktop](screenshots/current/wallet-confirm-desktop.png) | [Mobile](screenshots/current/wallet-confirm-mobile.png) |
| Wallet/account drawer | Portfolio sidebar | [Mobile](screenshots/current/accounts-mobile.png) |
| Swap quote result after scrolling | Swap quote above | [Mobile](screenshots/current/swap-quote-mobile.png) |

[Visual gallery](gallery.html). The `screenshots/current/` directory is the current evidence set; earlier captures outside it are historical.

The recovery-phrase screen contains the invalid placeholder word `preview` in every position. It contains no wallet key material. Send review/result captures use browser-intercepted synthetic responses to exercise the real components; no transaction is built, signed or submitted by the preview server.

## Local preview

From `ui/web`, run `npm ci`, `npm run build`, then `node design-preview.mjs`. Open http://127.0.0.1:4174 and enter any demo password.

The preview has two wallets, separate accounts, sample tokens, NFT photography, pool data and synthetic quotes. Wallet/account selection and media preference changes are held in memory. Transaction and persistent-settings writes return 403. It uses no real wallets, keys or node connections; the script and fixtures are outside the production bundle.

Additional states run in separate preview processes:

```sh
BURSA_PREVIEW_PORT=4176 BURSA_PREVIEW_SCENARIO=vault-create node design-preview.mjs
BURSA_PREVIEW_PORT=4177 BURSA_PREVIEW_SCENARIO=receive-unknown node design-preview.mjs
```

The first-run scenario accepts a demo password of at least 12 characters, then opens the real Add Wallet and recovery-phrase screens. It creates no vault and refuses the final wallet write. The unknown-usage scenario exercises the Receive safeguard for older backends.

## Research and fixtures

- [Trezor Suite accounts](https://trezor.io/guides/trezor-suite/manage-accounts-in-trezor-suite): wallet/account grouping and clear context.
- [Trezor Suite overview](https://trezor.io/guides/trezor-suite/getting-to-know-trezor-suite): compact balances and primary actions.
- [Lace account management](https://www.lace.io/blog/lace-1-10-0-release): separate accounts and wallets.
- [Lace staking](https://www.lace.io/blog/stake-your-ada-across-multiple-pools-with-lace-s-new-multi-delegation-feature-beta): readable delegation and pool information.
- MIN and SNEK logos: [Cardano token registry](https://github.com/cardano-foundation/cardano-token-registry). Preview policy IDs are synthetic and the branding illustrates metadata rendering.
- `fixtures/dunes.jpg`: [Peter Thomas on Unsplash](https://unsplash.com/photos/a-group-of-sand-dunes-in-the-desert-jIU025fNx5g).
- `fixtures/coast.jpg`: [Unsplash source photograph](https://images.unsplash.com/photo-1475924156734-496f6cac6ec1). Both photographs are sample artwork, not actual NFTs; see the [Unsplash license](https://unsplash.com/license).

## Validation

- `npm ci`, lint (zero errors, one existing unused-disable warning), type-check and production build passed.
- 1,029 tests across 73 files passed, including preview URL/write guards, Send progress, visible copy feedback and mobile navigation behavior. Existing jsdom navigation diagnostics appear during the suite; all tests pass.
- UI Go vet/tests and `make wallet-binary` passed.
- Browser captures cover 1440px desktop and 390px mobile with no horizontal overflow or page errors. A separate 320px check covers Portfolio, Send, Receive, Activity, Staking, Settings, Pools, Import, Swap and vault creation.
- Receive with unknown usage has no hero card, zero outer padding, a transparent background and no shadow at both screenshot sizes.

Live IPFS retrieval, hardware signing, native webviews and physical devices were not exercised. NFT media requires the `nftmedia` build capability. Swap execution stays with the chosen DEX.
