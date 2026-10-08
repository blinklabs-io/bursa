# Bursa interface design

Bursa is a local-node Cardano wallet. The interface uses charcoal surfaces, self-hosted Manrope, aligned data rows and restrained gold accents.

## Brand

Use lowercase **bursa** as plain gold text. The previous pouch illustration and image wordmark are excluded from the interface. Gold identifies primary actions and selected navigation.

## Layout

Keep forms at a readable width. Import caps at 760px, with explicit spacing between its introduction, field label, textarea and action. Portfolio pairs a compact balance panel with delegation, followed by native assets and NFT media. Mobile uses one column and fixed bottom navigation.

Group accounts beneath their wallet. Show each account label and balance on separate lines. Security labels reflect the wallet type: password protected, hardware secured, watch-only or shared wallet.

## Asset and quote presentation

Token icons use bounded PNG data from the Cardano token registry. Missing or failed logos fall back to colored initials. NFT media requires opt-in and a build with media support; unavailable images have a visible error and retry action. NFT identity and description remain available alongside supported media.

Pool rows expose margin, fixed cost per epoch, pledge, live stake, active stake and saturation. Values come from the existing API; names and tickers are omitted when the node does not provide them.

Swap uses readable amounts when decimals are known and explicitly labels base units otherwise. A changed amount scale clears the input. Quotes show estimated output, price impact, pool fee and route, then offer parameter export. Execution remains on the chosen DEX.

## Verification

The isolated preview uses synthetic data and rejects transaction writes. See [preview instructions, screenshots and research](docs/design/README.md). Live hardware signing and IPFS retrieval require separate verification.
