# Bursa interface design

Bursa is a local-node Cardano wallet. The interface uses warm ink surfaces, self-hosted Geist, aligned data rows and muted brass accents.

## Brand

Use lowercase **bursa** as plain gold text. The previous pouch illustration and image wordmark are excluded from the interface. Gold identifies primary actions and selected navigation.

The transfer card uses satin gold with a soft edge and recessed lettering. Its finish is CSS, so amounts and addresses remain live text. The mobile amount panel shares the finish. Keep other surfaces solid, with quiet dividers; gold fills identify primary actions and the transfer draft.

Use Geist for the interface and a system monospace for addresses and hashes. Labels use 13px, explanatory text 14px and compact metadata at least 12px. Mobile inputs use 16px. Financial amounts use tabular numerals. Tune the wordmark independently at weight 700 with slight negative tracking.

## Layout

Keep forms at a readable width. Import caps at 760px, with explicit spacing between its introduction, field label, textarea and action. Portfolio gives the balance and its actions an open area beside delegation, followed by native assets and NFT media. The Send editor is unboxed beside the transfer draft. Activity and Receive use continuous rows separated by dividers. Mobile uses one column and fixed bottom navigation.

Use the shared spacing tokens: 8px from a field label to its control, 16px between fields, and 24px between sections. Cards use 24px padding on desktop and 20px on mobile; unboxed ledgers use zero padding. Page gutters are 40px on desktop, 24px on tablet and 16px on mobile. Headers and screen containers share the 1180px content limit. Flat forms use child margins; grouped forms use gaps, with one owner for each interval.

Vault setup stays in one centered column. Recovery words use two columns on small phones so complete words fit. Settings tools and staking panels retain explicit separation at every breakpoint.

Group accounts beneath their wallet. Show each account label and balance on separate lines. Security labels reflect the wallet type: password protected, hardware secured, watch-only or shared wallet.

## Asset and quote presentation

Token icons use bounded PNG data from the Cardano token registry. Missing or failed logos fall back to colored initials. NFT media requires opt-in and a build with media support; unavailable images have a visible error and retry action. NFT identity and description remain available alongside supported media.

Pool rows expose margin, fixed cost per epoch, pledge, live stake, active stake and saturation. Values come from the existing API; names and tickers are omitted when the node does not provide them.

Swap uses readable amounts when decimals are known and explicitly labels base units otherwise. A changed amount scale clears the input. Quotes show estimated output, price impact, pool fee and route, then offer parameter export. Execution remains on the chosen DEX.

## Verification

The isolated preview uses synthetic data and rejects transaction writes. See [preview instructions, screenshots and research](docs/design/README.md). Live hardware signing and IPFS retrieval require separate verification.
