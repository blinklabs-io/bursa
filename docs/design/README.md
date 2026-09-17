# Wallet UI design review

Responsive slate-and-gold redesign of Portfolio, Send, Receive, Activity, Staking and Settings. Screenshots use the isolated sample-data preview; they do not demonstrate a live node or submitted transactions.

## Screenshots

| Screen | Desktop | Mobile |
| --- | --- | --- |
| Portfolio | [Desktop](screenshots/desktop.png) | [Mobile](screenshots/mobile.png) |
| Send | [Desktop](screenshots/send-draft-desktop.png) | [Mobile](screenshots/send-mobile.png) |
| Receive | [Desktop](screenshots/receive-desktop.png) | [Mobile](screenshots/receive-mobile.png) |
| Activity | [Desktop](screenshots/activity-desktop.png) | [Mobile](screenshots/activity-mobile.png) |
| Staking | [Desktop](screenshots/stake-desktop.png) | [Mobile](screenshots/stake-mobile.png) |
| Settings | [Desktop](screenshots/settings-desktop.png) | [Mobile](screenshots/settings-mobile.png) |

[Visual gallery](gallery.html)

## Local preview

From `ui/web`, run `npm ci`, `npm run build`, then `node design-preview.mjs`. Open http://127.0.0.1:4174 and enter any password. The preview serves synthetic wallet data, shows a persistent preview banner and rejects transaction/settings mutations. The preview server is outside the production bundle.

## Design references

- [Eternl published interface](https://cardano.org/apps/eternl/)
- [Stakent](https://dribbble.com/shots/23902428-Stakent-Crypto-Dashboard)
- [Nixtio portfolio dashboard](https://dribbble.com/shots/26395268-Crypto-Dashboard-UI-for-Portfolio-Tracking)
- [Uiflow wallet](https://dribbble.com/shots/27690332-Crypto-Wallet-App-UI-Design)
- [ALIZI wallet](https://dribbble.com/shots/26787301-Crypto-Wallet-Secure-Sleek-Dark-Mode)

References informed hierarchy and surface separation. Bursa retains its palette and existing functionality; reference artwork is not shipped.
