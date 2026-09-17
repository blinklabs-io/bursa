# Bursa interface design

Bursa is a local-node Cardano wallet. Its interface prioritizes readable addresses, balances and signing steps, using slate surfaces and gold accents.

## Brand assets

Use the existing Bursa pouch and custom lowercase wordmark from `.github/assets/bursa-illustration.png` and `.github/assets/bursa-logo-with-text-horizontal.png`. Web copies live in `ui/web/public/brand`. The original colors and shapes are preserved; light backing improves wordmark contrast on slate. The invented B emblem and BVRSA text treatments have been removed from the redesigned UI.

## Visual system

- Self-hosted Manrope for interface text; monospace for addresses and hashes.
- Upright surfaces with directional light, subtle edge highlights and offset shadows.
- Gold primary actions, restrained selected navigation, recessed inputs and visible keyboard focus.
- Responsive desktop sidebar and mobile bottom navigation with an accessible wallet drawer.
- Reduced-motion preferences are respected.

## Screens

Portfolio emphasizes the ADA balance and groups native assets in raised slate rows. Asset initials are derived from identity and do not claim official token branding.

Send keeps transaction entry upright and displays a decorative live draft on wide screens. The draft reflects entered values, says Not sent, is hidden from assistive technology and disappears below 1100px.

Receive groups the QR and full address above a full-width address ledger. Mobile rows retain address status, QR, copy and explorer actions. QR codes keep a white quiet zone.

Staking emphasizes withdrawable rewards on a slate surface with a compact adjoining delegation panel. Existing provisional notes, validation and signing flows are preserved.

Activity uses aligned transaction rows that become complete stacked entries on mobile. Settings groups node context and preferences with desktop side tabs and mobile horizontal tabs.

## Product truth

Values come from existing wallet hooks. Capability and signing gates remain in place. The standalone design preview contains synthetic fixtures and rejects transaction/settings writes; it is outside the production bundle. Settings availability depends on platform, node and wallet capabilities.

See [screenshots and preview instructions](docs/design/README.md). Core styling is in `ui/web/src/styles/wallet.css` and `ui/web/src/styles/screens.css`.
