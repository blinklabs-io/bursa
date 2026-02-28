---
title: Release notes
---

# Release notes

## v0.16.0: certificate generation and key derivation

- Date: 2026-02-28
- Version: v0.16.0
- Summary: This release introduces CLI support for certificate generation, updates wallet key derivation behavior, and refreshes build and security dependencies.

### New Features

- Added CLI support for generating staking certificates and Conway governance certificates.

### Breaking Changes

- Updated wallet key derivation to match Cardano expectations, which may change derived keys and addresses; regenerate keys and update any stored address fixtures or golden vectors.

### Security

- Updated cryptography and security dependencies to incorporate upstream fixes, including `filippo.io/edwards25519`, `github.com/cloudflare/circl`, and `sops`.
- Updated repository scanning configuration to reduce noise, including targeted lint suppressions and ignoring `.worktrees/`.

### Additional Changes

- Updated core and networking dependencies, including `gouroboros`, `plutigo`, gRPC modules, and `github.com/ethereum/go-ethereum`.
- Updated build and CI tooling, including `docker/build-push-action` and the `blinklabs-io/go` base image.