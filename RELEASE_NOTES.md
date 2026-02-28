---
title: Release notes
---

# Release notes

## v0.16.0: certificate generation and key derivation

- Date: 2026-02-28
- Version: v0.16.0
- Summary: This release includes CLI support for certificate generation, updated wallet key derivation behavior, and updated build and security dependencies.

### New Features

- Added CLI support for generating staking certificates and Conway governance certificates, including certificate-generation logic and tests.

### Breaking Changes

- Updated wallet key derivation to use CIP-0003 Icarus PBKDF2 root derivation and adjusted hardened-derivation inputs, which may change derived keys and addresses; regenerate keys and update any stored address fixtures or golden vectors.

### Security

- Updated cryptography and security dependencies to incorporate upstream fixes, including `filippo.io/edwards25519` to `v1.2.0`, `github.com/cloudflare/circl` to `v1.6.3`, and `sops` to `v3.12.1`.
- Updated repository scanning configuration to reduce noise, including targeted lint suppressions and ignoring `.worktrees/`.

### Additional Changes

- Updated core and networking dependencies, including `gouroboros`, `plutigo`, `gRPC`-related modules, and `github.com/ethereum/go-ethereum` to `v1.17.0`.
- Updated build and CI tooling, including `docker/build-push-action` from `v6.18.0` to `v6.19.2` and the `blinklabs-io/go` base image from `1.25.6-1` to `1.25.7-1`.