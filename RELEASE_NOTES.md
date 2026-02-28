---
title: Release Notes
---

# Release Notes

## v0.16.0 - certificates and key derivation

- **Date:** 2026-02-28
- **Version:** v0.16.0

### Summary

This release includes CLI support for generating stake and Conway governance certificates and updates wallet root key derivation to Cardano `CIP-3` Icarus, along with security and dependency updates.

### New Features

- Added CLI support for generating stake and Conway governance certificates.

### Breaking Changes

- Updated wallet root key derivation to follow Cardano `CIP-3` Icarus (PBKDF2), so you must regenerate derived keys and update any stored test vectors.

### Security

- Updated cryptography and secret-management dependencies including `filippo.io/edwards25519` to `v1.2.0`, `github.com/cloudflare/circl` to `v1.6.3`, `github.com/ethereum/go-ethereum` to `v1.17.0`, and `sops` to `v3.12.1`.

### Additional Changes

- Updated Go modules including `gouroboros`, `plutigo`, and `grpc`, bumped GitHub Actions `docker/build-push-action` to `v6.19.2`, and updated the `blinklabs-io/go` Docker base image to `1.25.7-1`.
- Updated lint-suppression annotations for selected security checks and updated `.gitignore` to exclude `.worktrees/`.
