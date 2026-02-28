---
title: Release Notes
---

# Release Notes

## v0.16.0

- **Date:** 2026-02-28
- **Version:** v0.16.0

### Summary

This release includes the changes described in the sections below.

### Generated notes (source)

```json
{
  "Additional Changes": [
    "Project dependencies and build tooling were refreshed to keep the build and CI environment current. This updates Go modules including gouroboros, plutigo, gRPC and related packages, bumps the GitHub workflow docker/build-push-action to v6.19.2, and updates the blinklabs-io/go Docker base image to 1.25.7-1.",
    "Repository hygiene and static-analysis configuration were adjusted to better align with development workflows. This adds targeted lint-suppression annotations for specific security checks and updates Git ignore rules to exclude the .worktrees/ directory."
  ],
  "Breaking Changes": [
    "Wallet root key derivation now follows the Cardano CIP-3 Icarus approach instead of the previous behavior, which can change derived keys and expected test vectors. The BIP32 root derivation has been switched to CIP-3 Icarus PBKDF2, hardened derivation inputs were adjusted, and Cardano-related tests and golden values were updated to match the new derivation outputs."
  ],
  "New Features": [
    "You can now generate stake and Conway governance certificates using the command-line interface. This adds new CLI subcommands plus shared certificate-generation core logic, and it includes tests to validate the new stake and Conway governance certificate workflows."
  ],
  "Security": [
    "Cryptography and secret-management components were updated to incorporate upstream security and maintenance fixes. This updates dependencies including filippo.io/edwards25519 (to v1.2.0), github.com/cloudflare/circl (to v1.6.3), github.com/ethereum/go-ethereum (to v1.17.0), and sops (to v3.12.1) along with refreshed related Go modules."
  ]
}

```
