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
    "Project dependencies and build tooling were refreshed to keep the build and CI environment current.",
    "Repository hygiene and static-analysis configuration were adjusted to better align with development workflows."
  ],
  "Breaking Changes": [
    "Wallet root key derivation now follows the Cardano CIP-3 Icarus approach instead of the previous behavior, which can change derived keys and expected test vectors."
  ],
  "New Features": [
    "You can now generate stake and Conway governance certificates using the command-line interface."
  ],
  "Security": [
    "Cryptography and secret-management components were updated to incorporate upstream security and maintenance fixes."
  ]
}

```
