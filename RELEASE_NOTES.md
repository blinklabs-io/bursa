---
title: Release notes
---

# Release notes

## v0.16.0: new features and fixes

- Date: 2026-02-28
- Version: v0.16.0
- Summary: This release includes new features, bug fixes, and additional changes.

### Unprocessed entries

```json
{
  "Additional Changes": [
    "Core and networking dependencies have been refreshed to keep builds reproducible and align with newer upstream APIs and fixes. Specifically, Go modules including gouroboros, plutigo, gRPC-related dependencies, and github.com/ethereum/go-ethereum (to v1.17.0) were updated, with corresponding go.sum checksum updates.",
    "Build and CI images and workflow actions have been updated to ensure consistent toolchains across environments. Specifically, docker/build-push-action was bumped from v6.18.0 to v6.19.2 in GitHub workflows, and the blinklabs-io/go base image was updated from 1.25.6-1 to 1.25.7-1."
  ],
  "Breaking Changes": [
    "The wallet key-derivation behavior has been updated to match Cardano’s current expectations, which may change derived keys and addresses for the same inputs in some workflows. Specifically, BIP32 root derivation was switched to CIP-3 Icarus PBKDF2, hardened-derivation inputs were adjusted, and Cardano-related tests and golden vectors were updated to reflect the new derivation and byte-handling behavior."
  ],
  "New Features": [
    "The command-line interface now supports generating staking and Conway governance certificates so you can create these artifacts directly from the tool. Specifically, new CLI subcommands and underlying certificate-generation logic were added for stake certificates and Conway governance certificates, along with accompanying tests to validate the outputs."
  ],
  "Security": [
    "Cryptographic and security-related dependencies have been updated to incorporate upstream fixes and reduce exposure to known issues. Specifically, dependencies including filippo.io/edwards25519 (to v1.2.0, superseding earlier intermediate bumps) and github.com/cloudflare/circl (to v1.6.3) were upgraded, and sops was updated to v3.12.1 with related Go module refreshes.",
    "Repository security scanning noise has been reduced while keeping relevant checks actionable for maintainers. Specifically, targeted lint-suppression annotations were added for selected security checks, and .worktrees/ was added to Git ignore rules to avoid scanning and indexing transient worktree state."
  ]
}

```