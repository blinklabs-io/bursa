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
    "Core and networking dependencies have been refreshed to keep builds reproducible and align with newer upstream APIs and fixes.",
    "Build and CI images and workflow actions have been updated to ensure consistent toolchains across environments."
  ],
  "Breaking Changes": [
    "The wallet key-derivation behavior has been updated to match Cardano’s current expectations, which may change derived keys and addresses for the same inputs in some workflows."
  ],
  "New Features": [
    "The command-line interface now supports generating staking and Conway governance certificates so you can create these artifacts directly from the tool."
  ],
  "Security": [
    "Cryptographic and security-related dependencies have been updated to incorporate upstream fixes and reduce exposure to known issues.",
    "Repository security scanning noise has been reduced while keeping relevant checks actionable for maintainers."
  ]
}

```