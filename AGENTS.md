# Bursa agent guide

## What this repository is

Bursa is a Cardano wallet and signing service. It contains a reusable Go
wallet/key library, a CLI and HTTP API, a desktop wallet with an embedded web
UI, a browser extension, and native Android/iOS shells. Changes involving keys,
addresses, transactions, signatures, wallet persistence, or API payloads are
security- and compatibility-sensitive: inspect callers and fixtures before
changing a contract.

The repository is independently versioned. Do not make source changes in the
parent `clanker` checkout to represent a Bursa change; the parent should only
record the resulting submodule pointer when explicitly requested.

## Before editing

1. Run `git status --short --branch` and preserve unrelated changes, worktrees,
   generated files, and local agent state.
2. Read the relevant package, its tests, and the nearest documentation before
   changing behavior. For an API or generated type, read both the server-side
   producer and every checked-in consumer first.
3. Identify the module boundary. This checkout has three Go modules:

   - `./` — wallet library, CLI, API, storage, signer, and shared Cardano code
   - `ui/` — embedded wallet application, boot/supervisor, node integration,
     wallet/spend/vault services, and mobile binding
   - `openapi/` — generated Go API client and its tests

   The web projects are separate Node packages:

   - `ui/web/` — React/Vite desktop wallet SPA, embedded by the `ui` module
   - `ui/extension/` — browser extension connector and provider

4. Check `.github/CODEOWNERS` and the workflow that covers the changed path.
   Markdown changes are owned by the documentation owners as well as core
   owners.

## Repository map

| Area | Purpose | Typical checks |
| --- | --- | --- |
| `bursa.go`, `addresses.go`, `bip32/`, `transaction.go`, `message.go` | key derivation, Cardano addresses, transaction/message signing and serialization | root Go tests; inspect CIP and cardano-cli compatibility tests |
| `cmd/bursa/` | CLI commands for keys, wallets, addresses, scripts, signing, encryption, and certificates | root Go tests; run command `--help` for CLI changes |
| `internal/api/` | HTTP handlers, request validation, errors, Swagger annotations | root tests; regenerate `docs/` when annotations change |
| `internal/config/` | YAML and `BURSA_*` environment configuration | config tests; verify defaults and unknown/malformed values |
| `internal/storage/` and `gcp/` | file, SQLite, and Google Secret Manager wallet persistence | storage/backend tests; never use real credentials or wallets |
| `internal/signer/` | signer API, backends, policies, watermarks, and custody integrations | signer unit/integration tests; review authorization and replay boundaries |
| `internal/sops/` | passphrase/SOPS key-file handling | encryption tests; keep passphrases out of argv, logs, and fixtures |
| `ui/internal/` | wallet services, embedded node boot, chain/API adapters, vault, spend, and desktop support | `ui` Go checks; identify the affected service and its web consumer |
| `ui/web/src/` | browser wallet screens, API hooks/types, hardware-wallet and QR flows | web lint, type-check, tests, build |
| `ui/extension/src/` | extension/provider boundary and browser messaging | extension lint, type-check, tests, build |
| `ui/mobile/`, `mobile/android/`, `mobile/ios/` | gomobile binding and native shells | binding tests; platform toolchains for native artifacts |
| `docs/swagger.yaml`, `docs/swagger.json`, `docs/docs.go` | generated server API documentation | regenerate together after API annotation changes |
| `openapi/` | generated client from `docs/swagger.yaml` | generated client tests; regenerate rather than hand-edit |

## Boundaries that must stay synchronized

- HTTP request/response structs, validation, status codes, and error JSON are
  one contract shared by `internal/api`, `docs/`, `openapi/`, and the web
  clients. Change the producer and consumers together. Preserve the documented
  error shape and reject trailing JSON or oversized request bodies.
- The `ui` module imports the root Bursa module and also embeds the built SPA.
  Build `ui/web` before tests or builds that exercise `ui/internal/webui`.
  `ui/web/node_modules` contains files that can confuse a repo-wide Go wildcard;
  scope UI Go commands to `./cmd/... ./internal/...`.
- The browser extension talks to the web/API provider boundary. Check both
  `ui/extension/src` and the web-side provider/connector code for origin,
  message, serialization, and permission changes.
- The mobile binding is deliberately narrow: only gomobile-marshalable values
  cross it. Keep `Start`, `Port`, and `Stop` behavior and error propagation
  compatible with both native shells.
- Generated Swagger/OpenAPI output is not a place for manual feature edits.
  Update server annotations/source, then regenerate and inspect the full diff.

## Security and compatibility invariants

- Treat mnemonics, extended signing keys, passphrases, wallet files, signer
  backend credentials, JWT secrets, and hardware-wallet material as secrets.
  Do not add them to logs, command arguments, test output, screenshots, or
  committed fixtures. Prefer temporary directories and deterministic dummy
  keys in tests.
- Preserve restrictive secret-key file permissions on Unix and Windows. Any
  change to key-file creation, replacement, or encryption must retain the
  permission checks and update the platform-specific tests.
- Do not weaken signer authentication, TLS/loopback restrictions, caller
  authorization, key policy checks, transaction/CIP-8 watermarks, or replay
  protection. A new signer operation needs positive and negative tests for
  caller, key, policy, and watermark behavior.
- Keep cryptographic and wire-format changes tied to the relevant CIP and
  cardano-cli compatibility tests. Do not change CBOR, bech32 prefixes,
  derivation paths, network tags, key envelope types, or transaction witness
  semantics without checking existing fixtures and consumers.
- Storage changes must preserve wallet naming, item encoding, atomicity,
  deletion behavior, and context cancellation across file, SQLite, and cloud
  backends. Never point tests at a real cloud project or an existing wallet.
- The API has explicit request-size and JSON validation behavior. Maintain
  content types, status codes, field names, and safe internal-error messages
  unless the client contract is intentionally updated in the same change.

## Validation

Run the narrowest applicable checks, then the broader checks when practical.
From the repository root:

```sh
go test ./...
go test -race ./...
go vet ./...
```

The Makefile's `make test` runs `go mod tidy` and `go test -v -race ./...`;
use it when module-file changes are part of the intended work. `make build`
builds the CLI binaries. `make format` also changes module files, so do not
run it as a read-only check on an unrelated working tree.

For the `ui` module, build the embedded SPA first, then run:

```sh
cd ui/web && npm ci && npm run build
cd .. && go vet ./cmd/... ./internal/...
go test ./cmd/... ./internal/...
go build ./cmd/bursa-wallet
```

For web UI changes, from `ui/web/` run `npm ci`, `npm run lint`,
`npm run type-check`, `npm run test`, and `npm run build`. For extension
changes, run the same five commands from `ui/extension/`. Use the package lock
files; do not update dependencies unless the task requires it.

For the generated client, run `go test ./...` from `openapi/`. The regeneration
script is `./openapi.sh`; it requires Docker and regenerates the client from
`docs/swagger.yaml`, then formats and tidies modules. Review generated output
for unintended changes before staging it.

Desktop webview builds require native CGO/webview libraries. The supported
targets are `make wallet-binary-webview` after the SPA build, and the Makefile's
`webkit-shim` handles the Ubuntu 24.04 WebKitGTK 4.1 compatibility case. Do
not claim a webview or native-platform check passed if the required toolchain
was unavailable.

Mobile builds are platform-specific and intentionally not part of normal PR
CI. Android uses `mobile/android/Dockerfile` and
`mobile/android/build-in-docker.sh`; iOS requires macOS/Xcode and
`mobile/ios/project.yml`. The workflow is the authoritative artifact recipe.

After any change, run `git diff --check`, inspect `git diff --stat`, and verify
that only intended files are staged. Do not commit build output, `node_modules`,
wallet/key material, generated files that the project does not track, or local
reports.

## Pull requests and review

- Use a short Conventional Commit subject and a DCO sign-off for commits.
- Product-repository changes go through a pull request; do not push directly to
  `main` or bypass branch protection.
- Describe the affected module/boundary, validation commands, generated files,
  and any platform or live-service checks that could not run.
- UI changes need screenshots of affected states at the relevant viewport with
  secrets and personal data redacted.
- Review changes in this order: secret/key safety; cryptographic and wire/API
  compatibility; authorization and error behavior; persistence and concurrency;
  generated-code synchronization; then style.
- A test is useful only if it exercises the behavior under change. For a bug or
  security fix, include the failure/negative case and ensure the test would fail
  against the pre-fix behavior.

When changing a public API, key format, generated client, storage schema, or
mobile binding, explicitly list the consumers checked in the PR. If a consumer
is outside this checkout, identify the required coordinated change instead of
assuming it is unaffected.
