# Bursa Signer & KES Agent

Operator documentation for the two bursa signing daemons:

- **`bursa signer`** - a remote signing service exposing an HTTP API. It holds
  no wallet state, resolves keys from configured custody backends, and produces
  Cardano signatures (transactions, CIP-8/CIP-30 messages, operational
  certificates) under a per-key policy engine and an anti-double-sign watermark.
- **`bursa kes-agent`** - a KES (Key Evolving Signature) agent daemon for a Go
  block producer (dingo). It holds the block-production KES key in memory with
  best-effort `mlock`, evolves it forward-securely each KES period, and serves
  it over Unix sockets. If locking is unavailable or refused, it logs a warning
  and continues with potentially swappable memory. The pool cold signing key
  never touches the agent.

## Documents

| File | Contents |
|------|----------|
| [`runbook.md`](runbook.md) | Deploy, TLS, auth, backends, watermark, health, metrics |
| [`attested-custody.md`](attested-custody.md) | Attested TEE key custody: protocol, AWS Nitro and GCP Confidential Space backends, trust boundaries |
| [`security.md`](security.md) | Threat model, custody guarantees, dev-only file backend |
| [`kes-agent.md`](kes-agent.md) | KES agent daemon operation |
| [`openapi.yaml`](openapi.yaml) | OpenAPI 3 spec for the signer `/v1` HTTP API |
| [`kes-agent-protocol.md`](kes-agent-protocol.md) | KES agent Unix-socket wire protocol |
| [`signer.example.yaml`](signer.example.yaml) | Annotated signer config |
| [`kes-agent.example.yaml`](kes-agent.example.yaml) | Annotated KES agent config |

Systemd units, an `EnvironmentFile` example, and a Dockerfile live in
[`../../packaging/signer/`](../../packaging/signer/).

## Capability summary

| Capability | Support |
|------------|---------|
| Auth | mTLS client certificate, authorized-keys Ed25519 request signing, and JWT bearer (HS256 shared secret or JWKS RS256/ES256/EdDSA); precedence mTLS > request-signing > JWT; optional per-subject caller ACL |
| Transport | Server-side TLS (TLS 1.2+); loopback may run plaintext. Optional mutual TLS verifies client certificates against a configured CA bundle |
| Custody backends | `nitro` and `confidential-space` (keys held in an attested TEE), `vault` (Transit, remote signing), `pkcs11` (HSM, keys never leave the token; CGO, `-tags pkcs11`), `sops` (GCP Secret Manager + SOPS), `software`/`file` (in-process plaintext, dev-only) |
| Operations | `tx`, `cip8`, `opcert` signing; key list/detail with effective policy |
| Anti-double-sign | Watermark store: `mem` (non-durable; only with `warn` or `off`), `file` (SQLite), or shared HA-safe `postgres`; modes off/warn/enforce |
| Observability | Static liveness on `/healthz`, dependency-aware readiness on `/readyz`, Prometheus `/metrics` |

## Quick start (development)

`signer.example.yaml` documents the full production shape (JWKS auth, TLS,
a Vault backend, a SOPS/GCP backend, a caller ACL, and a durable watermark
path) with placeholder values that don't exist on a fresh machine. Passing it
as-is won't boot: `BuildBackends` dials the Vault and GCP Secret Manager
placeholders at startup, and the watermark's SQLite path
(`/var/lib/bursa/signer/watermark.sqlite`) doesn't exist on a fresh machine
either. Prepare an owner-only development directory, then cut the copied config
down to a dependency-free loopback config:

```sh
SIGNER_DEV_DIR=$(docs/signer/prepare-quickstart.sh)
SIGNER_DEV_CONFIG="$SIGNER_DEV_DIR/signer.yaml"
SIGNER_DEV_KEYS="$SIGNER_DEV_DIR/keys"
# In "$SIGNER_DEV_CONFIG":
#   - clear jwks_url (blank string) and leave jwt_secret blank. The helper
#     generated SIGNER_JWT_SECRET in the owner-only auth.env file (exactly one
#     of jwt_secret and jwks_url may be set)
#   - clear tls_cert_file and tls_key_file (loopback may run plaintext)
#   - replace the `backends:` list with a single software entry:
#       backends:
#         - name: "local-dev"
#           type: "software"
#           path: "<value of $SIGNER_DEV_KEYS>"
#     (drop the vault-prod and sops-secrets entries - each dials a real
#     backend at boot and fails without one)
#   - drop the top-level `keys:` entry (it references the now-removed
#     vault-prod backend); add one back for `local-dev`, keyed on the real
#     key's hash, once you've dropped a *.skey into the software backend's
#     `path` - see the runbook's `bursa key` guidance
#   - drop the `callers:` list (an absent ACL is unrestricted, which is fine
#     for a local smoke test)
#   - drop the top-level `google:` block (only read by the sops backend)
#   - change `watermark.type` to `mem` and `watermark.mode` to `warn` (drops
#     the requirement for a pre-existing `/var/lib/bursa/signer` directory;
#     non-durable, which is fine for development)
set -a
. "$SIGNER_DEV_DIR/auth.env"
set +a
bursa signer --config "$SIGNER_DEV_CONFIG"
```

This boots with no external dependencies. It can't sign anything until you
load a real key into `$SIGNER_DEV_KEYS` and add back a matching `keys:` policy
entry - see the [runbook](runbook.md). The helper applies `umask 077`; its
directory and key directory remain mode `0700`, and the copied configuration
and generated authentication environment file remain mode `0600`.

For anything exposed off-host, follow the [runbook](runbook.md) to configure
TLS, JWKS, and a Vault or SOPS backend.
