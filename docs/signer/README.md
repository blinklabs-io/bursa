# Bursa Signer & KES Agent

Operator documentation for the two bursa signing daemons:

- **`bursa signer`** - a remote signing service exposing an HTTP API. It holds
  no wallet state, resolves keys from configured custody backends, and produces
  Cardano signatures (transactions, CIP-8/CIP-30 messages, operational
  certificates) under a per-key policy engine and an anti-double-sign watermark.
- **`bursa kes-agent`** - a KES (Key Evolving Signature) agent daemon for a Go
  block producer (dingo). It holds the block-production KES key in locked
  (mlock'd) memory, evolves it forward-securely each KES period, and serves it
  over Unix sockets. The pool cold signing key never touches the agent.
  (Introduced in #675.)

## Documents

| File | Contents |
|------|----------|
| [`runbook.md`](runbook.md) | Deploy, TLS, auth, backends, watermark, health, metrics |
| [`security.md`](security.md) | Threat model, custody guarantees, dev-only file backend |
| [`kes-agent.md`](kes-agent.md) | KES agent daemon operation |
| [`openapi.yaml`](openapi.yaml) | OpenAPI 3 spec for the signer `/v1` HTTP API |
| [`kes-agent-protocol.md`](kes-agent-protocol.md) | KES agent Unix-socket wire protocol |
| [`signer.example.yaml`](signer.example.yaml) | Annotated signer config |
| [`kes-agent.example.yaml`](kes-agent.example.yaml) | Annotated KES agent config |

Systemd units, an `EnvironmentFile` example, and a Dockerfile live in
[`../../packaging/signer/`](../../packaging/signer/).

## Capability summary

Rows marked **not yet in main** describe a capability that is specified here but
served by an open pull request; the caveat names it. Everything else is in the
current `main`.

| Capability | Support |
|------------|---------|
| Auth | JWT bearer (HS256 shared secret dev, or JWKS RS256/ES256/EdDSA prod); optional per-subject caller ACL. mTLS client certificate and authorized-keys Ed25519 request signing (precedence mTLS > request-signing > JWT) are **not yet in main** - implemented by PR #673 |
| Transport | Server-side TLS (TLS 1.2+); loopback may run plaintext. Optional mutual TLS is **not yet in main** - implemented by PR #673 |
| Custody backends | `vault` (Transit, remote signing), `pkcs11` (HSM, keys never leave the token; CGO, `-tags pkcs11`; merged in #668), `sops` (GCP Secret Manager + SOPS), `software`/`file` (in-process plaintext, dev-only) |
| Operations | `tx`, `cip8`, `opcert` signing; key list/detail with effective policy |
| Anti-double-sign | Watermark store: `mem` (non-durable), `file` (SQLite), or shared HA-safe `postgres`; modes off/warn/enforce |
| Observability | Static liveness on `/healthz`, dependency-aware readiness on `/readyz`, Prometheus `/metrics` |

## Quick start (development)

`signer.example.yaml` documents the full production shape (JWKS auth, TLS,
a Vault backend, a SOPS/GCP backend, a caller ACL, and a durable watermark
path) with placeholder values that don't exist on a fresh machine. Passing it
as-is won't boot: `BuildBackends` dials the Vault and GCP Secret Manager
placeholders at startup, and the watermark's SQLite path
(`/var/lib/bursa/signer/watermark.sqlite`) doesn't exist on a fresh machine
either. Copy it and cut it down to a dependency-free loopback config instead:

```sh
mkdir -p /tmp/signer-dev-keys   # may stay empty; see note below
cp docs/signer/signer.example.yaml /tmp/signer-dev.yaml
# In /tmp/signer-dev.yaml:
#   - clear jwks_url (blank string) and set jwt_secret to a random >=32-byte
#     value (exactly one of the two may be set)
#   - clear tls_cert_file and tls_key_file (loopback may run plaintext)
#   - replace the `backends:` list with a single software entry:
#       backends:
#         - name: "local-dev"
#           type: "software"
#           path: "/tmp/signer-dev-keys"
#     (drop the vault-prod and sops-secrets entries - each dials a real
#     backend at boot and fails without one)
#   - drop the top-level `keys:` entry (it references the now-removed
#     vault-prod backend); add one back for `local-dev`, keyed on the real
#     key's hash, once you've dropped a *.skey into the software backend's
#     `path` - see the runbook's `bursa key` guidance
#   - drop the `callers:` list (an absent ACL is unrestricted, which is fine
#     for a local smoke test)
#   - drop the top-level `google:` block (only read by the sops backend)
#   - change `watermark.type` to `mem` (drops the requirement for a
#     pre-existing `/var/lib/bursa/signer` directory; non-durable, which is
#     fine for development)
bursa signer --config /tmp/signer-dev.yaml
```

This boots with no external dependencies. It can't sign anything until you
load a real key into `/tmp/signer-dev-keys` and add back a matching `keys:`
policy entry - see the [runbook](runbook.md).

For anything exposed off-host, follow the [runbook](runbook.md) to configure
TLS, JWKS, and a Vault or SOPS backend.
