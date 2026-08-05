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

| Capability | Support |
|------------|---------|
| Auth | JWT bearer (HS256 shared secret dev, or JWKS RS256/ES256/EdDSA prod), mTLS client certificate, and authorized-keys Ed25519 request signing; precedence mTLS > request-signing > JWT; optional per-subject caller ACL |
| Transport | Server-side TLS (TLS 1.2+), optional mutual TLS; loopback may run plaintext |
| Custody backends | `vault` (Transit, remote signing), `pkcs11` (HSM, keys never leave the token; CGO, `-tags pkcs11`), `sops` (GCP Secret Manager + SOPS), `software`/`file` (in-process plaintext, dev-only) |
| Operations | `tx`, `cip8`, `opcert` signing; key list/detail with effective policy |
| Anti-double-sign | Watermark store: `mem` (non-durable), `file` (SQLite), or `postgres` (shared, HA-safe); modes off/warn/enforce |
| Observability | `/healthz`, `/readyz` (pings the watermark store), Prometheus `/metrics` |

## Quick start (development)

`signer.example.yaml` documents the full production shape (JWKS auth, TLS,
Vault) with placeholder values that don't exist on a fresh machine, so copy it
and trim it down for a loopback run rather than passing it as-is:

```sh
cp docs/signer/signer.example.yaml /tmp/signer-dev.yaml
# In /tmp/signer-dev.yaml:
#   - clear jwks_url (blank string) and set jwt_secret to a random >=32-byte
#     value (exactly one of the two may be set)
#   - clear tls_cert_file and tls_key_file (loopback may run plaintext)
bursa signer --config /tmp/signer-dev.yaml
```

For anything exposed off-host, follow the [runbook](runbook.md) to configure
TLS, JWKS, and a Vault or SOPS backend.
