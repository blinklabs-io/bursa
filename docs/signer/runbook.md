# Signer Runbook

Operational guide for deploying and running `bursa signer`.

## 1. Build

The signer is part of the `bursa` binary (root module, pure Go,
`CGO_ENABLED=0`):

```sh
CGO_ENABLED=0 go build -o bursa ./cmd/bursa
# or
make build
```

A container image is provided in [`packaging/signer/`](../../packaging/signer/).

## 2. Configure

Configuration is a YAML file (see
[`signer.example.yaml`](signer.example.yaml)), supplied via `--config` or the
`BURSA_CONFIG` environment variable. Every field also has an environment-
variable override (shown in the example). Secrets (JWT secret, Vault token,
key passphrase) should be delivered via environment variables, not the file.

Boot performs eager validation and exits non-zero on any of:

- neither or both of `signer.jwt_secret` / `signer.jwks_url` set;
- `signer.jwt_secret` shorter than 32 bytes;
- only one of `tls_cert_file` / `tls_key_file` set;
- a non-loopback listen address without TLS;
- a software/file backend on a non-loopback address without
  `allow_insecure_file_backend` (see [security.md](security.md));
- no backends configured, or the same key hash served by two backends;
- invalid policy, watermark, or caller ACL.

## 3. Authentication

At least one auth mode must be configured. The modes are composable and all
resolve to a single caller identity fed to the caller ACL. When more than one is
enabled, they are tried in a fixed precedence: **mTLS client cert >
authorized-keys request signing > JWT bearer**. The first scheme that presents a
credential decides the request - a valid credential authenticates it, an invalid
one rejects it (there is no fall-through to a weaker scheme once a credential is
presented). An empty chain fails closed.

### JWT bearer

Configure **at most one** validator:

- **HS256** (`signer.jwt_secret`, >=32 bytes) - development / simple.
- **JWKS** (`signer.jwks_url`) - production. Verifies RS256/ES256/EdDSA against
  the identity provider's published keys.

`signer.jwt_issuer` and `signer.jwt_audience` are enforced when set; leave them
unset only if you intend to accept any issuer/audience (a warning is logged).
The caller identity is the token `sub` claim.

### mTLS client certificate

Set `signer.client_ca_cert` to a PEM bundle of CA certificate(s) used to verify
TLS client certificates. This requires server TLS (below) - the client cert is
verified during the TLS handshake, so boot fails if `client_ca_cert` is set
without `tls_cert_file`/`tls_key_file`.

- `signer.require_client_cert: true` makes a verified client certificate
  mandatory on every connection (`RequireAndVerifyClientCert`); mTLS then always
  wins over the other modes, a transport-level identity a captured bearer token
  cannot override.
- Left `false` (with `client_ca_cert` set), a client cert is optional
  (`VerifyClientCertIfGiven`): connections that present one authenticate via
  mTLS, connections without one fall through to the next configured mode.

The caller identity is derived from the verified leaf certificate: first URI
SAN, else first DNS SAN, else the Subject CommonName. Set the matching value as
a `signer.callers[].subject` to scope keys per client identity.

### Authorized-keys request signing

`signer.authorized_keys` registers Ed25519 public keys allowed to authenticate
by signing each request. Each entry is `{caller, ed25519_pubkey_hex}` (the
pubkey is the hex-encoded 32 bytes). The client signs the canonical string

```
METHOD | PATH | HEX(SHA-256(body)) | TIMESTAMP | NONCE
```

(fields joined by a literal `|`) with its Ed25519 private key and sends:

| Header | Value |
|--------|-------|
| `X-Bursa-Key` | the `caller` naming the authorized key |
| `X-Bursa-Signature` | lower-case hex of the 64-byte Ed25519 signature |
| `X-Bursa-Timestamp` | Unix seconds (decimal) used in the canonical string |
| `X-Bursa-Nonce` | a client-unique value per request |

The server rebuilds the canonical string, verifies the signature against the
registered key, rejects timestamps outside `±signer.request_sign_skew_seconds`
(default 60), and rejects a reused `(key, nonce)` via an in-memory replay cache
(TTL = twice the skew; at capacity it fails closed with 503). The caller
identity is `X-Bursa-Key`.

### Caller ACL

`signer.callers` maps a caller identity (JWT `sub`, mTLS cert identity, or
authorized-key `caller`) to a list of key hashes. When any callers are
configured, unlisted subjects are denied every key, and each subject is limited
to its listed keys. Without a caller ACL, any valid token may use any configured
key (a warning is logged at boot). Sign-path ACL denials return HTTP 403; key
list/detail filtering hides unauthorized keys (detail returns 404 to prevent
existence probing).

## 4. TLS

The signer serves server-side TLS when both `tls_cert_file` and `tls_key_file`
are set (TLS 1.2 minimum). A non-loopback listen address without TLS is refused
at boot. Loopback listeners may run plaintext (for local development or when a
co-located proxy terminates TLS).

Mutual TLS is supported natively: set `signer.client_ca_cert` to enable client-
certificate verification during the handshake (see the mTLS subsection under
[Authentication](#3-authentication)). You may still terminate mTLS at a reverse
proxy that forwards a JWT if you prefer, but it is no longer required.

## 5. Custody backends

Configure one or more `signer.backends`. A key is routed to the backend that
holds it; the same hash appearing in two backends is a boot error.

### vault (recommended for production)

Vault Transit signing. The private key never leaves Vault; the signer sends the
digest and receives the signature. Only standard (non-extended) Ed25519 keys are
supported. Configure `address`, `transit_mount`, the token env var
(`token_env`, default `VAULT_TOKEN`), and an explicit `keys` list naming each
Transit key and its Cardano type.

### sops

SOPS-encrypted key envelopes fetched from GCP Secret Manager (using the
top-level `google.project`) and decrypted in-process at boot. Keys are held in
memory after decryption. Use `secret_prefix` to select the secrets.

### software / file (development only)

Loads plaintext (or passphrase-encrypted) `*.skey` files from `path` directly
into process memory. Passphrase-encrypted files require `passphrase_env`. This
backend is gated by `allow_insecure_file_backend` on non-loopback addresses;
see [security.md](security.md).

### pkcs11 (HSM; requires `-tags pkcs11`)

Hardware-custody backend that signs with an Ed25519 key held in a PKCS#11 token
(HSM). The private key never leaves the token: the signer sends the message and
the token performs `CKM_EDDSA` (PureEdDSA), returning the 64-byte signature -
the same "key never leaves the HSM" property as Vault Transit. Because no
in-process private key exists, this backend does **not** serve `cip8` (the CIP-8
path needs an in-memory key and rejects pkcs11 keys, same as Vault).

This driver uses CGO and is compiled only with the `pkcs11` build tag; the
default pure-Go build (`CGO_ENABLED=0`) wires a stub that fails at boot with a
clear "not compiled in" error if a `pkcs11` backend is configured. Build it with:

```sh
CGO_ENABLED=1 go build -tags pkcs11 -o bursa ./cmd/bursa
```

Configure:

- `module` - filesystem path to the PKCS#11 module (`.so`).
- `token_label` **or** `slot` - select the token by label, or by explicit slot id.
- `pin_env` - name of the env var holding the user PIN (never written to config).
- `keys` (optional) - an allowlist of `{name, type}` where `name` is the object's
  `CKA_LABEL` and `type` is the Cardano key type. When omitted, every Ed25519
  signing key on the token is loaded as a `payment` key.

## 6. Per-key policy

`signer.keys` attaches a policy to each key hash (deny-by-default: a key with no
entry can sign nothing). `allowed_requests` lists the permitted request kinds
(`tx`, `cip8`, `opcert`); `tx_policy` / `cip8_policy` add typed constraints.
Unknown policy fields fail at boot.

## 7. Anti-double-sign watermark

`signer.watermark` records the highest period/counter signed per key and refuses
regressions.

- `type: mem` - in-memory, non-durable (lost on restart). Default.
- `type: file` - SQLite file at `path`, durable across restarts (single process).
- `type: postgres` - durable store shared by every replica; the HA-safe option.
  Set the connection string via `dsn_env` (an env var name, keeps credentials
  out of the config file) in preference to the plaintext `dsn` fallback.
- `mode: off | warn | enforce` - `enforce` (default) rejects a conflicting sign
  with HTTP 409; `warn` logs and allows; `off` disables the check.

### High availability

For a single active instance, a durable `file` (SQLite) watermark is sufficient.

To run **multiple signer replicas** for the same keys, they **must share one
`postgres` watermark store** - all replicas point at the same database. The
Postgres store enforces the anti-double-sign guards atomically: the monotonic
issue-counter guard is a single advance-if-greater SQL statement, so two
replicas that concurrently try to advance the same key to the same counter
cannot both succeed. Do **not** run multiple active signers against independent
`mem` or per-instance `file` stores for the same keys - the guard would not be
shared and double-signing becomes possible.

## 8. Health, readiness, metrics

Unauthenticated endpoints on the signer's listener:

- `GET /healthz` - liveness (always 200 while the process runs).
- `GET /readyz` - readiness. Verifies runtime dependencies: backends were built
  at boot, and the watermark store is reachable (the `file` and `postgres`
  stores are pinged, bounded by a 3s timeout). Returns 200 when ready, 503 when
  the store is unreachable. This makes `/readyz` meaningful for an HA deployment
  behind a load balancer - a replica whose shared Postgres store is down is
  taken out of rotation.
- `GET /metrics` - Prometheus exposition.

Metrics exported:

| Metric | Meaning |
|--------|---------|
| `bursa_signer_requests_total` | Sign requests, by outcome |
| `bursa_signer_deny_total` | Denials (e.g. ACL, policy) |
| `bursa_signer_sign_duration_seconds` | Sign latency histogram |
| `bursa_signer_backend_errors_total` | Custody backend errors |
| `bursa_signer_watermark_conflicts_total` | Watermark rejections |

## 9. Logs and audit

The signer logs structured JSON. Every sign request emits exactly one audit line
carrying a per-request `audit_id` (also returned in the response body), the
caller subject, request type, outcome, and remote address. No secrets or raw
CBOR are logged. 5xx response bodies are masked; the real error is logged under
the same `audit_id`.

## 10. Shutdown

`SIGINT` / `SIGTERM` triggers graceful drain with a 10-second timeout before
forced exit.
