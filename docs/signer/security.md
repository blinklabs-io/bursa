# Signer Security Guide

## Threat model

The signer's job is to hold or reach signing keys and produce signatures only
for authenticated, authorized, and policy-compliant requests, without ever
regressing an anti-double-sign watermark. The assets and the controls that
protect them:

| Asset | Threat | Control |
|-------|--------|---------|
| Private key material | Exfiltration from the signer host | Prefer custody where the key never enters the signer process - a PKCS#11 HSM token or Vault Transit; keep the plaintext software backend on loopback/dev only |
| The signing capability | Unauthorized callers | Bearer JWT (HS256/JWKS) with enforced `iss`/`aud`; per-subject caller ACL over the resolved identity. mTLS client certificate and authorized-keys Ed25519 request signing (timestamp window + nonce replay cache) are not yet in main - implemented by PR #673 |
| Correct-but-unwanted signatures | Over-broad key use | Deny-by-default per-key policy (`allowed_requests`, tx/cip8 policy) |
| Consensus safety / key reuse | Double-signing, period rollback | Watermark store in `enforce` mode; KES period guard in the KES agent |
| Request contents | Leakage via logs/errors | No secrets or raw CBOR logged; 5xx bodies masked; audit IDs correlate |
| Transport | Eavesdropping / tampering | Server-side TLS required off-loopback |

Out of scope: the signer trusts its configuration file and host. Protect the
config, the TLS key, the JWT secret / Vault token, and any key files with
filesystem permissions and a dedicated service user (see the systemd units in
`packaging/signer/`).

## Machine-to-machine authentication

> **Implementation status.** Bearer JWT is the only auth scheme in `main` today
> (`internal/signer/api/auth.go`). The mTLS and authorized-keys schemes below,
> the precedence chain, and the `client_ca_cert`, `require_client_cert`,
> `authorized_keys` and `request_sign_skew_seconds` settings are implemented by
> PR #673 (branch `feat/signer-mtls`) and are not available until it merges.

The signer is a service-to-service component; its production auth is designed for
machine callers, tried in precedence order **mTLS > request-signing > JWT**:

- **mTLS client certificate** (`client_ca_cert`, `require_client_cert`) binds the
  caller identity to a certificate verified during the TLS handshake - a
  transport-level identity that a captured bearer token cannot override. With
  `require_client_cert` every connection must present a verified cert.
- **Authorized-keys request signing** (`authorized_keys`) has each caller sign
  `METHOD|PATH|sha256(body)|timestamp|nonce` with an Ed25519 key. The signature
  covers the body, and a timestamp window (`request_sign_skew_seconds`) plus a
  nonce replay cache stop capture-and-replay. No long-lived bearer secret is sent
  on the wire.
- **JWT bearer** remains available for IdP-issued tokens (`iss`/`aud` enforced).

All three resolve to a single caller identity fed to the per-subject caller ACL.
Until #673 merges, that identity is always the JWT `sub`.

## Custody guarantees

**Keys never leave the HSM/Vault.** With the `pkcs11` backend the private key
lives in the HSM token and the token itself performs the Ed25519 signature
(`CKM_EDDSA`); with the `vault` backend the signer sends only the digest to Vault
Transit and receives a signature back. In both cases the signer process never
holds the key. These are the recommended postures for production and for any
high-value key (pool cold, governance, payment hot). The `pkcs11` driver is CGO
and requires the `-tags pkcs11` build; the default pure-Go build refuses to boot
if a `pkcs11` backend is configured (`ErrPKCS11NotCompiled`). Merged in #668.

The `sops` backend fetches SOPS-encrypted envelopes from GCP Secret Manager and
decrypts them **in process** at boot; the decrypted key then lives in signer
memory for the process lifetime. This is stronger than plaintext-at-rest but
still places key material in the signer's address space.

## The file/software backend is development-only

The `software` (a.k.a. `file`) backend loads plaintext `*.skey` files (or
passphrase-decrypts them) directly into process memory
(`internal/signer/backend/software.go`). It exists for local development and
testing. **Never use it in production**, mirroring Signatory's guidance to never
run the file backend in production.

The signer enforces this with a guardrail:

- If a `software`/`file` backend is configured **and** the listen address is
  non-loopback (including the all-interfaces empty address) **and**
  `signer.allow_insecure_file_backend` is not set, the signer **refuses to
  boot** with a clear error.
- On a loopback address, or with `allow_insecure_file_backend: true` explicitly
  set, boot proceeds but a **loud warning** is logged on every start.

Set `allow_insecure_file_backend: true` only for deliberate, isolated
development setups where you understand that plaintext keys are exposed to
anything that can read the process memory or the key directory.

## Deployment hardening checklist

- Run under a dedicated, unprivileged service user; use the provided systemd
  hardening (`NoNewPrivileges`, `ProtectSystem=strict`, `MemoryDenyWriteExecute`,
  etc.).
- Terminate/serve TLS (TLS 1.2+); never expose a plaintext non-loopback listener.
- Use JWKS with `iss` and `aud` enforced in production and rotate signing keys
  at the IdP. Once PR #673 merges, prefer machine-to-machine auth instead: mTLS
  client certificates (with `require_client_cert`) and/or authorized-keys
  request signing.
- Configure a caller ACL so each subject reaches only the keys it needs.
- Prefer the `pkcs11` (HSM) or `vault` backend so keys never enter the process;
  reserve `software`/`file` for development.
- Run the watermark in `enforce` mode with a durable `file` (SQLite) store.
  Multiple replicas for the same keys require a shared store, which is not yet
  in main - the `postgres` store is implemented by PR #674 (branch
  `feat/signer-ha-store`). Until then, run a single active signer per key set;
  never point multiple active signers at independent per-instance stores.
- Restrict the config file, TLS key, and any key files to the service user.
- Scrape `/metrics`; alert on `bursa_signer_watermark_conflicts_total` and
  `bursa_signer_backend_errors_total`.
