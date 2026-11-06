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

- no authentication mode configured, or both `signer.jwt_secret` and
  `signer.jwks_url` set;
- `signer.jwt_secret` shorter than 32 bytes;
- only one of `tls_cert_file` / `tls_key_file` set;
- a non-loopback listen address without TLS;
- a software/file backend on a non-loopback address without
  `allow_insecure_file_backend` (see [security.md](security.md));
- a `signer.policy_hook_url` that is not an absolute HTTPS URL;
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

`signer.callers` maps a caller identity to a list of key hashes. That identity
is the verified certificate identity, authorized-key `caller`, or JWT `sub`,
depending on the authentication mode. When any callers are configured, unlisted
subjects are denied every key, and each subject is limited to its listed keys.
Without a caller ACL, any authenticated caller may use any configured key (a
warning is logged at boot). A signing request denied entirely by the caller
ACL returns HTTP 403. Transaction requests can return HTTP 200 with successful
witnesses and per-signer ACL errors; if no signer succeeds, a signing error
takes precedence over an ACL error when selecting the response status. Key
list/detail filtering hides unauthorized keys (detail returns 404 to prevent
existence probing).

## 4. TLS

The signer serves server-side TLS when both `tls_cert_file` and `tls_key_file`
are set (TLS 1.2 minimum). A non-loopback listen address without TLS is refused
at boot. Loopback listeners may run plaintext (for local development or when a
co-located proxy terminates TLS).

For mutual TLS, set `signer.client_ca_cert` and optionally
`signer.require_client_cert` as described under
[Authentication](#3-authentication). Client certificates are verified during
the TLS handshake.

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

SOPS-encrypted key envelopes decrypted in-process at boot. Keys are held in
memory after decryption. The envelopes come from one of two sources, and
setting both `path` and `secret_prefix` is refused:

- `path`: a local directory, such as a mounted Kubernetes Secret. Every
  regular `*.json` file whose name does not start with a dot is one envelope,
  encrypted in the SOPS JSON format. Symlinks are followed, so the `..data`
  links of a Secret volume work. Files are capped at 64 KiB. An entry that
  cannot be read, such as a dangling symlink, fails boot rather than dropping
  that key.
- Otherwise, GCP Secret Manager (using the top-level `google.project`): the
  secrets whose names start with `secret_prefix`. An empty prefix selects
  every secret in the project.

Decryption uses the standard SOPS key sources, such as an age identity in
`SOPS_AGE_KEY_FILE` or `SOPS_AGE_KEY`. Encrypt the key files to a recipient
that unlocks nothing else.

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
`backend`, when set, names the configured backend (`backends[].name`) that
must hold the key; a request is denied when the key resolves from any other
backend. Omit it to accept any backend. A `backend` that matches no configured
backend name, or more than one, fails at boot, as do unknown policy fields.

### External transaction-policy hook

`signer.policy_hook_url` adds an external authorization step after the static
transaction policy allows a request. The signer sends the parsed operation
summary as JSON and signs only when the endpoint returns HTTP 200 with
`{"allow":true}`. Transport errors, timeouts, redirects, other status codes,
and malformed or non-allow responses deny signing.

The summary includes `tx_id`, `fee`, `ttl`, `outputs` (including each
`has_assets` flag), `certificate_count`, `certificates`, `has_mint`,
`withdrawal_count`, `voting_procedure_count`, `voters` (paired `kind` and
optional `drep_id` values), `proposal_procedure_count`, and
`has_treasury_donation`. Ledger value effects are reported as
`treasury_donation`, `certificate_deposit_total`, `certificate_refund_total`,
`proposal_deposit_total`, `unresolved_certificate_deposits`,
`unresolved_certificate_refunds` (deposits or refunds whose amount the
transaction does not encode), and `certificate_value_effects_complete`, which
is false when a certificate type has no known value effect.
The original `voter_kinds` and `drep_ids` arrays remain
for existing hook consumers. Bursa denies signing before calling the hook when
the decoded certificate or voter details do not match their transaction counts.

The URL must use HTTPS. Bursa verifies the endpoint certificate against the
host's system trust store and refuses redirects, so a policy decision cannot be
downgraded to an unauthenticated plaintext response. Install a private policy
service CA in the host trust store when needed. Set the request deadline with
`signer.policy_hook_timeout_ms` (default 5 seconds).

Transaction policy evaluates both possible ledger effect paths because the
`is_valid` flag is not part of the signed transaction body. A body with
collateral inputs must include `total_collateral`; that amount is checked
against fee limits, while collateral return is checked against output network,
address, amount, asset, and total-value limits. The external policy hook
receives `collateral_inputs`, `collateral_return`, and `total_collateral` in
addition to ordinary outputs and the fee.

## 7. Anti-double-sign watermark

`signer.watermark` records the highest period/counter signed per key and refuses
regressions.

- `type: mem` - in-memory, non-durable (lost on restart). Default type, but
  refused unless `mode` is `warn` or `off`. Warning mode retains the latest
  65,536 transaction watermark scopes in FIFO order; older scopes are evicted.
  This bound affects warning records only. Enforced watermarks use a durable,
  non-evicting store.
- `type: file` - SQLite file at `path`, durable across restarts (single process).
- `type: postgres` - durable store shared by every replica; the HA-safe option.
  The connection string is set via `dsn_env` (an env var name, keeping
  credentials out of the config file) in preference to the plaintext `dsn`
  fallback. Remote connections must use `sslmode=verify-full` with a trusted
  CA; Bursa refuses remote connections that do not verify the server hostname.
  Unix sockets, `localhost`, and loopback addresses may connect without TLS.
  The database role needs permission to create the two watermark tables on
  first startup and to read and write them thereafter.
- `mode: off | warn | enforce` - `enforce` (default) rejects a conflicting sign
  with HTTP 409; `warn` logs and allows; `off` disables the check.

Operational certificates have two counter rules. A request with
`issue_counter` must be strictly greater than every counter already signed
for the cold key. A request with `chain_counter` (the pool's on-chain opcert
counter) is issued at `chain_counter + 1` and records the chain counter as a
floor: the same value is accepted again, because a pool that rotates KES
without forging a block in between needs the same issue number, and only a
lower value is refused. Use `chain_counter` for small pools; a strictly
increasing counter would otherwise run two ahead of the chain, which nodes
reject.

The signer also records the last issue number it signed for the key, from
either request form, and refuses a chain counter above it with HTTP 409: the
ledger only holds counters that were issued, so a higher value cannot be real
and would raise the floor past every counter the ledger accepts. In `warn`
mode the request is logged and signed, and neither the floor nor the record
changes.

The same record bounds both forms from below, so switching forms cannot go
back to an earlier counter. An `issue_counter` must be greater than it. A
`chain_counter` request's issue number, `chain_counter + 1`, may equal it (a
reissue) but not be lower. Either is otherwise refused with HTTP 409; in `warn`
mode it is logged and signed, and the record does not change. A key with no
record (first use, or signed before this record existed) is not bounded until
its next opcert.

After signing, the request's own record (issue counter or floor) and this
record are written in one database transaction. A request refused at either
leaves both unchanged.

If opcerts for the same cold key are also issued by another signer, this
record falls behind. To clear it, stop opcert requests for the key on
every signer instance and let in-flight requests finish, then delete the row
whose `record_key` is `<56-character hex key hash>|opcert-chain-issued` (for a
key served by a profiled backend, `<hash>|opcert-chain-issued|<profile>`) from
`signer_counter_watermark` (Postgres) or `counter_watermark` (SQLite), and
resume requests.

#### Failover and failback of an opcert signer

Opcert counter records live in the watermark store. Signers that share one
store share these records, so this procedure applies only to signers with
independent stores; do not reset a healthy replica on a shared store.

If signer A issued counter 9 and the pool then renewed through signer B,
which has its own store, issued 10 and forged with it, the chain is at 10
while A still records 9 as issued. With `mode: enforce`, A refuses a
`chain_counter` of 10 as above the last counter issued, and an armory device
refuses it the same way. With `mode: warn`, A logs the conflict and signs
without changing its records.

Reset A's records to the current chain counter before failing back. The
reset is fenced against in-flight opcert requests: it bumps a per-key reset
generation (`opcert-chain-reset-gen`) in the same transaction, and a request
that read the records before the reset and commits after it is refused with a
conflict (HTTP 409) and returns no signature, so it cannot overwrite the
reset's floor or recreate `opcert-chain-issued`. The caller retries. Pausing
the renewal for that pool around the reset is still advisable, to avoid
refused requests, but is not required for safety:

```
bursa signer counter-reset --config signer.yaml \
  --key <56-character cold key hash> --chain-counter 10 --yes
```

Without `--yes` it opens the store read-only, prints the records and the
change, writes no records, and exits non-zero. For a `file` store in WAL mode
SQLite may still create its own `-wal` and `-shm` files beside the store,
which hold no records; the dry run fails with an error naming the directory
when it cannot. It sets `opcert-chain-floor` to the reported counter, lower or
higher than the stored value, and deletes `opcert-chain-issued`, in one
transaction that also bumps `opcert-chain-reset-gen`. It leaves `opcert-counter` (explicit `issue_counter` requests)
and the tx and cip8 watermarks alone, and refuses a `mem` store, watermark
`mode: off`, and a `file` store path that does not exist. It is a local command with no API route.

A key served by a profiled backend keeps these records under its profile
(see Profile routing). Reset them with `--profile`, naming that backend's
`profile`:

```
bursa signer counter-reset --config signer.yaml --profile otg@preview \
  --key <56-character cold key hash> --chain-counter 10 --yes
```

It sets `opcert-chain-floor|<profile>`, deletes `opcert-chain-issued|<profile>`
and bumps `opcert-chain-reset-gen|<profile>`, so only requests under that
profile are fenced. The same transaction deletes the key's
`opcert-chain-issued` record written before profile scoping: while the
profile's backend is the key's only holder the signer reads it whenever the
profile has no issued record, and it would refuse the failback again. With
several holders it is not read, and those rows are migrated before a second
profile is added. The floor written before profile scoping is left alone, as
the new floor under the profile is read in its place.

`--profile` must be the `profile` of a nitro, confidential-space or armory
backend in the config. When the config has any such backend, the command
refuses to run without `--profile`, since an unprofiled reset would neither
clear the key's records nor fence its requests. For a key served by a backend
without a profile in such a config, pass `--unprofiled` instead. Configs with
no profiled backend need neither flag.

The reset trusts the chain counter you report, as the device's floor reset
does. Read it from the chain (the counter of the pool's last forged block)
and not from another signer.

An armory device keeps its own floor. Reset it separately with the
`/provision/floor` admin route, which sets the floor and clears the last
issued counter (see the `opcert-check` command for how the device records
them).

Order:

1. Stop issuing through the old path (signer A and its device).
2. Renew through the new path (signer B).
3. Before failing back, with no opcert request for the key in flight, read
   the chain counter, then reset both the device and signer A to it.
4. Resume issuing through A; its next opcert is `chain_counter + 1`.

### Profile routing

One cold key may be held by several armory backends, each with its own
`profile` (for example `otg@preview`, `otg@musashi`, `otg@preprod` on one
device). Startup accepts a key hash in several backends only when every holder
has a non-empty profile and the profiles are distinct. A hash in a profiled and
an unprofiled backend, in two backends with one profile, or in two unprofiled
backends is refused. Configure one `keys:` entry per hash. Its `backend` field
is enforced: when set, a request is denied unless the backend the profile
selects has that name, so a key served under several profiles leaves it empty.

A sign request names the profile in `profile`; `GET /v1/keys/<hash>` takes it as
the `profile` query parameter. Without it, a key held by one backend is served
as before, and a key held by several is refused with HTTP 400. A key held by
profiled backends is served only under the named profile; a profile none of
them has is refused with HTTP 404. A key held by an unprofiled backend is not
network scoped and is served whatever the profile, so one tx can name the
profile for its armory signer and still reach its other signers. The profile
only routes: the caller is authorized by key hash.

Records of a key served by a profiled backend carry the profile:
`<hash>|<scope>|<profile>` for the opcert counter, floor and issued scopes and
for tx records, so each network keeps its own history. Records of an
unprofiled backend are unchanged. Opcert records an armory-backed key wrote
before profile scoping are keyed without the profile. While one backend holds
the key, they still bound its opcert requests until a record under its profile
exists. Once several backends hold it they are not consulted, as they cannot
be attributed to one profile. Before adding a second profile for a key, stop
every signer instance that uses the store, then migrate each of the key's
`opcert-counter`, `opcert-chain-floor` and `opcert-chain-issued` rows keyed
without a profile, naming the profile that wrote them:

- If a row for the same scope under `|<profile>` already exists, set it to the
  higher of the two values and delete the row without the profile.
- Otherwise append `|<profile>` to the row's `record_key`.

Start the signers again only after every row is migrated.

### High availability

For a single active instance, a durable `file` (SQLite) watermark is sufficient.
Multiple signer replicas for the same keys **must share one `postgres`
watermark store** - all replicas point at the same authoritative database. The
Postgres store enforces the anti-double-sign guards
atomically: the monotonic issue-counter guard is a single advance-if-greater SQL
statement, so two replicas that concurrently try to advance the same key to the
same counter cannot both succeed.

Do **not** run multiple active signers against independent `mem` or
per-instance `file` stores for the same keys - the guard would not be shared and
double-signing becomes possible. PostgreSQL replication and failover are
external to Bursa: the failover endpoint must preserve all committed rows and
must not route replicas to independent databases.

Bursa does not import watermark history from `mem` or `file` automatically.
Move both payload and counter watermark rows during a controlled outage before
cutting an active signer over to PostgreSQL, or enable PostgreSQL before the
affected keys sign for the first time.

## 8. Health, readiness, metrics

Unauthenticated endpoints on the signer's listener:

- `GET /healthz` - liveness (always 200 while the process runs).
- `GET /readyz` - pings the configured SQLite or PostgreSQL watermark store
  with a three-second timeout. It returns 503 while that dependency is
  unreachable and 200 for a healthy store. The in-memory store has no external
  dependency and is always ready after startup.

Prometheus exposition is available at `/metrics` on the dedicated metrics
listener. The listener accepts only a loopback host, with the port set by
`metrics.port`, and defaults to
`127.0.0.1:8081`; set `metrics.port` to zero to disable it. A local collector
can scrape the endpoint without exposing signer activity on the service
listener.

Use `/readyz` as the HA load-balancer readiness gate so a replica whose shared
watermark store is unavailable is removed from rotation. Custody backends are
validated at startup but are not rechecked by `/readyz`.

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
