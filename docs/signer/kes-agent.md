# KES Agent Daemon

`bursa kes-agent` is a KES (Key Evolving Signature) agent daemon: a Go replica
of IOG's kes-agent, serving a Go block producer (dingo) rather than
cardano-node.

The configuration described here is consumed by `bursa kes-agent`, separately
from the remote signer's configuration. Run `bursa kes-agent --help` for command
options.

The agent holds the block-production KES signing key in memory with best-effort
`mlock`, evolves it forward-securely each KES period, and serves it to the
producer over Unix-domain sockets. **The pool cold signing key never touches the
agent**; the agent holds only the cold *verification* key and consumes the
operational certificate that the cold signer (e.g. cardano-cli or `bursa signer`
in `opcert` mode) issued.

For the socket wire format, see
[`kes-agent-protocol.md`](kes-agent-protocol.md). For all config keys, see
[`kes-agent.example.yaml`](kes-agent.example.yaml).

## Modes

- **`serve-key`** - the agent pushes the current KES signing key (with its
  opcert) to the producer over the service socket. Key custody moves to the
  producer for actual header signing.
- **`sign`** - the producer sends a block header body and the agent returns
  its signature; the KES signing key never leaves the agent. Only header
  bodies matching the installed key and operational certificate are signed
  (see the protocol document). To run the agent inside an attested workload,
  see [`attested-custody.md`](attested-custody.md).

## Profiles

One agent can serve several pools, on one network or several. Each pool is a
profile in `kes_agent.profiles` with:

- `name`: 1-64 characters, starting with an ASCII letter or digit and followed
  by ASCII letters, digits, `.`, `_` or `-`, unique in the agent;
- its own `cold_vkey_file` or `cold_vkey_hex`;
- its network's `system_start`, `slot_length` (default 1),
  `slots_per_kes_period`, `max_kes_evolutions` (default 62) and
  `max_clock_skew` (default `5s`);
- its own `guard_file`. Two profiles may not share a guard file.

Each profile has its own staged and active KES key, operational certificate,
evolution schedule, period floor and last signed slot, and its own lock. A
refusal in one profile, such as a second header for a signed slot, does not
affect another.

The `sign` service routes each header to a profile by its issuer key (the
pool's cold key) and the KES key named by its operational certificate. One
cold key may be used on several networks; the KES key tells those profiles
apart. A header that matches no profile is refused. `serve-key` mode takes
exactly one profile, since a producer subscribes to one key. On the attested
listener, each session is bound to one profile. With more than one profile,
the attestation request selects it with its optional `kes_vkey` and `profile`
fields (see the protocol document), and the session then signs only headers
that route to that profile. The local socket still routes by header across
every profile.

Control commands take the profile name. With one profile it may be omitted,
and `info` without a name lists every profile.

A configuration without `profiles` serves one profile named `default` from the
single-pool settings (`cold_vkey_file`, `system_start`, `guard_file` and so
on), and its existing guard file is that profile's state. Setting `profiles`
together with those single-pool settings is refused at startup, as is a
top-level `slot_length` or `max_kes_evolutions` other than its default.

## Sockets

Two Unix-domain sockets, each with its own independent mode (default `0600`,
owner-only):

- **service socket** (`service_socket`, mode `service_socket_mode`) - the
  block producer connects here.
- **control socket** (`control_socket`, mode `control_socket_mode`) -
  operator key management. Can drop/install keys; keep this owner-only.

Access is governed purely by filesystem permissions - do not expose either
socket over a network. A pathname Unix-socket client needs *write* permission
on the socket itself, plus *execute* (search) permission on every parent
directory; read access alone is not sufficient. There are two supported ways
for the block producer (a different UID) to reach the service socket:

- Run the producer and the agent under the same UID, or
- Add the producer's user to the agent's group and set
  `service_socket_mode: "0660"`.

Never apply the same widening to `control_socket_mode` - doing so would let
the producer's group drop or install KES keys. Keep it at the owner-only
default `0600` regardless of how `service_socket_mode` is configured.

## Attested remote signing

Sign mode can additionally listen on `attested_listen_address` for a remote
Dingo producer. This listener speaks `bursa-attested-kes/1`. It never
offers serve-key mode or control commands. The local control socket remains the
only route for staging, installing, or dropping keys.

Before accepting a header request, Dingo sends a fresh 32-byte challenge. With
the `nitro` or `confidential-space` provider, the agent asks its workload-local
provider adapter for evidence that commits to the
challenge, pool cold verification key, active KES verification key, installed
operational certificate, and active period. Dingo verifies that evidence with
the pinned Nitro PCR policy or Confidential Space image policy described in
[`attested-custody.md`](attested-custody.md). Provider failure, a wrong nonce or
provider, a failed measurement, or a failed client certificate (where the agent requires one) closes the
connection before signing is available.

The provider adapter is configured by `attester_address`. It accepts the
protocol binding at `POST /v1/attest` over HTTPS, loopback HTTP, or a Unix
socket. Static evidence is insufficient because every connection has a fresh
challenge.

### Listener transport modes

The agent supports three modes. Each authenticates a different thing at the
agent itself; transport security can also be provided outside the agent, for
example by a sidecar or the network.

| Mode | Configuration | Authenticated at the agent |
| --- | --- | --- |
| TLS 1.3 with client certificates | `attested_tls_cert_file`, `attested_tls_key_file`, `attested_client_ca_file` | The agent to the client by its server certificate; the client to the agent by a certificate issued by the CA. |
| TLS 1.3, server authentication only | `attested_tls_cert_file`, `attested_tls_key_file` | The agent to the client. No client certificate is requested. |
| Plain TCP | `attested_plaintext: true` | Nothing at the transport. |

`attested_plaintext` cannot be combined with the TLS certificate, key or client
CA files; the agent refuses to start. All modes speak the same protocol: hello,
the attestation exchange, then sign frames. The agent logs which mode it is
serving at startup.

### none provider

Without platform evidence, set `attestation_provider: "none"`. There is no
attester and `attester_address` must be unset. The agent answers the challenge
with an empty `attestation`. The provider describes evidence only: it provides
no workload measurement, so use `nitro` or `confidential-space` where a
measured workload is required. Transport authentication is independent of the
provider. A client may pin the agent's server certificate public key (SHA-256
of its SubjectPublicKeyInfo) and the agent may require client certificates;
both are options of the client and the agent. Compute the pin with:

```sh
openssl x509 -in server.pem -pubkey -noout | openssl pkey -pubin -outform der | openssl dgst -sha256 -r | cut -d' ' -f1
```

At startup the agent logs the same value as `server_spki_sha256` when it
serves TLS (message "attested KES server certificate public key"). `nitro` and
`confidential-space` are unchanged and still require `attester_address`. With
`attested_listen_address` set and no provider configured, the agent refuses to
start; without the attested listener no provider is needed.

## Key lifecycle (control socket)

1. **`gen-staged-key`** - the agent generates a fresh staged KES key pair and
   returns its verification key.
2. Issue an operational certificate for that KES vkey **offline** with the pool
   cold key (cardano-cli or `bursa signer` `type: opcert`). The cold key stays
   in its own custody.
3. **`install-key`** - hand the agent the opcert (CBOR). The agent verifies the
   opcert's cold signature against the configured cold verification key,
   confirms it commits to the staged/active KES vkey, and checks the KES period
   before promoting the staged key to active and serving it. **The agent never
   issues an opcert.**
4. **`drop-key`** - drop `active`, `staged`, or `all` key material.
5. **`info`** - status snapshot (active period/start/end, current period,
   guard floor, exhaustion, staged/active vkeys).

## Period guard

The agent enforces a monotonic non-decreasing floor on the KES period it will
serve or sign for, protecting against re-serving a superseded period after a
clock jump, restart, or stale key re-install - a belt-and-suspenders complement
to KES forward security. A period strictly below the floor is refused; a period
equal to the floor is allowed (a producer signs many headers within one period).
The floor is persisted to `guard_file` via an atomic temp-file + rename write.
Each profile has its own guard file and floor.
`guard_file` is required unless a shared guard store is configured (below);
the daemon refuses to start without a durable path.
In `sign` mode, requests for a period later than the agent's wall-clock current
period are rejected before key evolution or guard persistence. So is a header
whose slot is ahead of the agent's current slot by more than `max_clock_skew`
(a Go duration, default `5s`, five slots at a one-second `slot_length`):
recording it would refuse every earlier slot until the clock reached it. Keep
the agent's and the producers' clocks synchronised to well within that
allowance.

In `sign` mode the guard also records the slot and a SHA-256 of the body of the
last header signed, in the same write as the floor. The agent signs at most one
header body per slot and never an older slot: the identical body may be signed
again (a retry), but a different body for a signed slot or a lower slot is
refused. Several producers can therefore share one agent for a pool, and the
first header signed for a slot wins. The record survives restarts and key
installs, since slots are absolute. A guard file from an earlier version loads
with no slot record, so slots signed before the upgrade are not covered: a
header for a slot the earlier version already signed is accepted even with a
different body until a higher slot has been recorded after the upgrade.
Each refusal is counted in
`bursa_kesagent_slot_guard_refusals_total` with a `reason` of `equivocation`
(a different body for a signed slot) or `rollback` (a lower slot); both
series start at 0 for every profile.

While it runs, the agent holds an exclusive lock on `<guard_file>.lock`, a file
next to the guard file that it creates if needed and leaves in place on exit.
A second agent process started on the same guard file fails at startup with a
"guard file is locked" error. The lock is released when the agent exits. It
uses `flock` and is not taken on platforms without it (Windows, AIX). The guard
file's directory must exist at startup.

A missing or empty guard file loads with no floor and no slot record. That is
expected on a first start, so the agent still starts, but it logs a warning
naming the file and sets `bursa_kesagent_guard_fresh` to 1 for that profile.
On any later start it means the record of signed slots was lost (for example a
wiped volume), and the agent could sign a second header for a slot it already
signed; alert on this gauge. Since the gauge is also 1 on a first start,
silence that alert for a profile's first deployment.

For restart recovery, preserve the guard on durable storage available only to
the approved workload measurement, then stage and install a key whose current
period is at or above that floor. A replacement workload must use that same
floor or a newly certified KES key. Do not run active and standby agents from
independent guard copies.

### Shared guard store (PostgreSQL)

Several agent replicas can share one guard through PostgreSQL instead of guard
files. Without `store` the agent uses guard files exactly as described above.

```yaml
kes_agent:
  store:
    type: "postgres"          # default "file": each profile's guard_file
    dsn_env: "KESAGENT_PG_DSN" # environment variable holding the DSN
```

With `type: postgres`, leave `guard_file` unset (the agent refuses both). The
DSN is read only from the variable `dsn_env` names. A non-loopback host
requires `sslmode=verify-full`; a Unix socket or loopback host does not. The
agent uses the signer's watermark tables (`signer_watermark` and
`signer_counter_watermark`) and creates them if they do not exist. Its records
are keyed by the hash of the pool cold verification key and scoped by the
profile's network (`system_start`), so one cold key on several networks keeps
separate records.

- The KES period floor is one shared non-decreasing record: a period below it
  is refused on every replica.
- Each signed slot is one shared record of its header body. The first body
  recorded for a slot wins on every replica; the identical body may be signed
  again (a retry); a different body is refused as an equivocation. Two
  replicas can never both sign different headers for one slot.
- Refusing a slot older than the last one signed is per replica, from the
  replica's own memory, and starts empty on each start.

The first start against an empty store has no floor, so the agent logs a
warning and sets `bursa_kesagent_guard_fresh` to 1, as for a missing guard
file. Moving from guard files to the store does not copy the file's floor.
A database error refuses the signature; it is not counted as a slot-guard
refusal.

### Shared KES key (sealed with age)

With the PostgreSQL store, the replicas can also share each profile's KES key,
so any replica can sign for any profile. Without these settings each replica
keeps its own key in memory only, as before.

```yaml
kes_agent:
  store:
    type: "postgres"
    dsn_env: "KESAGENT_PG_DSN"
    age_recipients: ["age1..."]             # seal staged keys to these
    age_identity_file: "/etc/bursa/age.txt" # unseal installed keys with these
    key_poll_interval: "10s"                # optional, default 10s
```

`age_recipients` and `age_identity_file` are set together and only with
`type: postgres`. Like other secret key files, `age_identity_file` is refused
when group or other users can access it. The keys live in the `kes_agent_key` table, created on first
use, with at most one staged and one installed key per pool cold key and
network (the same identity the guard records use).

- `gen-staged-key` on any replica generates the key, seals it with age to
  `age_recipients` and stores it as the staged key, replacing any staged
  before. It refuses a key that this replica's own identity cannot open.
- `install-key` on any replica checks the opcert against the stored staged key
  and the cold key as before, unseals the key, and marks it installed in one
  transaction. If two replicas install at once, one install wins; the other
  gets an error unless it installed the very same opcert.
- Every replica loads the installed key at startup, before its sockets open,
  and checks for a newly installed one every `key_poll_interval`. It re-checks
  the opcert against the cold key, unseals the key, evolves it to the current
  KES period and signs with it. Until a replica has loaded the key it refuses
  signs for that profile, and the error names why (for example, an identity
  the key was not sealed to). A replica that misses an install keeps signing
  with its previous key until its next poll.
- `drop-key` stays local: it wipes this replica's copy and leaves the stored
  records alone. The replica does not reload the dropped key until a new key
  is installed or it restarts.

The stored key is sealed at the period it was generated at and is not
re-sealed as it evolves. It is at rest in the database and in every backup of
it, and anything holding the age identity can read it. The stored copy can
sign for every period the key covers, including periods the replicas have
already evolved past, so it has no KES forward security. Unsealing goes through age's own buffers, which
the agent cannot wipe; the agent wipes its own copies and keeps the key in
locked memory as before.

### Running replicas

1. Give every replica the same profiles and the same `store` settings, except
   `age_identity_file`, which names that replica's own identity. Replicas can
   each have their own identity, as long as every one is listed in
   `age_recipients` on every replica, since a key is sealed on whichever
   replica runs `gen-staged-key`. A replica whose identity a key was not
   sealed to cannot load it and reports not ready (see
   [Health and metrics](#health-and-metrics)).
2. Start the replicas. With no installed key yet, each one starts, refuses
   signs for that profile and stays ready, so a pool added to a running set of
   replicas does not take them out of service for the pools they already sign
   for.
3. Run `gen-staged-key` on any one replica, issue the opcert offline as in
   [Key lifecycle](#key-lifecycle-control-socket), and run `install-key` with
   it on any replica. The others load the key within `key_poll_interval`.
4. Rotate the same way. Until a replica's next poll it keeps signing with the
   previous key and opcert.

Point every replica at one database. PostgreSQL replication and failover are
outside Bursa: a failover must keep every committed row, and replicas must
never be split across independent databases, or two of them could each sign a
different header for the same slot.

A replica that goes unready is only removed from new connections by whatever
routes to it (a load balancer or a Kubernetes Service). Producer sessions that
are already open stay on it until they reconnect. For a profile whose new key
it cannot load, it keeps signing with the key it holds, or refuses signs with
the reason when it holds none.

## Locked memory

The agent attempts to lock the KES signing key buffer with `mlock` so that
buffer cannot be swapped to disk. This requires a sufficient `RLIMIT_MEMLOCK`;
the provided systemd unit sets `LimitMEMLOCK`. If the platform does not support
`mlock` or the lock request is refused, the agent logs a warning and continues
with unlocked memory, which may be swapped to disk.

## Slot / period configuration

Absolute KES periods are derived from the current slot and
`slots_per_kes_period`. The current slot is counted at `slot_length` from an
anchor: `shelley_start_slot` at `shelley_start_time` when set, otherwise slot 0
at `system_start`. Networks whose Byron era used 20-second slots need the
Shelley anchor, or the agent runs ahead of the chain and refuses every header:
mainnet is slot 4492800 at `2020-07-29T21:44:51Z`, preprod is slot 86400 at
`2022-06-21T00:00:00Z`. Preview has no Byron era and needs none. Set these to match the target
network (e.g. mainnet `slots_per_kes_period: 129600`, `max_kes_evolutions: 62`).
The scheduler ticks every `evolve_interval` (default `1m`) to evolve the key as
periods advance.

## Health and metrics

When `metrics.port` is non-zero the agent serves, on the dedicated metrics
listener:

- `GET /healthz` - liveness: 200 while the process runs.
- `GET /readyz` - 200 when the agent is ready to sign, 503 when it is not.
  Without a `store` it is always ready. With a PostgreSQL store it is not
  ready while the database does not answer a test write within three seconds,
  or while any profile has an installed key in the shared key store that the
  replica could not read or load on its latest poll. A profile with no
  installed key does not make it unready.
- `GET /metrics` - Prometheus metrics.

The configured address must be a loopback host without a port; it defaults to
`127.0.0.1` so a local collector can scrape it without exposing KES activity
on a network interface. Setting `metrics.port` to 0 also disables the health
endpoints.

Because the listener is loopback only, an HTTP probe from outside the host or
pod cannot reach it. `bursa kes-agent ready --config <file>` reads the same
config file, queries `/readyz` and exits 0 when the agent is ready and 1
otherwise, so it can run as an exec readiness probe:

```yaml
readinessProbe:
  exec:
    command: ["bursa", "kes-agent", "ready", "--config", "/etc/bursa/config.yaml"]
  periodSeconds: 10
  timeoutSeconds: 6
```

Every metric except `bursa_kesagent_service_connections` carries a `profile`
label, which is `default` for a single-pool configuration.

| Metric | Meaning |
|--------|---------|
| `bursa_kesagent_served_keys_total` | Keys pushed to producers |
| `bursa_kesagent_sign_total` | Sign operations (sign mode) |
| `bursa_kesagent_evolutions_total` | KES evolutions performed |
| `bursa_kesagent_current_period` | Current absolute KES period |
| `bursa_kesagent_exhausted` | Active key exhausted (1/0) |
| `bursa_kesagent_service_connections` | Active service-socket connections |
| `bursa_kesagent_slot_guard_refusals_total` | Headers refused by the slot guard, by `reason` (`equivocation`, `rollback`) |
| `bursa_kesagent_guard_fresh` | Guard file was missing or empty at startup (1/0) |

## Shutdown

`SIGINT` / `SIGTERM` stops the listeners and removes the socket files.
