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
Dingo producer. This listener speaks `bursa-attested-kes/1` and requires TLS
1.3 with a client certificate issued by `attested_client_ca_file`. It never
offers serve-key mode or control commands. The local control socket remains the
only route for staging, installing, or dropping keys.

Before accepting a header request, Dingo sends a fresh 32-byte challenge. The
agent asks its workload-local provider adapter for evidence that commits to the
challenge, pool cold verification key, active KES verification key, installed
operational certificate, and active period. Dingo verifies that evidence with
the pinned Nitro PCR policy or Confidential Space image policy described in
[`attested-custody.md`](attested-custody.md). Provider failure, a wrong nonce or
provider, a failed measurement, or a failed client certificate closes the
connection before signing is available.

The provider adapter is configured by `attester_address`. It accepts the
protocol binding at `POST /v1/attest` over HTTPS, loopback HTTP, or a Unix
socket. Static evidence is insufficient because every connection has a fresh
challenge.

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
`guard_file` is required; the daemon refuses to start without a durable path.
In `sign` mode, requests for a period later than the agent's wall-clock current
period are rejected before key evolution or guard persistence.

For restart recovery, preserve the guard on durable storage available only to
the approved workload measurement, then stage and install a key whose current
period is at or above that floor. A replacement workload must use that same
floor or a newly certified KES key. Do not run active and standby agents from
independent guard copies.

## Locked memory

The agent attempts to lock the KES signing key buffer with `mlock` so that
buffer cannot be swapped to disk. This requires a sufficient `RLIMIT_MEMLOCK`;
the provided systemd unit sets `LimitMEMLOCK`. If the platform does not support
`mlock` or the lock request is refused, the agent logs a warning and continues
with unlocked memory, which may be swapped to disk.

## Slot / period configuration

Absolute KES periods are derived from the Shelley genesis `system_start`,
`slot_length`, and `slots_per_kes_period`. Set these to match the target
network (e.g. mainnet `slots_per_kes_period: 129600`, `max_kes_evolutions: 62`).
The scheduler ticks every `evolve_interval` (default `1m`) to evolve the key as
periods advance.

## Metrics

When `metrics.port` is non-zero the agent serves Prometheus metrics at
`/metrics` on the dedicated metrics listener. The configured address must be
a loopback host without a port; it defaults to `127.0.0.1` so a local collector can scrape it without
exposing KES activity on a network interface.

| Metric | Meaning |
|--------|---------|
| `bursa_kesagent_served_keys_total` | Keys pushed to producers |
| `bursa_kesagent_sign_total` | Sign operations (sign mode) |
| `bursa_kesagent_evolutions_total` | KES evolutions performed |
| `bursa_kesagent_current_period` | Current absolute KES period |
| `bursa_kesagent_exhausted` | Active key exhausted (1/0) |
| `bursa_kesagent_service_connections` | Active service-socket connections |

## Shutdown

`SIGINT` / `SIGTERM` stops the listeners and removes the socket files.
