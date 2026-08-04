# KES Agent Daemon

`bursa kes-agent` is a KES (Key Evolving Signature) agent daemon: a Go replica
of IOG's kes-agent, serving a Go block producer (dingo) rather than
cardano-node. It was introduced in #675.

The agent holds the block-production KES signing key in locked (mlock'd) secure
memory, evolves it forward-securely each KES period, and serves it to the
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
- **`sign`** - the producer sends header bytes and the agent returns
  signatures; the KES signing key never leaves the agent.

## Sockets

Two Unix-domain sockets, both created with mode `socket_mode` (default `0600`):

- **service socket** (`service_socket`) - the block producer connects here.
- **control socket** (`control_socket`) - operator key management.

Because access is governed by filesystem permissions, place the sockets in a
directory owned by the service user and readable only by the producer's user.
Do not expose them over a network; front with a Unix socket only.

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

## Locked memory

The KES signing key is held in `mlock`'d memory so it is never swapped to disk.
This requires a sufficient `RLIMIT_MEMLOCK`; the provided systemd unit sets
`LimitMEMLOCK`. On platforms without mlock support the agent degrades to
unlocked memory.

## Slot / period configuration

Absolute KES periods are derived from the Shelley genesis `system_start`,
`slot_length`, and `slots_per_kes_period`. Set these to match the target
network (e.g. mainnet `slots_per_kes_period: 129600`, `max_kes_evolutions: 62`).
The scheduler ticks every `evolve_interval` (default `1m`) to evolve the key as
periods advance.

## Metrics

When `metrics.port` is non-zero the agent serves Prometheus metrics at
`/metrics`:

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
