# Bursa KES Agent Wire Protocol

This document specifies the Unix-domain-socket protocol spoken by the bursa KES
agent (`bursa kes-agent`) so a client (e.g. a dingo block producer) can
implement it. It is transcribed from `internal/kesagent/protocol.go` and
`internal/kesagent/control.go` (introduced in #675).

The agent exposes two sockets:

- **service socket** - the block producer connects here to receive or use the
  KES signing key.
- **control socket** - operational key management (generate / install / drop /
  info).

Both sockets speak the same framing and handshake.

## Framing

    frame   = uint32(len, big-endian) || payload
    payload = JSON object (UTF-8)

- The length prefix is a 4-byte big-endian unsigned integer giving the payload
  byte count.
- Maximum payload length is **1 MiB** (`1 << 20`). Larger frames are rejected.
- A zero-length frame is a protocol error.
- `[]byte` fields are base64-encoded (standard `encoding/json` behavior).

## Handshake

Immediately after a client connects, the server sends a `Hello` frame:

```json
{ "protocol": "bursa-kes-agent/1", "mode": "serve-key" }
```

- `protocol` is always `bursa-kes-agent/1`. A client MUST verify this string
  before proceeding.
- `mode` is `serve-key` or `sign` on the service socket. (The control socket
  also sends a Hello; treat its mode field as informational.)

## Service socket - `serve-key` mode

After the Hello, and whenever the active key becomes available, evolves, or is
(re)installed, the server pushes a `KeyPush` frame. The client only reads; it
sends nothing.

```json
{
  "type": "key_push",
  "period": 512,
  "depth": 6,
  "kes_sign_key": "<b64 raw KES secret key bytes>",
  "kes_vkey": "<b64 32-byte KES verification key>",
  "opcert": "<b64 CBOR operational certificate>"
}
```

| Field          | Meaning                                            |
|----------------|----------------------------------------------------|
| `type`         | Always `key_push`.                                 |
| `period`       | Absolute KES period of the delivered key.          |
| `depth`        | KES tree depth (6 for the standard Sum6 KES).      |
| `kes_sign_key` | Raw KES secret key bytes (base64).                 |
| `kes_vkey`     | 32-byte KES verification key (base64).             |
| `opcert`       | CBOR operational certificate (base64).             |

## Service socket - `sign` mode

After the Hello the client sends `SignRequest` frames; the server replies with
one `SignResponse` per request. The KES key never leaves the agent.

Client -> server:

```json
{ "type": "sign_request", "period": 512, "message": "<b64>" }
```

Server -> client:

```json
{ "type": "sign_response", "period": 512, "signature": "<b64>", "error": "" }
```

`error` is non-empty (and `signature` absent) when signing is refused, e.g. a
period rollback or an exhausted key.

## Control socket

Request/response. The client sends a `Command` frame; the server replies with a
`Reply` frame.

### Commands

**gen-staged-key** - generate a fresh staged KES key pair, returning its vkey so
the operator can issue an opcert for it (offline, with the cold key).

```json
-> { "command": "gen-staged-key" }
<- { "ok": true, "kes_vkey": "<b64>", "info": { ... } }
```

**install-key** - install an operational certificate. The agent verifies the
opcert's cold signature against the configured cold verification key, confirms
it commits to the staged/active KES vkey, and checks the KES period before
promoting the staged key to active and serving it. The agent never issues an
opcert.

```json
-> { "command": "install-key", "opcert": "<b64 CBOR opcert>" }
<- { "ok": true, "info": { ... } }
```

**drop-key** - drop key material.

```json
-> { "command": "drop-key", "target": "active" }   // "active" | "staged" | "all"
<- { "ok": true, "info": { ... } }
```

**info** - status snapshot.

```json
-> { "command": "info" }
<- { "ok": true, "info": { ... } }
```

Unknown commands return `{ "ok": false, "error": "unknown command \"...\"" }`.

### Reply object

```json
{
  "ok": true,
  "error": "",
  "kes_vkey": "<b64, gen-staged-key only>",
  "info": { ... }
}
```

### AgentInfo (`info` field)

| Field               | Meaning                                                        |
|---------------------|----------------------------------------------------------------|
| `version`           | Agent version string.                                          |
| `mode`              | `serve-key` or `sign`.                                         |
| `has_active_key`    | Whether an active key is installed.                            |
| `active_period`     | Current absolute KES period of the active key.                 |
| `active_start`      | Absolute KES period the opcert was issued for.                 |
| `active_end`        | Last absolute KES period the key can serve.                    |
| `active_kes_vkey`   | 32-byte active KES vkey (base64; null if none).                |
| `staged_kes_vkey`   | 32-byte staged KES vkey (base64; null if none).                |
| `exhausted`         | Active key has run out of evolutions.                          |
| `current_period`    | Agent's computed current KES period.                           |
| `monotonic_floor`   | Period-guard floor (lowest period the agent will serve/sign).  |
| `floor_initialized` | Whether the guard floor is set.                                |

## Operational certificate CBOR

Operational certificates use the canonical node envelope, identical to
cardano-node / bursa:

    [[kes_vkey, issue_number, kes_period, cold_signature], cold_vkey]

The outer array has exactly two elements: the inner 4-tuple and the 32-byte
cold verification key.

## Period guard

The agent enforces a monotonic non-decreasing floor on the KES period it will
serve or sign for. A period strictly below the floor is refused
(`ErrPeriodRollback`); a period equal to the floor is allowed (a producer signs
many headers within a single period). The floor is persisted to a small JSON
file with an atomic temp-file + rename write (`kes_agent.guard_file`) so it
survives restarts, clock jumps, and stale key re-installs.
