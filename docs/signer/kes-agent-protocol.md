# Bursa KES Agent Wire Protocol

This document specifies the Unix-domain-socket protocol spoken by the bursa KES
agent (`bursa kes-agent`) so a client (e.g. a dingo block producer) can
implement it. The frame types, constants and framing are defined in the public
Go package `github.com/blinklabs-io/bursa/kesagent/wire` (`kesagent/wire`),
which clients should import rather than copy; golden frames are in
`kesagent/wire/testdata/frames`. Agent behavior is in
`internal/kesagent/protocol.go` and `internal/kesagent/control.go`.

The agent exposes two sockets:

- **service socket** - the block producer connects here to receive or use the
  KES signing key.
- **control socket** - operational key management (generate / install / drop /
  info).

Both sockets speak the same framing and handshake.

An optional remote sign listener uses the same framing over mutually
authenticated TLS 1.3. It speaks the attested extension below and exposes
neither control commands nor serve-key mode.

## Framing

    frame   = uint32(len, big-endian) || payload
    payload = JSON object (UTF-8)

- The length prefix is a 4-byte big-endian unsigned integer giving the payload
  byte count.
- Maximum payload length is **1 MiB** (`1 << 20`). Larger frames are rejected.
- A zero-length frame is a protocol error.
- `[]byte` fields are base64-encoded (standard `encoding/json` behavior).
- Sign and control clients must deliver each complete inbound frame within 10
  seconds after the server starts waiting for it. The server closes idle or
  stalled connections; clients must reconnect after such a close.
- Clients must drain each outbound frame within 10 seconds so a blocked writer
  cannot retain a connection slot indefinitely.
- Serve-key clients send no inbound frames, so their long-lived subscriptions
  are not subject to the inbound-frame deadline.

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
{ "type": "sign_request", "period": 512, "message": "<b64>", "profile": "pool-a" }
```

`profile` is optional. The agent routes a header to the profile whose cold
verification key is the header's issuer key and whose active KES vkey is the
one its operational certificate names. When `profile` is present, that must be
the profile the header routes to; otherwise the request is refused with `header
belongs to a different profile`. A header that matches no profile is refused
with `no such profile`, and one that matches more than one profile with
`request does not select exactly one profile`. An agent with a single profile
does not route: it checks the header against that profile, so a header for
another pool is refused with that check's error, such as `issuer key is not
this pool's cold key`.

Server -> client:

```json
{ "type": "sign_response", "period": 512, "signature": "<b64>", "error": "" }
```

`message` must be a Praos (Babbage/Conway) block header body, CBOR-encoded
exactly as it is signed, and nothing else. The agent refuses the request, with
the guard and key untouched, unless:

- the message decodes as a header body with no trailing bytes;
- the header's slot divided by `slots_per_kes_period` equals `period`;
- the issuer verification key equals the profile's cold verification key;
- the header's operational certificate carries the active KES vkey, the
  installed issue counter, the installed certificate start period, and the
  installed cold-key signature.

The agent then checks the header's slot against the last header it signed,
which it keeps in `guard_file`, or in the shared store when `store.type` is
`postgres`. A slot above it is recorded durably before the signature is
returned. The same slot is signed again only for the identical header body. A
producer that sends a header and gets no signature back, because the reply was
lost or because signing returned an error other than a refusal below, keeps
that body and retries it unchanged: the slot may already be recorded, and a
different body for it is then refused. A different body for a recorded slot
(`a different header was already signed for this slot`) is refused. A lower
slot in the same KES period is refused with `header slot below the last signed
slot refused`; a lower slot in an earlier period can be refused first with
`requested KES period is in the past for the active key` or a period rollback.
With a shared store, the per-slot record is shared by every replica, but the
last signed slot is held per replica in memory and starts empty on each start.
Producers that share an agent, or agents that share a store, therefore cannot
publish two blocks for the pool in one slot: the first header recorded for a
slot wins.

`error` is non-empty (and `signature` absent) when signing is refused, e.g. a
message that is not a matching header body, a second header for a signed slot,
an older slot, a period rollback, or an exhausted key. Header bodies of the pre-Babbage (TPraos) eras are refused.

The `type` field is mandatory and must equal `sign_request`. A frame with a
different or missing type is refused even when its other fields form a valid
header request.

## Attested remote sign extension

The remote server hello uses protocol `bursa-attested-kes/1` and mode `sign`.
The listener serves TLS 1.3 or, with `attested_plaintext`, plain TCP. It
requires a TLS client certificate only when `attested_client_ca_file` is set.
A TLS connection must complete the handshake, with a verified client
certificate where one is required, within 10 seconds. Connections still in the
handshake have their own budget, 64 in total and 4 per source (an IPv4 address
or an IPv6 /64). When a budget is full, a new connection closes the oldest
pending handshake from its source, or else the oldest overall, so a connection
that stalls in the handshake cannot hold its slot against a reconnecting
producer. Handshaking connections never occupy the slots that authenticated
connections use.
After the hello, and after client-certificate authentication where it is
required, Dingo sends one challenge before any sign request:

```json
{ "type": "attestation_request", "protocol": "bursa-attested-kes/1",
  "nonce": "<32 fresh random bytes>" }
```

The request may also carry two optional fields that select which profile the
response attests: `kes_vkey` (the 32-byte KES verification key) and `profile`
(a profile name). Old clients send neither, and agents ignore fields they do
not know. Selection:

- with `kes_vkey`, the profile whose active key has that verification key; if
  `profile` is also set it must name that profile, otherwise the response
  carries an `error`;
- with only `profile`, the named profile;
- with neither, the sole profile. With several profiles this is ambiguous and
  the response carries an `error`.

An unknown profile or a `kes_vkey` that matches no active key also sets
`error`. Selection picks only the key state in the response. It does not bind
the connection: sign requests keep routing by header across all profiles.

The workload answers:

```json
{ "type": "attestation_response", "protocol": "bursa-attested-kes/1",
  "nonce": "<same 32 bytes>", "provider": "nitro",
  "kes_vkey": "<32 bytes>", "opcert": "<CBOR operational certificate>",
  "period": 512, "attestation": "<provider evidence>" }
```

The evidence commits to:

```text
sha256("bursa-attested-kes/1" ||
       len(nonce) || nonce ||
       len(cold_vkey) || cold_vkey ||
       len(kes_vkey) || kes_vkey ||
       len(opcert) || opcert ||
       uint64_be(period))
```

Lengths are unsigned 64-bit big-endian values. Dingo admits the service only
after the nonce and configured provider match, the operational certificate is
the expected certificate, and the evidence passes the provider check: for
`nitro` or `confidential-space` the corresponding verifier accepts the evidence
and binding, and for `none` the evidence is empty. A failure response sets
`error`, omits evidence, and is followed by connection close. Successful
attestation is valid only for that connection, whatever its transport.

After admission, the connection accepts the ordinary typed `sign_request`
frames above. KES private state, evolution, period authorization, operational
certificate validation, and header signing stay inside the workload.

The workload-local provider adapter accepts:

```json
POST /v1/attest
{ "protocol": "bursa-attested-kes/1", "binding": "<32 bytes>" }
```

It returns the same protocol and binding plus `attestation`. Static or replayed
evidence fails because each Dingo connection supplies a fresh nonce.

With provider `none` there is no adapter and `attestation` is empty. The
client accepts empty evidence only when it expects `none`, and refuses
non-empty evidence for it; every other provider refuses empty evidence. The
nonce, opcert and period checks still apply. The protocol itself measures
nothing; transport authentication, such as a client pinning the SHA-256 SPKI
fingerprint of the agent's TLS server certificate, is separate from the
provider.

## Control socket

Request/response. The client sends a `Command` frame; the server replies with a
`Reply` frame.

Every command takes an optional `profile` field naming the profile it acts on.
It may be omitted when the agent has one profile. With several, a key command
without it is refused with `request does not select exactly one profile`, and
`info` without it returns every profile in `profiles`.

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
-> { "command": "info", "profile": "pool-a" }
<- { "ok": true, "info": { ... } }
-> { "command": "info" }                       // agent with several profiles
<- { "ok": true, "profiles": [ { ... }, { ... } ] }
```

Unknown commands return `{ "ok": false, "error": "unknown command \"...\"" }`.

### Reply object

```json
{
  "ok": true,
  "error": "",
  "kes_vkey": "<b64, gen-staged-key only>",
  "info": { ... },
  "profiles": [ { ... } ]
}
```

### AgentInfo (`info` field)

| Field                 | Meaning                                                       |
|-----------------------|---------------------------------------------------------------|
| `version`             | Agent version string.                                         |
| `mode`                | `serve-key` or `sign`.                                        |
| `profile`             | Profile name (`default` for a single-pool configuration).     |
| `has_active_key`      | Whether an active key is installed.                           |
| `active_period`       | Current absolute KES period of the active key.                |
| `active_start`        | Absolute KES period the opcert was issued for.                |
| `active_end`          | Last absolute KES period the key can serve.                   |
| `active_kes_vkey`     | 32-byte active KES vkey (base64; null if none).               |
| `active_issue_number` | Opcert issue counter the agent is serving.                    |
| `active_opcert`       | Installed opcert CBOR (base64; omitted when absent).          |
| `staged_kes_vkey`     | 32-byte staged KES vkey (base64; null if none).               |
| `exhausted`           | Active key has run out of evolutions.                         |
| `current_period`      | Agent's computed current KES period.                          |
| `monotonic_floor`     | Period-guard floor (lowest period the agent will serve/sign). |
| `floor_initialized`   | Whether the guard floor is set.                               |

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
