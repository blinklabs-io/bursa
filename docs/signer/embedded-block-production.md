# Embedded Dingo block production

Dingo embeds the Bursa root library for Cardano key-envelope and operational
certificate decoding. Its remote block-production boundary is the Bursa KES
agent Unix socket. Bursa wallet storage and signer custody backends do not
automatically become Dingo forging-key backends.

## Supported custody split

| Material | Dingo source | Bursa integration | Private material location |
| --- | --- | --- | --- |
| Pool cold key | Not loaded by Dingo | `bursa signer` issues operational certificates with an `opcert` request | The configured signer backend |
| VRF signing key | `--shelley-vrf-key` | Bursa decodes the key envelope | Dingo process memory |
| KES signing key | `--shelley-kes-key` or `--shelley-kes-agent-socket` | `bursa kes-agent` in `serve-key` or `sign` mode | Dingo in `serve-key`; the agent in `sign` |
| Operational certificate | `--shelley-operational-certificate` | The KES agent validates the same certificate before accepting a staged key | Public certificate in both processes |

`sign` is the remote-equivalent KES custody mode: Dingo sends a Praos header
body over a filesystem-protected Unix socket and receives a KES
signature. The KES private key never enters Dingo. `serve-key` exercises the
same protocol and automatic evolution updates, but sends the current private
KES key to Dingo and therefore does not preserve that isolation.

The VRF key is not supported by the remote signer or KES agent. VRF uses
ECVRF-ED25519-SHA512-Elligator2, while the signer backends provide PureEdDSA
signatures for transaction, CIP-8, and operational-certificate requests.
Configure the VRF key as a local secret file with restrictive permissions.

The operational certificate is public. Dingo keeps a local copy to pin the
pool cold key and certificate fields it expects from the KES agent. The pool
cold private key can remain remote: issue the certificate through
`bursa signer` with a pool key held by one of the supported backends below.

## Backend applicability

| Backend or mode | Pool cold opcert signing | KES header signing | VRF proving |
| --- | --- | --- | --- |
| Vault Transit | Yes; key stays in Vault | No | No |
| PKCS#11 | Yes; key stays in the token | No | No |
| Nitro / Confidential Space | Yes; key stays in the attested workload | No | No |
| SOPS + Secret Manager | Yes; key is decrypted into the signer process | No | No |
| Software / file | Yes; development use | No | No |
| KES agent `sign` | No | Yes; key stays in the agent | No |
| KES agent `serve-key` | No | Yes; key is sent to Dingo | No |
| Wallet storage (`file`, SQLite, GCP, AWS) | No | No | No |

AWS Secrets Manager and GCP Secret Manager wallet storage persist Bursa wallet
records. They are separate from `signer.backends` and are not consulted by the
Dingo forging path. SOPS is a signer backend only when configured under
`signer.backends`.

## Rotation and reload

The KES agent generates a staged key, accepts an operational certificate that
binds it to the pool cold key, evolves it forward to the current period, and
persists a monotonic period floor. In `sign` mode Dingo reconnects for each
signing request. In `serve-key` mode the long-lived connection receives a new
key push after evolution or installation. Dingo validates each update against
the locally pinned pool identity and operational certificate lifetime before it
can forge with it.

Generating a new staged KES key is certificate rotation, not ordinary period
evolution. Issue a higher-counter certificate with the remote pool cold key,
install it through the owner-only control socket, and confirm `info` reports the
new issue number and certificate.

## Operator-facing failures

| Condition | Bursa or Dingo error |
| --- | --- |
| Vault token variable missing | `vault token env var <name> is empty` |
| Vault rejects an expired or invalid token | `vault key "<name>": ... Code: 403` |
| Configured remote cold key is absent | `vault key "<name>": transit key not found` or signer `not_found` |
| KES agent has no installed key | `kesagent: no active KES key installed` |
| Dingo cannot reach the agent | `kesagent: dial ...` followed by the socket error |
| Socket protocol or mode differs | `kesagent: protocol mismatch` or `kesagent: mode mismatch` |
| Certificate names another cold or KES key | `kesagent: opcert cold vkey does not match configured cold vkey` or `kesagent: opcert KES vkey does not match the staged key` |
| Certificate is outside its KES lifetime | `kesagent: opcert expired` |
| Requested period is behind the durable floor | `kesagent: KES period rollback refused` |
| Requested period is ahead of wall clock | `kesagent: future KES period refused` |

These failures stop certificate issuance, key installation, or header signing.
The block producer does not fall back to a different key source.

## Reproducible validation

`TestEmbeddedBlockProducerRemoteCustody` runs without cloud credentials. It
uses the production Vault Transit client against a loopback protocol server to
cold-sign an operational certificate, installs the resulting KES key into the
real agent, builds a Praos header with a verifiable VRF proof, and signs the
header through the real KES agent socket. It advances one KES period, reconnects
as Dingo sign mode does, and verifies the evolved signature. The companion
failure test pins missing and rejected Vault credentials, a missing KES key,
and an expired operational certificate.

Run the scenario with:

```sh
go test -race ./internal/signer -run '^TestEmbeddedBlockProducerRemoteCustody'
```

This scenario validates the Bursa side of the boundary. Dingo owns block
assembly, leader selection, ledger admission, and live DevNet forging.
