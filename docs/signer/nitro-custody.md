# AWS Nitro Enclave pool-cold custody

Bursa can hold a stake-pool cold key inside a measured AWS Nitro Enclave. The
host stores only an envelope-encrypted key, forwards TLS bytes to AWS KMS, and
translates the signer's existing attested HTTP protocol to gRPC over vsock.

The implementation follows the AWS [cryptographic attestation][aws-attestation]
and [KMS recipient condition][aws-kms-conditions] contracts. Its process split
follows the trust boundary in Circle's [Arc Remote Signer][arc-signer]: the KMS
client, recipient private key, data-key plaintext, pool-cold seed, and Ed25519
operation remain in the enclave.

## Runtime boundary

| Component | Responsibilities | Secret material available |
|-----------|------------------|---------------------------|
| `bursa signer` | caller authentication, policy, opcert counter watermark, response signature verification, signing each enclave request with the signer authority key | signer authority private key (`host_key_file`) |
| `bursa nitro proxy` on the parent instance | authenticate to enclave gRPC with a dedicated client certificate, read/write one existing Secrets Manager secret, fetch temporary role credentials, relay an offline provisioning authorization, bridge the signer socket to enclave gRPC, forward opaque KMS TLS bytes to the configured regional endpoint | proxy client key, temporary AWS credentials, provisioning signature and wrapped envelope |
| `bursa nitro enclave` in the EIF | require a client certificate from the proxy CA, verify provisioning against the measured image's authority key, verify the signer authority's signature and a one-time challenge on each signing request, create recipient attestation, call KMS, unwrap the data key, decrypt the cold-key seed, attest inventory, validate and sign opcert requests | RPC server key, provisioning and signer authority public keys, data key and cold key in enclave memory |

The host proxy has no operation that returns a plaintext key. The envelope in
Secrets Manager contains the pool role, public key, KMS key ARN, KMS
`CiphertextBlob`, and an AES-256-GCM ciphertext and nonce. The public metadata
is authenticated as AES-GCM additional data. A reload derives the public key
from the recovered seed and refuses a mismatch.

The host proxy socket defaults to owner-only mode. When the proxy and signer
run as separate users, put only those users in a dedicated socket group, run
the proxy with that effective group, and set `--socket-mode 0660`. Keep the
signer's `host_key_file` owner-only so the proxy cannot read it. Configure the
signer's `nitro` backend with that socket:

```yaml
backends:
  - name: "nitro-pool-cold"
    type: "nitro"
    address: "unix:///run/bursa/nitro.sock"
    host_key_file: "/etc/bursa/signer/nitro-host.skey"
    root_ca_file: "/etc/bursa/signer/aws-nitro-root.pem"
    pcrs:
      0: "<96 lowercase hex characters from the production EIF>"
```

Create a dedicated CA for the proxy identity. Create an offline Ed25519
provisioning authority and put only its 32-byte lowercase-hex public key in the
EIF. Create a separate signer host key and put its 32-byte lowercase-hex public
key in the EIF; its private key is the signer's `host_key_file` and must not be
readable by the proxy service user. The provisioning authority private key must
remain outside both the EIF and parent instance. Put the CA certificate and the
enclave server certificate and owner-only key in the EIF. Install the proxy
client certificate, its owner-only key, and the enclave server CA on the parent
for the dedicated proxy service user.

`host_key_file` uses the owner-only `ArmoryHostSigningKey_ed25519` text envelope
accepted by the attested signer backends. `signer-authority-file` is the
lowercase-hex public key corresponding to that private key.

Run `bursa nitro enclave` as the EIF entry point:

```text
bursa nitro enclave \
  --server-cert-file /etc/bursa/nitro/server.pem \
  --server-key-file /etc/bursa/nitro/server-key.pem \
  --client-ca-file /etc/bursa/nitro/proxy-ca.pem \
  --provision-authority-file /etc/bursa/nitro/provision-authority.hex \
  --signer-authority-file /etc/bursa/nitro/signer-authority.hex
```

On the parent instance run:

```text
bursa nitro proxy --enclave-cid <cid> --region <region> \
  --secret-id <existing-secret-id> --socket /run/bursa/nitro.sock \
  --socket-mode 0660 \
  --enclave-ca-file /etc/bursa/nitro/enclave-ca.pem \
  --enclave-server-name nitro-enclave.internal \
  --client-cert-file /etc/bursa/nitro/proxy.pem \
  --client-key-file /etc/bursa/nitro/proxy-key.pem
```

The proxy reads the wrapped envelope and the sealed counter state stored
beside it, and calls `Reload`. It fails before opening the signer socket if
Secrets Manager, KMS recipient decryption, envelope authentication, counter
state authentication, the expected public key, or enclave initialization
fails. The proxy reloads only at startup, so restart it after every enclave
restart; a restarted enclave holds no key, and the proxy returns errors until
its own restart repeats that recovery path.

Provisioning is explicit and writes only an existing empty secret. The proxy
refuses to replace an existing wrapped pool-cold key. Before provisioning,
the offline authority must sign `ProvisionAuthorizationBinding` for the exact
protocol version, region, KMS key ARN, and `pool` role. Store the 64-byte
signature as lowercase hex on the parent:

```text
bursa nitro proxy --provision --enclave-cid <cid> --region <region> \
  --kms-key-id <kms-key-arn> --secret-id <existing-empty-secret-id> \
  --provision-authorization-file /etc/bursa/nitro/provision-authorization.hex \
  --enclave-ca-file /etc/bursa/nitro/enclave-ca.pem \
  --enclave-server-name nitro-enclave.internal \
  --client-cert-file /etc/bursa/nitro/proxy.pem \
  --client-key-file /etc/bursa/nitro/proxy-key.pem
```

Create the secret, KMS key, role, policies, EC2 instance, and enclave outside
Bursa. Bursa does not create cloud or infrastructure resources.

The signed binding is SHA-256 over these byte strings in order:
`bursa-nitro-provision/1`, `bursa-nitro-custody/1`, the AWS region, the full
KMS key ARN, and `pool`. Each field is preceded by its decimal byte length and
a colon. The account is part of the signed ARN. The enclave verifies the
Ed25519 signature before creating a KMS client, so changing the key, account,
region, role, or protocol fails before any KMS operation. A deployment can use
the same measured authority public key for multiple explicitly signed KMS keys
without making the host or its AWS credentials an authorization source.
The enclave returns the original envelope when an accepted provisioning request
is repeated, and refuses to reload a different key while one is active. A
replayed authorization therefore cannot replace the active pool key.

## KMS recipient policy

Grant the parent instance role only the operations the enclave uses. Bind both
`kms:GenerateDataKey` and `kms:Decrypt` to recipient attestation. PCR0 is the
EIF image measurement. Bind PCR1 and PCR2 when the kernel/bootstrap and
application measurements are controlled independently; bind PCR8 when images
are signed.

```json
{
  "Effect": "Allow",
  "Principal": {"AWS": "arn:aws:iam::<account>:role/<parent-role>"},
  "Action": ["kms:GenerateDataKey", "kms:Decrypt"],
  "Resource": "<kms-key-arn>",
  "Condition": {
    "StringEqualsIgnoreCase": {
      "kms:RecipientAttestation:ImageSha384": "<PCR0>",
      "kms:RecipientAttestation:PCR1": "<PCR1>",
      "kms:RecipientAttestation:PCR2": "<PCR2>"
    }
  }
}
```

KMS denies a request without a valid recipient document or with a different
measurement. The enclave additionally refuses absent PCR0 and the all-zero PCR0
AWS emits for debug mode. The signer independently verifies the inventory's
NSM document, certificate chain, PCRs, nonce binding, and non-debug state.

The parent role needs `secretsmanager:GetSecretValue`,
`secretsmanager:DescribeSecret`, and `secretsmanager:PutSecretValue`.
`DescribeSecret` distinguishes an existing secret with no value from a missing
secret. `PutSecretValue` writes the envelope during provisioning and the sealed
counter state with every signature, so the proxy needs it while it serves. It
does not need permission to decrypt a data key without recipient attestation.

## Protocol and signing rules

The host/enclave gRPC protocol is `bursa-nitro-custody/1`. Every RPC requires
TLS 1.3 and a proxy client certificate from the enclave's dedicated client CA;
there is no plaintext or anonymous mode. Both RPC private-key files must deny
group and other access. JSON-encoded gRPC messages reject unknown fields and
trailing values. The signer-facing protocol remains
`bursa-attested-signer/1`, so the existing `KeyRef` path retains caller ACL,
policy, watermark, attestation, and returned-signature checks.

The proxy client key authorizes lifecycle, inventory, and challenge RPCs.
Signing additionally requires a fresh enclave challenge and a request signature
from the signer authority whose public key is part of the measured EIF. The
proxy can forward that authorization but cannot create another signing request.
Provisioning also requires a signature from the separate provisioning authority.
The enclave independently restricts signing to canonical pool-cold
operational-certificate payloads and maintains its nonce and issue counter
guards while the key remains loaded, and seals the counter state (see
below).

The enclave accepts only the `pool` role and `opcert` purpose, without a
workload profile. It signs the canonical 48-byte `OCertSignable` value:

```text
KES verification key (32 bytes) || issue counter (uint64 big endian) ||
KES period (uint64 big endian)
```

Requests require a fresh 32-byte nonce and one-time signer challenge. The
enclave rejects an absent or invalid signer authorization, challenge or nonce
replay, a counter below the stored one, an equal counter with a different
payload, a wrong key hash or role, malformed payloads, and unsupported
protocol versions. The signer verifies the returned Ed25519
signature before constructing the operational certificate.

The enclave seals the highest issued counter, with the SHA-256 of the exact
48-byte payload signed at it, with every signature it returns. A request at
the stored counter whose payload hashes to the stored value is signed again:
Ed25519 is deterministic, so the signature is the one already issued and
nothing new exists. Any other payload at that counter (a different KES key or
period) is refused, as is a lower counter. SHA-256 is already the enclave's
hash for the sealing key and authenticated data; the digest sits inside the
sealed record, where the host cannot read or forge it. The sealing key is
derived with HKDF from the KMS data key under its
own label, so only the enclave can seal or open the state, and the
authenticated data binds the pool public key, the KMS key ID, and a state
version. The proxy writes the sealed state to the same Secrets Manager secret
as the envelope before it releases the signature, admitting one request at a
time across the enclave call and the write. A sign request that does not
finish within 20 seconds, including any wait behind another request, fails
and releases nothing. On start the proxy passes the stored state to
`Reload`. A tampered state, or one sealed for another key or KMS key, refuses
the reload; a secret with no state is a legacy start with no known counter. A
reload on a loaded enclave never lowers its counter. Secrets written before
this change hold the envelope only and still load.

If the write fails or times out, the request fails, no signature is released,
and the proxy logs the cause and refuses every later sign until it restarts,
since the failed write can still land after a newer one. While stopped, the
proxy also answers inventory with HTTP 503, so a signer started against it
fails closed; a proxy restart clears it. The running enclave has still counted
the issue number. After the restart reloads the stored state, a retry of the
same request (same payload, fresh nonce and challenge) is signed again and its
state saved, whether or not the failed write landed. If the failed write did
not land, the restart reloads an older state and the retry signs as a new
counter.

The same re-sign recovers a response lost between the enclave and the signer,
and a signer whose watermark commit failed: the signer commits an issue
counter only after it holds a verified signature, so it has no record of the
number and passes the retry to the enclave. Once the signer has committed the
number, its watermark refuses a retry of it, even when the signer's own
response to its caller was lost.

The sealed state is versioned. A state of the previous version holds no
payload hash; it still loads and allows no re-sign at its counter, so an equal
counter is refused until a higher one is signed. A tampered or malformed
state, a hash of the wrong length, or an unknown version refuses the reload.

Each signature writes a new secret version. Secrets Manager keeps every
version created in the last 24 hours, so more than about 100 signatures in a
day reach its version quota, and a write refused there fails like any other.
The enclave signs only operational certificates.

The proxy and the enclave image move together: their gRPC messages reject
unknown fields, so a proxy and an enclave from releases on either side of
this change refuse each other. Earlier releases also refuse a secret that
holds counter state. To downgrade, write the envelope-only value back to the
secret; the signer's watermark continues to enforce the issue counter.

The sealed state narrows the restart gap and is not the counter authority. The
host holds it and can restore an older secret version. Two proxies pointed at
one secret overwrite each other's state (last writer wins, no compare and
swap). The signer's durable watermark therefore remains the authority for the
operational-certificate issue counter, including across replicas.
`bursa signer` refuses to start with a `nitro` backend unless
`signer.watermark.mode` is `enforce` (the default) and `signer.watermark.type`
is `file` or `postgres`. A `file` path must open a file-backed SQLite
database; an in-memory one such as `:memory:` is refused.

Two signer features are refused by design:

- `chain_counter` requests. The signer sends these as `opcert-next`, which
  accepts the same chain counter again so a KES rotation can reuse an issue
  number. The enclave's counter only increases, so it never signs a second
  certificate at an issue number it has already used (it repeats only the
  identical payload, which yields the same signature). Send `issue_counter`
  instead.
- A backend `profile`. The enclave signs no profile binding, so leave
  `profile` unset on a `nitro` backend; with it set, the inventory request is
  refused and the backend does not load.

## Reproducible EIF and PCR rotation

Build the Linux binary with the repository's pinned Go toolchain and module
checksums:

```text
CGO_ENABLED=0 go build -trimpath -buildvcs=false -ldflags=-buildid= \
  -o bursa ./cmd/bursa
```

Pin the base image by digest, normalize file ownership, permissions, and
timestamps, and keep the EIF kernel and bootstrap inputs pinned. Build on the
target architecture without embedding AWS credentials, proxy client keys,
deployment configuration, or the AWS Nitro root certificate. Record together:

- source commit and clean-tree status;
- Go toolchain version and module checksum file;
- base image digest and EIF build inputs;
- provisioning authority public key;
- binary SHA-256;
- EIF SHA-384 and PCR0, PCR1, PCR2, and PCR8 values emitted by
  `nitro-cli build-enclave`.

Rebuilding the same inputs must reproduce the binary hash and PCR values before
the image is eligible for deployment. A different PCR is a different trusted
workload and must not be added to policy merely to make a rollout pass.

Rotate an approved image in this order:

1. Reproduce and record the new EIF and measurements.
2. Add the new PCR conditions to the KMS policy while retaining the active
   image's conditions.
3. Configure the signer to trust the new PCR set, start the new enclave, and
   verify attested inventory and one controlled opcert issuance.
4. Move traffic, stop the old enclave, then remove the old PCR conditions from
   KMS and signer configuration.

If rollback is required, use an image whose measurements remain explicitly
approved. Never use `--debug-mode` or `--attach-console` as a recovery path;
AWS reports zero PCRs for them and Bursa refuses them.

[aws-attestation]: https://docs.aws.amazon.com/enclaves/latest/user/set-up-attestation.html
[aws-kms-conditions]: https://docs.aws.amazon.com/kms/latest/developerguide/conditions-nitro-enclave.html
[arc-signer]: https://github.com/circlefin/arc-remote-signer
