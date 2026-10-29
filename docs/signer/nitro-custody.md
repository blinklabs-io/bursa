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
| `bursa signer` | caller authentication, policy, opcert counter watermark, response signature verification | none |
| `bursa nitro proxy` on the parent instance | authenticate to enclave gRPC with a dedicated client certificate, read/write one existing Secrets Manager secret, fetch temporary role credentials, bridge the signer socket to enclave gRPC, forward opaque KMS TLS bytes to the configured regional endpoint | proxy client key, temporary AWS credentials and wrapped envelope |
| `bursa nitro enclave` in the EIF | require a client certificate from the proxy CA, create recipient attestation, call KMS, unwrap the data key, decrypt the cold-key seed, attest inventory, validate and sign opcert requests | RPC server key, data key and cold key in enclave memory |

The host proxy has no operation that returns a plaintext key. The envelope in
Secrets Manager contains the pool role, public key, KMS key ARN, KMS
`CiphertextBlob`, and an AES-256-GCM ciphertext and nonce. The public metadata
is authenticated as AES-GCM additional data. A reload derives the public key
from the recovered seed and refuses a mismatch.

The host proxy listens on an owner-only Unix socket. Configure the signer's
`nitro` backend with that socket:

```yaml
backends:
  - name: "nitro-pool-cold"
    type: "nitro"
    address: "unix:///run/bursa/nitro.sock"
    root_ca_file: "/etc/bursa/signer/aws-nitro-root.pem"
    pcrs:
      0: "<96 lowercase hex characters from the production EIF>"
```

Create a dedicated CA for the proxy identity. Put the CA certificate and the
enclave server certificate and owner-only key in the EIF. Install the proxy
client certificate, its owner-only key, and the enclave server CA on the parent
for the dedicated proxy service user.

Run `bursa nitro enclave` as the EIF entry point:

```text
bursa nitro enclave \
  --server-cert-file /etc/bursa/nitro/server.pem \
  --server-key-file /etc/bursa/nitro/server-key.pem \
  --client-ca-file /etc/bursa/nitro/proxy-ca.pem
```

On the parent instance run:

```text
bursa nitro proxy --enclave-cid <cid> --region <region> \
  --secret-id <existing-secret-id> --socket /run/bursa/nitro.sock \
  --enclave-ca-file /etc/bursa/nitro/enclave-ca.pem \
  --enclave-server-name nitro-enclave.internal \
  --client-cert-file /etc/bursa/nitro/proxy.pem \
  --client-key-file /etc/bursa/nitro/proxy-key.pem
```

The proxy reads the wrapped envelope and calls `Reload`. It fails before
opening the signer socket if Secrets Manager, KMS recipient decryption,
envelope authentication, the expected public key, or enclave initialization
fails. A process or enclave restart repeats that complete recovery path.

Provisioning is explicit and writes only an existing empty secret. The proxy
refuses to replace an existing wrapped pool-cold key:

```text
bursa nitro proxy --provision --enclave-cid <cid> --region <region> \
  --kms-key-id <kms-key-arn> --secret-id <existing-empty-secret-id> \
  --enclave-ca-file /etc/bursa/nitro/enclave-ca.pem \
  --enclave-server-name nitro-enclave.internal \
  --client-cert-file /etc/bursa/nitro/proxy.pem \
  --client-key-file /etc/bursa/nitro/proxy-key.pem
```

Create the secret, KMS key, role, policies, EC2 instance, and enclave outside
Bursa. Bursa does not create cloud or infrastructure resources.

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

The parent role needs `secretsmanager:GetSecretValue`. Grant
`secretsmanager:PutSecretValue` only during explicit provisioning. It does not
need permission to decrypt a data key without recipient attestation.

## Protocol and signing rules

The host/enclave gRPC protocol is `bursa-nitro-custody/1`. Every RPC requires
TLS 1.3 and a proxy client certificate from the enclave's dedicated client CA;
there is no plaintext or anonymous mode. Both RPC private-key files must deny
group and other access. JSON-encoded gRPC messages reject unknown fields and
trailing values. The signer-facing protocol remains
`bursa-attested-signer/1`, so the existing `KeyRef` path retains caller ACL,
policy, watermark, attestation, and returned-signature checks.

The host OS and proxy client key are the RPC authorization boundary. A process
without that key cannot invoke provisioning, reload, inventory, or signing.
Host root or proxy-key compromise permits RPC calls, but does not expose the
enclave-held cold key. The enclave independently restricts signing to canonical
pool-cold operational-certificate payloads and maintains its nonce and issue
counter guards while the key remains loaded.

The enclave accepts only the `pool` role and `opcert` purpose. It signs the
canonical 48-byte `OCertSignable` value:

```text
KES verification key (32 bytes) || issue counter (uint64 big endian) ||
KES period (uint64 big endian)
```

Requests require a fresh 32-byte nonce. The enclave rejects nonce replay,
non-increasing counters, a wrong key hash or role, malformed payloads, and
unsupported protocol versions. The signer verifies the returned Ed25519
signature before constructing the operational certificate.

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
