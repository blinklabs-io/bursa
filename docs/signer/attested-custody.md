# Attested Remote Key Custody

An attested backend holds private keys inside a trusted execution environment
(TEE) and lets the signer use them only through a purpose-bound protocol. The
signer process never holds key material; it trusts a key only after verifying
platform attestation evidence, and it verifies every signature before use.

Two platform verifiers ship in the signer:

| Backend `type` | Platform | Evidence | Verified against |
|----------------|----------|----------|------------------|
| `nitro` | AWS Nitro Enclaves | COSE_Sign1 attestation document | pinned AWS Nitro root certificate, expected PCR values |
| `confidential-space` | GCP Confidential Space | Google Cloud Attestation OIDC token | Google's published token signing keys, audience, container image digest |

## Trust boundaries

| Component | Trusted for | Not trusted for |
|-----------|-------------|-----------------|
| Enclave workload (measured image) | holding keys, enforcing its own signing policy | nothing beyond its measurement |
| Cloud attestation service / KMS | issuing evidence; releasing wrapped key material only to the measured workload | - |
| Host or VM that runs the signer and the proxy | - | confidentiality of keys (it never sees them), request integrity, availability |
| Host proxy (vsock or socket forwarder) | - | everything: it can drop, delay, replay, or rewrite messages |
| Signer process | caller authentication, per-key policy, Cardano operation validation, watermarks, signature verification | key custody |

Because the proxy is untrusted, correctness rests on three checks the signer
performs itself:

1. The key inventory is accepted only when its attestation evidence verifies and
   commits to the signer's fresh nonce and to the exact key list
   (`InventoryBinding`). Evidence cannot be replayed for another nonce or paired
   with a different key list.
2. Every sign request carries a fresh random nonce that the response must echo;
   a stale or replayed response is refused.
3. Every signature is verified against the attested public key before it is
   returned or used (`SignTx`, `SignOpCert` and `SignCIP8` all verify). A
   signature from any other key is discarded.

### Authorization when the host proxy is untrusted

The signer authenticates callers and applies per-key policy, but that happens on
the host. A host that is compromised can bypass the signer and talk to the
enclave directly, so the signer's policy is not an authorization boundary for
the enclave. The enclave must enforce, inside the measured image and independent
of the signer:

- the purpose, role and payload-shape rules below;
- a durable, monotonic operational-certificate issue counter per cold key (the
  signer's watermark protects only requests that pass through the signer);
- any transaction policy the operator relies on when the host is not trusted;
- refusal of a repeated request nonce.

Anything the enclave does not enforce is only as strong as the host.

## Protocol

The protocol version is `bursa-attested-signer/1`. The inventory response and
both sign messages carry it, and a peer answering with another version is
refused; the inventory request carries only the nonce. Messages are JSON; `[]byte` fields
are base64.

`POST /v1/inventory` takes `{"nonce": <32 bytes>}` and returns:

```json
{"version": "bursa-attested-signer/1",
 "keys": [{"role": "pool", "public_key": "<32 bytes>"}],
 "attestation": "<platform evidence>"}
```

The evidence must commit to
`sha256("bursa-attested-signer/1" || nonce || for each key: decimal(len(role)) || ":" || role || public_key)`.
Nitro carries it in the document's `user_data`; Confidential Space carries
`hex(binding)` in the token's `eat_nonce`. Keys are identified by their Cardano
key hash (blake2b-224 of the public key) and carry the role the enclave
attests: `payment`, `stake`, `drep`, `cc-hot`, `cc-cold`, `pool`, or `policy`.
An unknown role, a malformed public key, or a duplicate key fails the load, and
a failed load leaves the backend serving no keys.

`POST /v1/sign` takes:

```json
{"version": "bursa-attested-signer/1", "purpose": "opcert",
 "key_hash": "<56 hex>", "role": "pool", "nonce": "<32 bytes>", "payload": "<bytes>"}
```

and returns `{"version", "nonce", "signature"}` or `{"version", "nonce", "error"}`.

| Purpose | Payload | Key role |
|---------|---------|----------|
| `tx-hash` | 32-byte transaction body hash | any |
| `opcert` | 48-byte OCertSignable: KES vkey, issue counter, KES period | `pool` only |
| `cip8` | COSE Sig_structure for CIP-8 data signing | any |

The signer refuses a request whose payload shape or key role does not fit its
purpose before contacting the enclave. KES header signing is not carried here:
it uses the KES agent's `sign` mode, whose request is likewise typed (see
[`kes-agent-protocol.md`](kes-agent-protocol.md)).

The existing signer checks stay authoritative: caller ACL, per-key policy,
Cardano operation validation, watermarks, role guard for operational
certificates, and signature verification all run in the signer before and after
the enclave call. A plain `Sign` on an attested key is refused.

The signer can reach the enclave at an `http://`, `https://` or `unix:///path`
address. Forwarding that address onto the platform's vsock (Nitro) or onto the
workload's port (Confidential Space) is the deployment's job; the channel needs
no confidentiality or integrity guarantee from the signer's point of view.

## AWS Nitro Enclaves

```yaml
backends:
  - name: "nitro"
    type: "nitro"
    address: "unix:///run/bursa/enclave.sock"   # host proxy to the enclave vsock
    root_ca_file: "/etc/bursa/signer/aws-nitro-root.pem"
    pcrs:
      0: "<96 hex: image measurement from the built EIF>"
      # 1, 2, 8 optional
```

- `root_ca_file` is the AWS Nitro Enclaves root certificate, obtained from AWS
  and checked against the fingerprint AWS publishes. The signer trusts no
  embedded root.
- PCR0 is mandatory and must not be all zeros. A debug-mode enclave reports zero
  PCRs, so it can never match; an unattested or debug build is refused at boot.
- The attestation document's certificate chain must verify to the pinned root at
  the current time, and its ES384 signature must verify under the leaf key.
- Boot fails if attestation fails. Re-attestation (for example after an enclave
  restart) is `AttestedBackend.Load`, which drops all keys before verifying.

Operators wire the enclave side as follows; these controls live in AWS and in
the enclave image, outside the signer:

- Store only envelope-encrypted key material in Secrets Manager; the data key is
  wrapped by a KMS key.
- Bind decryption to the measured image with a KMS key policy that allows
  `kms:Decrypt` only when the request carries a Nitro attestation and
  `kms:RecipientAttestation:ImageSha384` equals the EIF's PCR0 (add
  `kms:RecipientAttestation:PCR1`/`PCR2` as needed). KMS then refuses a
  differently measured or debug enclave.
- Build the EIF reproducibly from pinned inputs and record its PCR values from
  the build output. Rotating the image changes PCR0: add the new value to the
  KMS policy and to `pcrs`, roll the signer, then remove the old value.

## GCP Confidential Space

```yaml
backends:
  - name: "gcp-cs"
    type: "confidential-space"
    address: "https://workload.example.internal:8443"
    audience: "https://signer.example.internal"
    image_digest: "sha256:<64 hex>"
    # jwks_url: defaults to Google's published token signing keys
```

The signer accepts a token only when all of these hold:

- it is RS256-signed by a key in the JWKS (HTTPS, or loopback HTTP, only);
- issuer is `https://confidentialcomputing.googleapis.com`, audience equals
  `audience`, and `iat`, `nbf`, and `exp` are present and valid;
- `dbgstat` is `disabled-since-boot`, `swname` is `CONFIDENTIAL_SPACE`, and
  `secboot` is true, the hardware model is supported, and the image carries
  the `STABLE` support attribute;
- `submods.container.image_digest` equals `image_digest`;
- `eat_nonce` contains the inventory binding.

### Pool cold-key workload

The `bursa confidential-space-workload` command is the enclave side of the
protocol for one pool cold key. It runs from the signer container image, obtains
custom tokens from the Confidential Space launcher socket, and exposes only
`/v1/inventory` and `/v1/sign`. The sign endpoint accepts only a `pool` key with
the `opcert` purpose and the canonical 48-byte operational-certificate payload.
It rejects reused request nonces and verifies each signature before returning
it.

The first boot generates the Ed25519 pool key and an AES-256-GCM data-encryption
key inside the workload. Cloud KMS wraps the data-encryption key. The workload
persists only the authenticated ciphertext, wrapped data-encryption key, and
public metadata in the file named by `--wrapped-key-file`. The file is created
once with mode `0600` and is never replaced. On restart, Cloud KMS must unwrap
the same data-encryption key before the public key is served. A denial, corrupt
envelope, mismatched KMS resource, or changed public metadata stops startup.

The command requires:

```text
bursa confidential-space-workload \
  --listen :8080 \
  --audience https://signer.example.internal \
  --kms-key projects/PROJECT/locations/LOCATION/keyRings/RING/cryptoKeys/KEY \
  --wrapped-key-file /var/lib/bursa/pool-cold.wrapped \
  --counter-bucket POOL_COUNTER_BUCKET \
  --counter-object pool-cold/counter.json \
  --wif-credentials /etc/bursa/confidential-space-wif.json
```

The credential file must be a Google external-account configuration that uses
`https://sts.googleapis.com/v1/token`, does not impersonate a service account,
and reads its text subject token only from
`/run/container_launcher/attestation_verifier_claims_token`. This is the
launcher's automatically refreshed default token for the Workload Identity
Federation provider. The custom token returned to the signer is separate: the
workload requests it for the configured signer audience with
`hex(InventoryBinding)` as its nonce on every inventory request.

Use direct resource access for the Cloud KMS key and counter object. Before a
signature is made, the workload commits the operational-certificate issue
counter to the configured Cloud Storage object with a generation precondition.
This makes the counter strictly increasing across restarts and concurrent
workload replicas. Give the workload identity only `storage.objects.get`,
`storage.objects.create`, and `storage.objects.delete` on the configured object
name. Cloud Storage requires delete permission when a new generation replaces
an existing object. Enable Object Versioning for recovery evidence, and do not
expose the workload's attestation credential outside the measured image.

The Workload Identity Federation provider must map the container image digest
and require
`CONFIDENTIAL_SPACE`, `disabled-since-boot`, secure boot, the approved digest,
and the production support attribute. Grant encrypt and decrypt on only the
wrapping key, and the three object permissions above on only the counter
object, to that digest-bound federated principal. The same condition makes
Cloud KMS and Cloud Storage refuse an unapproved digest, a debug image, an
expired default token, or a request without attestation. The signer
independently verifies those properties on the custom inventory token before
it accepts the public key.

Persist the wrapped-key file and counter object across workload restarts.
Losing the wrapped-key file creates a new pool identity on the next boot;
copying or rolling it back restores the same pool identity because the private
key never leaves its envelope. Back up the wrapped file together with the Cloud
KMS key's retention policy. Never restore or remove the counter object for an
existing pool key.

## KES agent in a protected workload

The KES agent's `sign` mode already keeps the KES key inside the agent. Running
`bursa kes-agent` in sign mode inside an attested workload extends that to the
cloud boundary:

| Boundary | What it protects |
|----------|------------------|
| Enclave / Confidential Space workload | the KES key, its evolution state, and the period guard file |
| Unix socket permissions (or an authenticated forwarder to it) | who may submit header bodies |
| Cold-key custody (separate backend) | the pool cold key; the agent holds only the cold verification key |

- Sign mode accepts only a Praos header body whose slot lies in the requested
  period and whose issuer key, KES key, issue counter, certificate period and
  cold-key signature match the installed operational certificate.
- Stage, certify and install keys through the control socket as described in
  [`kes-agent.md`](kes-agent.md); the opcert is issued with the cold key
  elsewhere (the signer's `opcert` purpose on a `pool` key).
- Restart recovery: the guard file refuses any period below the highest served,
  so it must persist across restarts. It protects against re-serving a
  superseded period only on the storage it lives on, so a failover instance must
  mount that same guard state, or be given a freshly staged key and a new
  operational certificate; never start a second agent with a copy of an older
  guard file.
- A restarted enclave has no key until one is staged and installed again (key
  material is wrapped by the cloud KMS and unwrapped only for the measured
  workload).
