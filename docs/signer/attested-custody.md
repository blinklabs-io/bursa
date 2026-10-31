# Attested Remote Key Custody

An attested backend holds private keys inside a trusted execution environment
(TEE) and lets the signer use them only through a purpose-bound protocol. The
signer process never holds key material; it trusts a key only after verifying
platform attestation evidence, and it verifies every signature before use.

Three verifiers ship in the signer:

| Backend `type` | Platform | Evidence | Verified against |
|----------------|----------|----------|------------------|
| `nitro` | AWS Nitro Enclaves | COSE_Sign1 attestation document | pinned AWS Nitro root certificate, expected PCR values |
| `confidential-space` | GCP Confidential Space | Google Cloud Attestation OIDC token | Google's published token signing keys, audience, container image digest |
| `armory` | USB armory Mk II with an SE050 | Ed25519 signature by the device identity key | pinned identity public key |

## Trust boundaries

| Component | Trusted for | Not trusted for |
|-----------|-------------|-----------------|
| Enclave workload (measured image) | holding keys, enforcing its own signing policy | nothing beyond its measurement |
| Cloud attestation service / KMS | issuing evidence; releasing wrapped key material only to the measured workload | - |
| Host or VM that runs the signer and the proxy | - | confidentiality of keys (it never sees them), request integrity, availability |
| Host proxy (vsock or socket forwarder) | - | everything: it can drop, delay, replay, or rewrite messages |
| Signer process | caller authentication, per-key policy, Cardano operation validation, watermarks, signature verification | key custody |

Because the proxy is untrusted, correctness rests on four checks the signer
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
4. A backend configured with a profile requires a second signature over the
   complete request and Cardano signature. This prevents a proxy from selecting
   a different profile while replaying a valid signature from the same key.

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

The Confidential Space workload also requires TLS 1.3 mutual authentication
for both protocol endpoints. This prevents network clients without the
signer's certificate from requesting inventory or signatures. The client
private key resides on the signer host, so compromise of that host also
compromises this caller credential. The workload's payload and durable counter
checks remain the limits on what that credential can request.

Anything else the enclave does not enforce is only as strong as the host.

## Protocol

The protocol version is `bursa-attested-signer/1`. The inventory response and
both sign messages carry it, and a peer answering with another version is
refused. The inventory request carries the nonce and optional profile. Messages
are JSON; `[]byte` fields are base64.

`POST /v1/inventory` takes `{"nonce": <32 bytes>, "profile": <optional string>}`
and returns:

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
 "key_hash": "<56 hex>", "role": "pool", "nonce": "<32 bytes>",
 "payload": "<bytes>", "profile": "<optional string>", "era": "<optional uint>"}
```

and returns `{"version", "nonce", "signature", "binding_signature", "issue_counter"}` or
`{"version", "nonce", "error"}`. `binding_signature` is required when the
backend has a profile and omitted for compatibility when it does not.

| Purpose | Payload | Additional field | Key role |
|---------|---------|------------------|----------|
| `tx-body` | Exact encoded transaction body | Resolved `era` | any |
| `tx-hash` | 32-byte transaction body hash (legacy) | - | any |
| `opcert` | 48-byte OCertSignable: KES vkey, issue counter, KES period | - | `pool` only |
| `opcert-next` | 48-byte payload: KES vkey, on-chain opcert counter, KES period | - | `pool` only |
| `cip8` | COSE Sig_structure for CIP-8 data signing | - | any |

For `tx-body`, the workload evaluates the body, computes its Blake2b-256 hash,
and signs that hash. Bursa independently extracts the original body bytes from
the transaction, verifies the returned signature against their hash, and
refuses a response for a body substituted by the proxy. It does not re-encode
the body before sending or hashing it.

For `opcert-next`, the payload carries the counter currently on chain, not the
number to issue. The enclave keeps its own floor on the chain counter and
issues the chain counter plus one, or refuses a chain counter below its floor;
a higher number would leave a gap nodes reject. It returns that
number as the JSON number `issue_counter` and signs `kes_vkey || issue || period`
(issue and period as 8-byte big-endian). The binding signature covers the
request as sent, so its payload still holds the chain counter. Bursa never
picks the issue number. It refuses the response unless `issue_counter` is
present and greater than the chain counter, and the signature verifies under
the pool key over the reconstructed bytes. The coordinator's
`SignOpCertFromChain` uses this purpose for attested pool keys and also
refuses any `issue_counter` other than the chain counter plus one. The method is
`SignOpCertNext(ctx, kesVKey, chainCounter, kesPeriod)` on attested pool keys
(`OpCertNextSigner`); the plain `SignPurpose` path refuses this purpose because
it cannot return the issue number. The signer's `opcert` request, where the
caller supplies the counter, is unchanged.

The binding signature is Ed25519 over the SHA-256 digest of the request fields
and Cardano signature. Each field is framed as its decimal byte length, `:`,
then its bytes, in this order: version, purpose, key hash, role, nonce, payload,
profile, decimal era, signature. Bursa verifies it with the requested key.

The signer refuses a request whose payload shape or key role does not fit its
purpose before contacting the enclave. KES header signing is not carried here:
it uses the KES agent's `sign` mode, whose request is likewise typed (see
[`kes-agent-protocol.md`](kes-agent-protocol.md)).

The existing signer checks stay authoritative: caller ACL, per-key policy,
Cardano operation validation, watermarks, role guard for operational
certificates, and signature verification all run in the signer before and after
the enclave call. A plain `Sign` on an attested key is refused.

The Nitro signer can reach its enclave through an `http://`, `https://` or
`unix:///path` address because attestation and response verification protect
that protocol across the host proxy. Confidential Space requires an `https://`
address, a pinned server CA, and a signer client certificate. Forwarding the
address onto the platform's vsock or workload port remains the deployment's
job.

## AWS Nitro Enclaves

```yaml
backends:
  - name: "nitro"
    type: "nitro"
    address: "unix:///run/bursa/enclave.sock"   # host proxy to the enclave vsock
    profile: "pool@mainnet"                     # optional fixed workload profile
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
    profile: "pool@mainnet"                     # optional fixed workload profile
    audience: "https://signer.example.internal"
    image_digest: "sha256:<64 hex>"
    tls_ca_file: "/etc/bursa/confidential-space-ca.pem"
    tls_client_cert_file: "/etc/bursa/confidential-space-client.pem"
    tls_client_key_file: "/etc/bursa/confidential-space-client-key.pem"
    # jwks_url: defaults to Google's published token signing keys
```

The signer accepts a token only when all of these hold:

- it is RS256-signed by a key in the JWKS (HTTPS, or loopback HTTP, only);
- issuer is `https://confidentialcomputing.googleapis.com`, audience equals
  `audience`, and `iat`, `nbf`, and `exp` are present and valid;
- `dbgstat` is `disabled-since-boot`, `swname` is `CONFIDENTIAL_SPACE`, and
  `secboot` is true, `hwmodel` is `GCP_AMD_SEV`, `GCP_AMD_SEV_ES`, or
  `GCP_INTEL_TDX`, and the image carries the `STABLE` support attribute;
- `submods.container.image_digest` equals `image_digest`;
- `eat_nonce` contains the inventory binding.

The Workload Identity Pool provider that authorizes access to Cloud KMS and
Cloud Storage must enforce the same hardware boundary in its
[attestation policy](https://cloud.google.com/confidential-computing/confidential-space/docs/create-grant-access-confidential-resources#create-an-attestation-policy).
Use `assertion.hwmodel == "GCP_AMD_SEV"` for AMD or
`assertion.hwmodel == "INTEL_TDX"` for Intel, matching Google's documented
[Workload Identity attestation assertion values](https://cloud.google.com/confidential-computing/confidential-space/docs/reference/attestation-assertions#vm-assertions),
and combine that condition with the software name, `STABLE` support attribute,
and container image digest conditions. The custom OIDC token verified by Bursa
uses `GCP_INTEL_TDX` for Intel. Neither policy admits `GCP_SHIELDED_VM`.

### Pool cold-key workload

The `bursa confidential-space-workload` command is the enclave side of the
protocol for one pool cold key. It runs from the signer container image, obtains
custom tokens from the Confidential Space launcher socket, and exposes only
`/v1/inventory` and `/v1/sign` over TLS 1.3. Both endpoints require a client
certificate signed by `--client-ca-file`. The sign endpoint accepts only a
`pool` key with the `opcert` purpose and the canonical 48-byte
operational-certificate payload. It rejects reused request nonces and verifies
each signature before returning it.

The first boot generates the Ed25519 pool key and an AES-256-GCM data-encryption
key inside the workload. Cloud KMS wraps the data-encryption key. The workload
persists only authenticated ciphertext, the wrapped data-encryption key, and
public metadata in the file named by `--wrapped-key-file`. It first publishes a
`counter-pending` envelope with mode `0600`, creates the matching counter
object, and atomically replaces the envelope with an authenticated `active`
form before serving. A restart can finish an interrupted pending bootstrap with
the same pool identity. An active envelope never recreates a missing counter.
Cloud KMS must unwrap the same data-encryption key before the public key is
served. A denial, corrupt envelope, mismatched KMS resource, or changed public
metadata stops startup.

The command requires:

```text
bursa confidential-space-workload \
  --listen :8080 \
  --audience https://signer.example.internal \
  --kms-key projects/PROJECT/locations/LOCATION/keyRings/RING/cryptoKeys/KEY \
  --wrapped-key-file /var/lib/bursa/pool-cold.wrapped \
  --counter-bucket POOL_COUNTER_BUCKET \
  --counter-object pool-cold/counter.json \
  --wif-credentials /etc/bursa/confidential-space-wif.json \
  --tls-cert-file /etc/bursa/confidential-space-server.pem \
  --tls-key-file /etc/bursa/confidential-space-server-key.pem \
  --client-ca-file /etc/bursa/confidential-space-client-ca.pem
```

Configure `tls_ca_file` on the signer with the CA that issued the workload
server certificate. Configure `tls_client_cert_file` and
`tls_client_key_file` with a client identity issued by the CA passed to
`--client-ca-file`. The workload has no plaintext or optional-client-certificate
mode.

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
The first counter must be `0`, and every later counter must be exactly one
greater than the committed value. The maximum `uint64` value is refused. This
keeps the counter sequential across restarts and concurrent workload replicas
without allowing one request to exhaust the counter range. Give the workload
identity only `storage.objects.get`,
`storage.objects.create`, and `storage.objects.delete` on the configured object
name. Cloud Storage requires delete permission when a new generation replaces
an existing object. Enable Object Versioning for recovery evidence, and do not
expose the workload's attestation credential outside the measured image.
Counter objects written with `bursa-confidential-space-counter/1` migrate once
with a generation precondition: `next_issue_number` becomes the stored
`issue_number` plus one. A legacy maximum value, malformed state, or a key-hash
mismatch stops startup.

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
KMS key's retention policy. The counter object is created with a new wrapped
identity; startup fails if that identity later has no matching counter object.
Never restore or remove the counter object for an existing pool key.

## USB armory

```yaml
backends:
  - name: "armory"
    type: "armory"
    address: "http://10.0.0.1"                  # the device on its USB network link
    profile: "pool@preview"                     # required: the device profile holding the keys
    identity_public_key: "<64 hex>"             # the device identity key, pinned
    host_key_file: "/etc/bursa/armory-host.skey" # optional: authenticates signing requests
```

The USB armory Mk II holds the pool cold key and the owner stake key in its
SE050 secure element, one profile per pool and network. Its signing firmware
serves this protocol at `/v1/inventory` and `/v1/sign`.

The evidence is the device identity key's Ed25519 signature over the inventory
binding. The signer accepts the inventory only when that signature verifies
under `identity_public_key`. This proves the inventory came from a device
holding the identity key. It is not a measurement of the firmware: the board
boots unsigned images, so anyone holding the device can run other firmware.
Record the identity key when the device is provisioned; the device's legacy
`/pubkey` endpoint returns a different key.

Profiled responses carry the second signature described above, so the signer
also refuses a response produced for another profile.

The firmware also answers sign requests at version `bursa-attested-signer/2`,
which `armory-pool witness` sends for `tx-body`. The reply echoes that version
and adds `summary`, the signing policy's description of the body (for a pool
registration: pledge, cost, margin, relays). Its binding appends the summary as
one more length-prefixed field after the signature, present even when empty. A
version-1 request gets the version-1 reply and binding, without `summary`. The
signer sends version 1; inventory and challenge replies stay at version 1.

`host_key_file` holds a host signing key written by `armory-pool host-key`
and registered on the device. With it set, the signer fetches a one-time
challenge from `/v1/challenge` before each signature and adds `challenge`,
`host_key` and `host_signature` to the request: an Ed25519 signature over
`AttestedRequestBinding`, the domain `bursa-armory-request/1` followed by the
request fields and the challenge, length-prefixed as in the response binding.
A device with a registered host key refuses requests without it. The file
must not be readable by group or others, and an unreadable or malformed file
fails startup.

## KES agent in a protected workload

The KES agent's `sign` mode already keeps the KES key inside the agent. Running
`bursa kes-agent` in sign mode inside an attested workload extends that to the
cloud boundary:

| Boundary | What it protects |
|----------|------------------|
| Enclave / Confidential Space workload | the KES key, its evolution state, and the period guard file |
| Unix socket permissions (or an authenticated forwarder to it) | who may submit header bodies |
| Cold-key custody (separate backend) | the pool cold key; the agent holds only the cold verification key |

For a remote Dingo producer, `bursa-attested-kes/1` applies two independent
checks: TLS client certificates authenticate Dingo to the workload, and fresh
nonce-bound platform evidence authenticates the measured workload and its
active public KES state to Dingo. The AWS adapter places the protocol binding
in Nitro `user_data`. The GCP adapter places its hex encoding in Confidential
Space `eat_nonce`. Dingo applies the same pinned PCR, image digest, debug-state,
issuer, audience, expiry, and secure-boot rules used by the attested signer.

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
- A restarted workload has no key until one is staged and installed again. The
  guard survives on workload-private durable storage; wrapped recovery material
  may be released only to the approved measurement. If the provider adapter,
  attestation service, KMS release, durable guard, or operational-certificate
  check fails, the workload exposes no signing service.
