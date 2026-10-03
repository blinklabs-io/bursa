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

The protocol version is `bursa-attested-signer/1`; every message carries it and
a peer speaking another version is refused. Messages are JSON; `[]byte` fields
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
  `audience`, and `exp` is present and in the future;
- `dbgstat` is `disabled-since-boot`, `swname` is `CONFIDENTIAL_SPACE`, and
  `secboot` is true;
- `submods.container.image_digest` equals `image_digest`;
- `eat_nonce` contains the inventory binding.

The workload obtains the token with the signer's audience and `hex(binding)` as
the nonce. Enclave-side controls live in Google Cloud: a Workload Identity
Federation provider whose attribute condition requires the same image digest,
`dbgstat`, `swname` and audience; IAM that lets only that federated principal
call Cloud KMS `decrypt` on the key wrapping the key material; and a workload
image published by digest. Cloud KMS then refuses an unapproved digest, a debug
image, a wrong audience, an expired token, or missing attestation.

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
  period and whose issuer key, KES key, issue counter and certificate period
  match the installed operational certificate.
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
