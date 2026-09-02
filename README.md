# bursa

<div align="center">
    <img src="./.github/assets/bursa-logo-with-text-horizontal.png" alt="Bursa Logo" width="640">
</div>

Programmatic Cardano Wallet

Bursa is two things that share one set of keys:

- **A Cardano wallet library and CLI** — BIP39 seeds, CIP-1852 derivation,
  addresses, certificates and native scripts, usable as a Go package or from the
  `bursa` command. That is what the rest of this README covers.
- **A full-node desktop wallet** — a single binary that embeds and supervises a
  [Dingo](https://github.com/blinklabs-io/dingo) node and serves a wallet
  interface over loopback, with hardware-wallet support, staking, Conway
  governance and stake-pool operations. It lives in [`ui/`](./ui) and has
  [its own README](./ui/README.md).

## Supported CIPs

Bursa implements the following Cardano Improvement Proposals:

- **CIP-0003**: Wallet Key Generation - Complete BIP39 seed generation and key derivation
- **CIP-0005**: Bech32 Address Format - Bech32 encoding/decoding for addresses and keys
- **CIP-0011**: Staking Key Delegation - Stake key derivation and reward address generation
- **CIP-0016**: Cryptographic Key Serialization - CBOR serialization for all key types
- **CIP-0018**: Multi-Stake Keys - Support for multiple stake keys per wallet
- **CIP-0019**: Cardano Addresses - Full address format support (mainnet/testnet)
- **CIP-0105**: Conway Era Key Chains - Governance key derivation (DRep, Committee)
- **CIP-1852**: HD Wallets - Hierarchical deterministic wallet structure
- **CIP-1853**: Stake Pool Cold Keys - Pool operator identity keys
- **CIP-1854**: Multi-signature Scripts - Native script support and validation
- **CIP-1855**: Forging Policy Keys - Native asset minting/burning policy keys

Start a Bursa wallet and interact with it using the Bursa API.

```golang
# Clone the Bursa repository
git clone git@github.com:blinklabs-io/bursa.git
cd bursa

# Start the Bursa API server
go run ./cmd/bursa api 
```

Access API Swagger documentation on the default loopback listener:
[http://localhost:8080/swagger/index.html](http://localhost:8080/swagger/index.html).

## Highly Available Signer Watermarks

Signer replicas must share one PostgreSQL watermark database to preserve the
payload and operational-certificate counter guards across replicas. Configure
every replica with the same database and keep `mode: enforce`:

```yaml
signer:
  watermark:
    type: postgres
    mode: enforce
    dsn_env: BURSA_SIGNER_WATERMARK_POSTGRES_DSN
```

Set the named environment variable to a pgx/libpq connection string. Remote
connections should require server identity verification, for example:

```text
postgres://bursa@postgres.example/bursa?sslmode=verify-full&sslrootcert=/etc/bursa/postgres-ca.pem
```

Supply the password through the process environment or another pgx-supported
credential mechanism; do not store credentials in the YAML file. The database
role needs permission to create the two watermark tables on first startup and
to read and write them thereafter.

PostgreSQL replication and failover are external to Bursa. A failover endpoint
must preserve all committed rows and continue to present one authoritative
database; routing replicas to independent databases defeats the HA signing
guards. Bursa reports the signer unready while the database is unavailable and
signing in `enforce` mode fails closed.

Bursa does not automatically import watermark history from the in-memory or
SQLite stores. Do not cut an active signer over to an empty PostgreSQL database:
preserve or import both the payload and counter watermark rows during a
controlled outage, or enable PostgreSQL before the affected keys sign for the
first time.

The API listens on `127.0.0.1` by default. Set `API_LISTEN_ADDRESS` to an
explicit address such as `0.0.0.0` only when remote access is intended and
protected by TLS and JWT authentication. A non-loopback listener refuses to
start unless `API_TLS_CERT_FILE` / `api.tls_cert_file` and
`API_TLS_KEY_FILE` / `api.tls_key_file` identify a server certificate and
private key, and exactly one of these API trust sources is configured:

- `API_JWT_SECRET` / `api.jwt_secret`: an HS256 secret of at least 32 bytes;
  keep it in a deployment secret, not a committed config file.
- `API_JWKS_URL` / `api.jwks_url`: an HTTPS JWKS endpoint (plain HTTP is only
  accepted for loopback development).

`API_JWT_ISSUER` / `api.jwt_issuer` and `API_JWT_AUDIENCE` /
`api.jwt_audience` optionally constrain accepted bearer tokens. The secret,
signing, and mnemonic/address-derivation endpoints require an
`Authorization: Bearer <JWT>` header whenever API authentication is configured.
When Google Secret Manager persistence is enabled, the wallet
`list`, `get`, `update`, and `delete` endpoints use the same authentication
requirement and additionally require a subject listed in
`API_JWT_ADMIN_SUBJECTS` / `api.jwt_admin_subjects`. This is an explicit
global-administrator model; wallet names are not caller ownership boundaries.
Wallet creation is `POST /api/wallet/create`; wallet responses are marked
`Cache-Control: no-store`. A remote Swagger URL uses the same HTTPS listener,
for example `https://wallet.example.com:8080/swagger/index.html`. Plain HTTP
remains available only for loopback development when no TLS files are set.

```yaml
api:
  address: 0.0.0.0
  port: 8080
  tls_cert_file: /run/secrets/bursa-api-cert.pem
  tls_key_file: /run/secrets/bursa-api-key.pem
  jwks_url: https://identity.example.com/.well-known/jwks.json
  jwt_issuer: https://identity.example.com
  jwt_audience: bursa-api
  jwt_admin_subjects:
    - wallet-service-admin
```

### Kubernetes and Helm deployment contract

The Bursa container listens on loopback by default. A Kubernetes Service must
set `API_LISTEN_ADDRESS` to the pod address (normally `0.0.0.0`) and preserve
the API and metrics container/Service ports of `8080` and `8081`. When Google
Secret Manager persistence is enabled, the deployment must inject
`GOOGLE_PROJECT`, `GCP_KMS_RESOURCE_ID`, and `GCP_SECRET_PREFIX`, provide
`API_JWT_SECRET` or `API_JWKS_URL`, provide at least one
`API_JWT_ADMIN_SUBJECTS` value, and mount the matching TLS certificate and key
as `API_TLS_CERT_FILE` and `API_TLS_KEY_FILE`. The API refuses a non-loopback
listener without both TLS files and authentication. These values belong in
the chart's secret/config wiring; do not place credentials in chart defaults.

For more information about Bursa CLI

```bash
go run ./cmd/bursa
Usage:
  bursa [command]

Available Commands:
  address     Address utility commands
  api         Runs the api
  cert        Certificate generation commands
  help        Help about any command
  key         Key derivation commands
  script      Script commands for multi-signature operations
  wallet      Wallet commands

Flags:
  -h, --help   help for bursa

Use "bursa [command] --help" for more information about a command.
```

### Key Derivation Commands

Derive individual keys from a BIP-39 mnemonic:

```bash
bursa key root --mnemonic "..."           # Root extended private key
bursa key account --mnemonic "..."        # Account key (CIP-1852)
bursa key payment --mnemonic "..."        # Payment key (CIP-1852)
bursa key stake --mnemonic "..."          # Stake key (CIP-1852)
bursa key policy --mnemonic "..."         # Forging policy key (CIP-1855)
bursa key pool-cold --mnemonic "..."      # Pool cold key (CIP-1853)
bursa key drep --mnemonic "..."           # DRep key (CIP-0105)
bursa key committee-cold --mnemonic "..." # Committee cold key (CIP-0105)
bursa key committee-hot --mnemonic "..."  # Committee hot key (CIP-0105)
bursa key vrf --mnemonic "..."            # VRF key pair for block production
bursa key kes --mnemonic "..."            # KES key pair for block production
```

All keys are output in bech32 format with appropriate prefixes (`root_xsk`, `acct_xsk`, `addr_xsk`, `stake_xsk`, `policy_xsk`, `pool_xsk`, `drep_xsk`, `cc_cold_xsk`, `cc_hot_xsk`, `vrf_sk`, `kes_sk`).

### Address Commands

Inspect Cardano addresses and display their components:

```bash
bursa address info <address>    # Display address type, network, credentials, etc.
```

Supports all CIP-0019 address types including base, enterprise, pointer, reward, and legacy Byron addresses.

### Certificate Commands

Generate certificates for stake pool operations and block production:

```bash
bursa cert op-cert --kes-vkey kes.vkey --cold-skey cold.skey \
  --counter 0 --kes-period 200 --out node.cert    # Operational certificate for block production
```

Operational certificates link KES keys to stake pool cold keys for secure block production.

## Cardano-CLI Compatibility

Bursa generates key files that are fully compatible with cardano-cli. Use `bursa wallet create` or `bursa wallet restore` to generate key files, then use them directly with cardano-cli commands:

```bash
# Create a wallet with Bursa
bursa wallet create --name mywallet

# Use the generated keys with cardano-cli
cardano-cli address build \
  --payment-verification-key-file mywallet/payment.vkey \
  --stake-verification-key-file mywallet/stake.vkey \
  --mainnet
```

This enables Bursa as a drop-in replacement for key generation while maintaining full compatibility with the Cardano ecosystem.

### Signing-key envelope contract

Keys derived through a Cardano HD path retain their existing public identity
when exported. Bursa therefore writes payment, stake, governance, policy,
multi-signature, Calidus, account, and root signing files as extended
Ed25519-BIP32 envelopes. The paired verification files remain the canonical
32-byte public identities used by addresses, credentials, and key hashes.
`cardano-cli key verification-key` emits an extended verification envelope for
an extended signing key; its first 32 bytes are the same paired public identity.

Pool-cold keys are the deliberate exception. Their canonical signing file is a
standard, non-extended Ed25519 seed envelope, matching the pool verification
key and pool ID. The optional extended pool-cold envelope expands that same
seed and therefore implies the same pool identity. Bursa continues to accept
valid non-extended envelopes produced from genuine Ed25519 seeds.

Signing files generated by older Bursa versions may declare a non-extended
type while containing the first 32 bytes of an HD key. Such a file does not
imply the verification key, address, credential, or pool identity that was
exported beside it. Do not fix one by changing only its `type` field. Regenerate
the signing and verification files together from the original mnemonic, then
compare the resulting address or key hash with the identity already in use
before signing. Bursa does not rewrite previously exported files or persisted
wallet items automatically.
