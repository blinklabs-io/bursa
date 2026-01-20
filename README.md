# bursa

<div align="center">
    <img src="./.github/assets/bursa-logo-with-text-horizontal.png" alt="Bursa Logo" width="640">
</div>

Programmatic Cardano Wallet

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

Access API Swagger documentation: [http://localhost:8080/swagger/index.html](http://localhost:8080/swagger/index.html)

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
