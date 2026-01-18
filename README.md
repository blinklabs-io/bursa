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
  api         Runs the api
  help        Help about any command
  key         Key derivation commands
  script      Multi-signature script commands
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
```

All keys are output in bech32 format with appropriate prefixes (`root_xsk`, `acct_xsk`, `addr_xsk`, `stake_xsk`, `policy_xsk`, `pool_xsk`, `drep_xsk`).
