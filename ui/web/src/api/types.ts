export type NodeState = "stopped" | "starting" | "bootstrapping" | "syncing" | "ready" | "error";

export interface BootstrapProgress {
  phase: string;
  percent: number;
  // Snapshot-download phase.
  bytes_downloaded?: number;
  total_bytes?: number;
  bytes_per_second?: number;
  // Block-replay phases (copy / gap-fill / backfill): how far through the chain.
  current_slot?: number;
  tip_slot?: number;
  count?: number;
  total?: number;
  description?: string;
}

export interface Status {
  state: NodeState;
  tip: number;
  latestBlockTime?: string;
  caughtUp: boolean;
  bootstrap?: BootstrapProgress;
  error?: string;
}

export interface Account {
  network: string;
  stake_address: string;
  receive_addresses: string[];
}

// wallet reads: quantity is a STRING
export interface AssetBalance {
  unit: string;
  quantity: string;
}

export interface Balance {
  lovelace: string;
  assets: AssetBalance[];
}

export interface AddressView {
  receive: string[];
  used: string[];
  next_unused: string;
}

export interface Tx {
  tx_hash: string;
  tx_index: number;
  block_height: number;
  block_time: number;
}

export interface DelegationView {
  pool_id: string | null;
  active: boolean;
  rewards_sum: string;
  withdrawable_amount: string;
  provisional: boolean;
  note: string;
}

// spend: quantity / lovelace are decimal STRINGS (uint64 server-side), matching
// the read side — so values beyond the JS safe-integer range (2^53) survive the
// JSON round-trip without being silently rounded.
export interface SendAsset {
  unit: string;
  quantity: string;
}

export interface SendRequest {
  to: string;
  lovelace: string;
  assets?: SendAsset[];
}

export interface Output {
  address: string;
  lovelace: string;
  assets?: SendAsset[];
}

export interface Preview {
  pending_id: string;
  inputs: string[];
  outputs: Output[];
  fee: string;
  change: string;
}

export interface TxResult {
  tx_hash: string;
}

// CIP-8/CIP-30 signData: sign an arbitrary message with a wallet address's key.
export interface SignDataRequest {
  address: string;
  message: string;
  password: string;
}

export interface SignDataResult {
  signature: string; // COSE_Sign1, hex
  key: string; // COSE_Key, hex
}

// CIP-8/CIP-30 verification: the inverse of signData. expected_address is
// optional; when set, a signature whose signer differs is reported invalid.
export interface VerifyDataRequest {
  signature: string; // COSE_Sign1, hex
  key: string; // COSE_Key, hex
  message: string;
  hashed?: boolean;
  expected_address?: string;
}

export interface VerifyDataResult {
  valid: boolean;
  address: string; // the bech32 address carried in the COSE protected header
}

// Air-gap signing. CBOR fields are hex strings carried (file/copy-paste)
// between an online instance (export + submit) and an offline keyed instance
// (sign).
export interface UnsignedTx {
  unsigned_tx_cbor: string;
  required_signers: string[]; // payment key-hashes (hex) that must witness the tx
}

export interface WitnessResult {
  witness_cbor: string;
}

export interface SignTxRequest {
  unsigned_tx_cbor: string;
  password: string;
}

export interface SubmitSignedRequest {
  unsigned_tx_cbor: string;
  witness_cbor: string;
}

// --- Native multi-signature -------------------------------------------------

// A signer in a multi-sig policy. key_hash_hex (Blake2b-224 of the CIP-1854
// multi-sig vkey) is what the script needs; vkey_hex is carried for sharing.
export interface MultiSigParticipant {
  label?: string;
  key_hash_hex: string;
  vkey_hex?: string;
}

// The spending rule: a threshold of M participants, optionally inside a slot
// validity interval (time-lock). Slots are numbers; if they ever exceed 2^53
// they would be sent as strings, but Cardano slots stay well within range.
export interface MultiSigPolicy {
  threshold: number;
  participants: MultiSigParticipant[];
  invalid_before?: number;
  invalid_after?: number;
}

// A saved multi-sig account: label + policy, plus the derived script + address.
export interface MultiSigAccount {
  id: string;
  label: string;
  network: string;
  policy: MultiSigPolicy;
  script_cbor: string;
  script_address: string;
}

export interface CreateMultiSigRequest {
  label: string;
  network?: string;
  policy: MultiSigPolicy;
}

// The wallet's own CIP-1854 participant identity, to share with co-signers.
export interface MultiSigMyKey {
  vkey_hex: string;
  key_hash_hex: string;
}

// The unsigned multi-sig spend plus the data needed to collect signatures.
export interface MultiSigUnsignedTx {
  unsigned_tx_cbor: string;
  required_signers: string[]; // candidate participant key-hashes (hex)
  threshold: number; // how many must sign
}

export interface MultiSigBuildRequest {
  to: string;
  lovelace: string;
}

export interface MultiSigBalance {
  lovelace: string;
}

export interface MultiSigSignRequest {
  unsigned_tx_cbor: string;
  password: string;
}

export interface MultiSigSubmitRequest {
  unsigned_tx_cbor: string;
  witnesses: string[];
}

export interface LoadWalletRequest {
  mnemonic: string;
  network: string;
}

export interface CreateKeystoreRequest {
  mnemonic: string;
  network: string;
  password: string;
}
