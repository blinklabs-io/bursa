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

// Vault: the encrypted, multi-wallet store. A single vault password unlocks the
// instance (read-only across all wallets); spending additionally needs the
// active wallet's own spending password.
export interface VaultStatus {
  exists: boolean;
  locked: boolean;
  wallet_count: number;
  legacy_keystore?: boolean;
}

// App settings: the lean-node (history-expiry) profile. restart_required is true
// when the persisted value differs from what the running node was built with —
// history expiry is a node-construction option, so it only takes effect on the
// next node restart.
export interface HistoryExpirySetting {
  enabled: boolean;
  restart_required: boolean;
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
  required_signers: string[];
}

export interface SubmitSignedRequest {
  unsigned_tx_cbor: string;
  witness_cbor: string;
}

// --- staking & governance ---

// PoolInfo mirrors GET /wallet/pool/{id}: a node-verified stake pool readout.
// margin_cost is a fraction (0.02 = 2%); the lovelace fields are decimal strings.
export interface PoolInfo {
  pool_id: string;
  hex: string;
  vrf_key: string;
  active_stake: string;
  live_stake: string;
  declared_pledge: string;
  fixed_cost: string;
  margin_cost: number;
}

// DRepInfo mirrors GET /wallet/drep/{id}: confirms a DRep exists on chain.
export interface DRepInfo {
  drep_id: string;
  hex: string;
  has_script: boolean;
  registered: boolean;
  amount: string;
  active: boolean;
  live_stake: string;
}

export type VoteType = "abstain" | "no_confidence" | "drep" | "register_self";

export interface VoteAnchor {
  url: string;
  hash: string; // hex-encoded 32-byte blake2b-256 digest
}

export type DelegationVote =
  | { type: "abstain"; drep_id?: never; anchor?: never }
  | { type: "no_confidence"; drep_id?: never; anchor?: never }
  | { type: "drep"; drep_id: string; anchor?: never }
  | { type: "register_self"; drep_id?: never; anchor?: VoteAnchor };

export interface DelegationRequest {
  pool_id?: string; // omitted = leave stake delegation unchanged
  vote?: DelegationVote;
  withdraw?: boolean; // sweep withdrawable rewards
}

export type CertKind =
  | "stake_registration"
  | "stake_delegation"
  | "vote_delegation"
  | "drep_registration"
  | "withdrawal";

// Cert is one itemized line in a delegation preview: a summary plus, where
// applicable, the refundable deposit it locks or the amount it moves.
export interface Cert {
  kind: CertKind;
  summary: string;
  deposit_lovelace?: string;
  amount_lovelace?: string;
}

export interface DelegationPreview {
  pending_id: string;
  certs: Cert[];
  fee: string;
  deposit: string; // total refundable deposit, decimal lovelace
  withdrawal?: string; // total withdrawn, decimal lovelace
  total: string; // net cost (fee + deposits − withdrawals), decimal lovelace
}

// --- Stake Pool Operations (SPO) ---

export interface PoolKeyInfo {
  vkey_hex: string;
  vkey_bech32?: string;
  hash_hex: string;
}

export interface PoolCredentials {
  network: string;
  pool_id: string;
  pool_id_hex: string;
  cold: PoolKeyInfo;
  vrf: PoolKeyInfo;
  kes: PoolKeyInfo;
  cold_index: number;
  vrf_index: number;
  kes_index: number;
}

export interface KESPeriodInfo {
  current_period: number;
  tip_slot: number;
  slots_per_kes_period: number;
  max_kes_evolutions: number;
}

export interface OpCert {
  kes_vkey_hex: string;
  issue_number: number;
  kes_period: number;
  cold_signature_hex: string;
  kes_index: number;
}

export interface OpCertPayload {
  payload_hex: string;
  kes_vkey_hex: string;
  issue_number: number;
  kes_period: number;
}

export interface PoolMetadataInput {
  name: string;
  ticker: string;
  homepage: string;
  description: string;
}

export interface PoolMetadataResult {
  json: string;
  hash_hex: string;
}

export interface PoolRelayInput {
  type: "single_host_address" | "single_host_name" | "multi_host_name";
  ipv4?: string;
  ipv6?: string;
  hostname?: string;
  port?: number;
}

// RegistrationParams mirrors the backend poolops.RegistrationParams. cold_vkey_hex
// is only set in the air-gap path (then vrf_key_hash_hex is required too).
export interface PoolRegistrationParams {
  pledge: string;
  cost: string;
  margin_num: number;
  margin_denom: number;
  reward_address?: string;
  owners?: string[];
  relays?: PoolRelayInput[];
  metadata_url?: string;
  metadata_hash?: string;
  cold_vkey_hex?: string;
}

export interface PoolCertResult {
  pool_id: string;
  cbor_hex: string;
}

export interface PoolIDResult {
  pool_id: string;
  pool_id_hex: string;
}

// A wallet as listed by the vault: read-only fields plus whether it's active.
// The encrypted seed is never exposed.
export interface WalletView {
  id: string;
  name: string;
  network: string;
  stake_address: string;
  addresses: string[];
  active: boolean;
}

export interface CreateVaultRequest {
  password: string; // vault password
}

export interface UnlockVaultRequest {
  password: string; // vault password
}

// Adding a wallet: the mnemonic + spending password (to encrypt the seed) plus
// the vault password (to re-seal the index).
export interface AddWalletRequest {
  name: string;
  mnemonic: string;
  network: string;
  vault_password: string;
  spend_password: string;
}

export interface MigrateLegacyKeystoreRequest {
  name: string;
  vault_password: string;
  spend_password: string;
}
