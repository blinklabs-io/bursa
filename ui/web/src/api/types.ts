export type NodeState = "stopped" | "starting" | "bootstrapping" | "syncing" | "ready" | "error";

export interface BootstrapProgress {
  phase: string;
  percent: number;
  bytes_downloaded?: number;
  total_bytes?: number;
  bytes_per_second?: number;
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
  pledge: number;
  cost: number;
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

export interface LoadWalletRequest {
  mnemonic: string;
  network: string;
}

export interface CreateKeystoreRequest {
  mnemonic: string;
  network: string;
  password: string;
}
