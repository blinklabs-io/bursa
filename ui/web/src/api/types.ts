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

// DEX swap quotes — computed entirely from the embedded node (pool UTxOs at the
// DEX script addresses). Reserves/amounts are uint64 decimal STRINGS server-side
// so values beyond the JS safe-integer range survive the JSON round-trip.
export interface DexPool {
  protocol: string;
  pool_id: string;
  asset_x: string; // unit: "lovelace" or policy+hexname
  asset_y: string;
  reserve_x: string;
  reserve_y: string;
  price_xy: number; // Y per X
  price_yx: number; // X per Y
  effective_fee: number;
  tx_hash: string;
  tx_index: number;
}

export interface DexPoolsResponse {
  pools: DexPool[];
}

export interface DexQuoteRequest {
  asset_in: string;
  asset_out: string;
  amount_in: string; // base-unit (e.g. lovelace) uint64 as a decimal string
}

export interface DexQuote {
  protocol: string;
  pool_id: string;
  asset_in: string;
  asset_out: string;
  amount_in: string;
  amount_out: string;
  price_impact_pct: number;
  effective_fee: number;
  route: string;
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
