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

export interface DelegationVote {
  type: VoteType;
  drep_id?: string; // when type === "drep"
  anchor?: VoteAnchor; // optional, when type === "register_self"
}

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

export interface LoadWalletRequest {
  mnemonic: string;
  network: string;
}

export interface CreateKeystoreRequest {
  mnemonic: string;
  network: string;
  password: string;
}
