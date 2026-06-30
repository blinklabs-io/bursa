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

// CIP-30 connector types.

// ConnectorState is returned by GET /connector/grants.
export interface ConnectorState {
  paired: boolean;
  extension_id: string;
  origins: string[];
}

// ConnectorRequest is a pending consent request from a dApp.
export interface ConnectorRequest {
  id: string;
  origin: string;
  method: string;
  params?: unknown;
  created: string; // RFC3339 timestamp
}

// PendingPairing is a pairing that has been initiated (BeginPair) but not yet
// confirmed. The code is present only after a vault-password reveal.
export interface PendingPairing {
  extension_id: string;
  code?: string;
}
