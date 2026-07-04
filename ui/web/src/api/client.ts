import type {
  Status,
  Balance,
  AddressView,
  Tx,
  TxDetail,
  DelegationView,
  Preview,
  TxResult,
  SendRequest,
  SignDataRequest,
  SignDataResult,
  VaultStatus,
  WalletView,
  CreateVaultRequest,
  UnlockVaultRequest,
  AddWalletRequest,
  AddHardwareWalletRequest,
  MigrateLegacyKeystoreRequest,
  HistoryExpirySetting,
  AutoLockSetting,
  VerifyDataRequest,
  VerifyDataResult,
  UnsignedTx,
  WitnessResult,
  SignTxRequest,
  SubmitSignedRequest,
  PoolInfo,
  DRepInfo,
  AssetInfo,
  DelegationRequest,
  DelegationPreview,
  HandleInfo,
  PoolCredentials,
  KESPeriodInfo,
  OpCert,
  OpCertPayload,
  PoolMetadataInput,
  PoolMetadataResult,
  PoolRegistrationParams,
  PoolCertResult,
  PoolIDResult,
  TPMStatus,
  EnableTPMRequest,
  DisableTPMRequest,
  Contact,
  UpsertContactRequest,
  DexPoolsResponse,
  DexQuoteRequest,
  DexQuote,
  MultiSigAccount,
  CreateMultiSigRequest,
  MultiSigMyKey,
  MultiSigBalance,
  MultiSigBuildRequest,
  MultiSigUnsignedTx,
  MultiSigSignRequest,
  MultiSigSubmitRequest,
  HardwareSignResponse,
  TxSummary,
  CosignResult,
  NFT,
  NftMediaSetting,
} from "./types";

export class ApiError extends Error {
  constructor(
    public status: number,
    message: string,
  ) {
    super(message);
    this.name = "ApiError";
  }
}

const REQUEST_TIMEOUT_MS = 30_000;
// Retry only on network failures (TypeError/"Failed to fetch"), not HTTP errors.
const RETRY_ATTEMPTS = 3; // total attempts (1 initial + 2 retries)
const RETRY_BACKOFF_BASE_MS = 250;
const RETRY_BACKOFF_CAP_MS = 1_000;

// Only retry read-only methods. Replaying DELETE can surface a false failure if
// the first request succeeded server-side but the response was lost.
const RETRYABLE_METHODS = new Set(["GET", "HEAD", "OPTIONS"]);

async function request<T>(method: string, path: string, body?: unknown): Promise<T> {
  let lastNetworkError: ApiError | null = null;
  const maxAttempts = RETRYABLE_METHODS.has(method.toUpperCase()) ? RETRY_ATTEMPTS : 1;

  for (let attempt = 0; attempt < maxAttempts; attempt++) {
    if (attempt > 0) {
      // Capped exponential backoff: 250ms, 500ms, ... capped at 1000ms
      const delay = Math.min(RETRY_BACKOFF_BASE_MS * Math.pow(2, attempt - 1), RETRY_BACKOFF_CAP_MS);
      await new Promise<void>((resolve) => setTimeout(resolve, delay));
    }

    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), REQUEST_TIMEOUT_MS);
    let res: Response;
    try {
      res = await fetch(path, {
        method,
        headers: body ? { "Content-Type": "application/json" } : undefined,
        body: body ? JSON.stringify(body) : undefined,
        signal: controller.signal,
      });
    } catch (e) {
      clearTimeout(timer);
      // Only retry on network failures (TypeError). AbortError (timeout) is not retried.
      if (e instanceof TypeError) {
        lastNetworkError = new ApiError(0, "network error");
        continue;
      }
      // Timeout / abort — treat as a terminal error, don't retry.
      throw new ApiError(0, "request timed out");
    }
    clearTimeout(timer);

    if (!res.ok) {
      let message = `request failed (${res.status})`;
      try {
        const j = await res.json();
        if (j && typeof j.error === "string") message = j.error;
      } catch {
        /* non-JSON */
      }
      // HTTP error responses are real responses — do not retry.
      throw new ApiError(res.status, message);
    }
    // All our endpoints return JSON.
    return (await res.json()) as T;
  }

  // Exhausted all retry attempts for network failures.
  throw lastNetworkError ?? new ApiError(0, "network error");
}

export const apiGet = <T>(path: string) => request<T>("GET", path);
export const apiPost = <T>(path: string, body?: unknown) => request<T>("POST", path, body);
export const apiPut = <T>(path: string, body?: unknown) => request<T>("PUT", path, body);

export const apiDelete = <T>(path: string, body?: unknown) => request<T>("DELETE", path, body);

export const getStatus = () => apiGet<Status>("/status");

// Vault lifecycle.
export const getVaultStatus = () => apiGet<VaultStatus>("/vault/status");
export const createVault = (req: CreateVaultRequest) => apiPost<VaultStatus>("/vault", req);
export const unlockVault = (req: UnlockVaultRequest) => apiPost<WalletView[]>("/vault/unlock", req);
export const lockVault = () => apiPost<VaultStatus>("/vault/lock");
export const migrateLegacyKeystore = (req: MigrateLegacyKeystoreRequest) =>
  apiPost<WalletView>("/vault/migrate-legacy", req);

// Wallet management.
// generateMnemonic calls the server-side BIP39 generator (256-bit / 24 words).
// Generating server-side keeps raw entropy inside the loopback process.
export const generateMnemonic = () =>
  apiGet<{ mnemonic: string }>("/wallet/mnemonic/generate").then((r) => r.mnemonic);
export const addWallet = (req: AddWalletRequest) => apiPost<WalletView>("/wallet", req);
export const addHardwareWallet = (
  name: string,
  accountXpub: string,
  accountIndex: number,
  network: string,
  vaultPassword: string,
) =>
  apiPost<WalletView>("/wallet/hardware", {
    name,
    account_xpub: accountXpub,
    account_index: accountIndex,
    network,
    vault_password: vaultPassword,
  } satisfies AddHardwareWalletRequest);
export const activateWallet = (id: string) =>
  apiPost<WalletView>(`/wallet/${encodeURIComponent(id)}/activate`);
export const removeWallet = (id: string, vaultPassword: string) =>
  apiDelete<{ removed: boolean }>(`/wallet/${encodeURIComponent(id)}`, { vault_password: vaultPassword });

export const getBalance = () => apiGet<Balance>("/wallet/balance");
export const getAddresses = () => apiGet<AddressView>("/wallet/addresses");
export const getTransactions = () => apiGet<Tx[]>("/wallet/transactions");
export const getTransactionDetail = (hash: string) =>
  apiGet<TxDetail>(`/wallet/transactions/${encodeURIComponent(hash)}`);
export const getDelegation = () => apiGet<DelegationView>("/wallet/delegation");
export const buildSend = (req: SendRequest) => apiPost<Preview>("/wallet/send", req);
export const confirmSend = (id: string, password: string) =>
  apiPost<TxResult>(`/wallet/send/${encodeURIComponent(id)}/confirm`, { password });
export const signData = (req: SignDataRequest) => apiPost<SignDataResult>("/wallet/sign-data", req);
export const getHistoryExpiry = () =>
  apiGet<HistoryExpirySetting>("/wallet/settings/history-expiry");
export const setHistoryExpiry = (enabled: boolean) =>
  apiPut<HistoryExpirySetting>("/wallet/settings/history-expiry", { enabled });
export const getAutoLock = () => apiGet<AutoLockSetting>("/wallet/settings/auto-lock");
export const setAutoLock = (minutes: AutoLockSetting["minutes"]) =>
  apiPut<AutoLockSetting>("/wallet/settings/auto-lock", { minutes });
export const verifyData = (req: VerifyDataRequest) =>
  apiPost<VerifyDataResult>("/wallet/verify-data", req);
export const exportUnsigned = (id: string) =>
  apiPost<UnsignedTx>(`/wallet/send/${encodeURIComponent(id)}/export-unsigned`);
export const signTx = (req: SignTxRequest) => apiPost<WitnessResult>("/wallet/sign-tx", req);
export const submitSigned = (req: SubmitSignedRequest) =>
  apiPost<TxResult>("/wallet/submit-signed", req);

// Hardware (Ledger) confirm-on-device signing via the air-gap submit path:
// fetch the structured signing request, then submit the device-produced
// witness against the same pending send.
export const getHardwareSignRequest = (id: string) =>
  apiGet<HardwareSignResponse>(`/wallet/send/${encodeURIComponent(id)}/hardware-sign-request`);
export const submitHardware = (id: string, witnessCbor: string) =>
  apiPost<TxResult>(`/wallet/send/${encodeURIComponent(id)}/submit-hardware`, { witness_cbor: witnessCbor });

// ADA Handle ($name) resolution for the Send screen: resolves the handle NFT
// to its current holding address through the node. name may carry a leading
// '$' or not — the server strips it either way.
export const resolveHandle = (name: string) =>
  apiGet<HandleInfo>(`/wallet/handle/${encodeURIComponent(name)}`);

// Staking & governance. Pool/DRep lookups verify a pasted ID through the node;
// buildDelegation returns an itemized preview; confirmDelegation signs + submits
// through the same Confirm path the send flow uses.
export const getPool = (id: string) => apiGet<PoolInfo>(`/wallet/pool/${encodeURIComponent(id)}`);
export const getDRep = (id: string) => apiGet<DRepInfo>(`/wallet/drep/${encodeURIComponent(id)}`);

// Native-asset on-chain metadata (node-only; see ../tokenMeta.ts for how the
// Portfolio screen interprets it, with a fallback when it's absent).
export const getAssetMetadata = (unit: string) =>
  apiGet<AssetInfo>(`/wallet/assets/${encodeURIComponent(unit)}`);
export const buildDelegation = (req: DelegationRequest) =>
  apiPost<DelegationPreview>("/wallet/delegation", req);
export const confirmDelegation = (id: string, password: string) =>
  apiPost<TxResult>(`/wallet/delegation/${encodeURIComponent(id)}/confirm`, { password });

// --- Stake Pool Operations (SPO) ---

export const poolCredentials = (password: string) =>
  apiPost<PoolCredentials>("/wallet/pool/credentials", { password });
export const poolKESPeriod = () => apiGet<KESPeriodInfo>("/wallet/pool/kes-period");
export const poolIssueOpCert = (req: {
  password: string;
  kes_index: number;
  issue_number: number;
  kes_period: number;
}) => apiPost<OpCert>("/wallet/pool/opcert", req);
export const poolRotateKES = (req: {
  password: string;
  new_kes_index: number;
  prev_issue_number: number;
  kes_period: number;
}) => apiPost<OpCert>("/wallet/pool/opcert/rotate", req);
export const poolOpCertPayload = (req: {
  kes_vkey_hex: string;
  issue_number: number;
  kes_period: number;
}) => apiPost<OpCertPayload>("/wallet/pool/opcert/payload", req);
export const poolAssembleOpCert = (req: {
  cold_vkey_hex: string;
  kes_vkey_hex: string;
  signature_hex: string;
  issue_number: number;
  kes_period: number;
}) => apiPost<OpCert>("/wallet/pool/opcert/assemble", req);
export const poolBuildMetadata = (req: PoolMetadataInput) =>
  apiPost<PoolMetadataResult>("/wallet/pool/metadata", req);
export const poolIDFromColdVKey = (cold_vkey_hex: string) =>
  apiPost<PoolIDResult>("/wallet/pool/id", { cold_vkey_hex });
export const poolBuildRegistration = (req: PoolRegistrationParams & { password: string }) =>
  apiPost<PoolCertResult>("/wallet/pool/registration", req);
export type PoolRegistrationAirGapRequest = PoolRegistrationParams & {
  cold_vkey_hex: string;
  vrf_key_hash_hex: string;
};
export const poolBuildRegistrationAirGap = (req: PoolRegistrationAirGapRequest) =>
  apiPost<PoolCertResult>("/wallet/pool/registration/airgap", req);
export type PoolBuildRetirementCertRequest = { epoch: number } & (
  | { password: string; cold_vkey_hex?: never }
  | { cold_vkey_hex: string; password?: never }
);
export const poolBuildRetirementCert = (req: PoolBuildRetirementCertRequest) =>
  apiPost<PoolCertResult>("/wallet/pool/retirement/cert", req);
export const poolSubmitRetirement = (req: { password: string; epoch: number }) =>
  apiPost<TxResult>("/wallet/pool/retirement/submit", req);

// TPM vault binding.
export const getTPMStatus = () => apiGet<TPMStatus>("/vault/tpm/status");
export const enableTPM = (req: EnableTPMRequest) => apiPost<TPMStatus>("/vault/tpm/enable", req);
export const disableTPM = (req: DisableTPMRequest) => apiPost<TPMStatus>("/vault/tpm/disable", req);

// Address book (local-only contacts). Upsert creates a new contact when
// req.id is omitted, or updates the contact with that id when supplied.
export const getContacts = () => apiGet<Contact[]>("/wallet/contacts");
export const upsertContact = (req: UpsertContactRequest) =>
  apiPost<Contact>("/wallet/contacts", req);
export const deleteContact = (id: string) =>
  apiDelete<{ removed: boolean }>(`/wallet/contacts/${encodeURIComponent(id)}`);

// DEX swap quotes (node-local: pool prices and best-pool quotes).
export const getDexPools = () => apiGet<DexPoolsResponse>("/wallet/dex/pools");
export const computeDexQuote = (req: DexQuoteRequest) =>
  apiPost<DexQuote>("/wallet/dex/quote", req);

// Native multi-signature accounts.
export const listMultiSig = () => apiGet<MultiSigAccount[]>("/wallet/multisig");
export const createMultiSig = (req: CreateMultiSigRequest) =>
  apiPost<MultiSigAccount>("/wallet/multisig", req);
export const getMultiSig = (id: string) =>
  apiGet<MultiSigAccount>(`/wallet/multisig/${encodeURIComponent(id)}`);
export const deleteMultiSig = (id: string) =>
  request<{ status: string }>("DELETE", `/wallet/multisig/${encodeURIComponent(id)}`);
export const multiSigMyKey = (password: string) =>
  apiPost<MultiSigMyKey>("/wallet/multisig/my-key", { password });
export const multiSigBalance = (id: string) =>
  apiGet<MultiSigBalance>(`/wallet/multisig/${encodeURIComponent(id)}/balance`);
export const multiSigBuild = (id: string, req: MultiSigBuildRequest) =>
  apiPost<MultiSigUnsignedTx>(`/wallet/multisig/${encodeURIComponent(id)}/build`, req);
export const multiSigSign = (req: MultiSigSignRequest) =>
  apiPost<WitnessResult>("/wallet/multisig/sign", req);
export const multiSigSubmit = (id: string, req: MultiSigSubmitRequest) =>
  apiPost<TxResult>(`/wallet/multisig/${encodeURIComponent(id)}/submit`, req);

// Import transaction: paste a full tx CBOR built elsewhere to inspect it
// (decode-tx), add this wallet's witness(es) (cosign-tx), and broadcast the
// result (submit-tx). The backend classifies vkey vs native-multisig
// transactions and routes accordingly — see TxSummary/CosignResult in types.ts.
export const decodeTx = (tx_cbor: string) => apiPost<TxSummary>("/wallet/decode-tx", { tx_cbor });
export const cosignTx = (req: { tx_cbor: string; password: string; partial_sign?: boolean }) =>
  apiPost<CosignResult>("/wallet/cosign-tx", req);
export const submitTx = (tx_cbor: string) => apiPost<TxResult>("/wallet/submit-tx", { tx_cbor });

// NFT media.
export const getNfts = () => apiGet<NFT[]>("/wallet/nft");
export const getNftMedia = () => apiGet<NftMediaSetting>("/wallet/settings/nft-media");
export const setNftMedia = (enabled: boolean) =>
  apiPut<NftMediaSetting>("/wallet/settings/nft-media", { enabled });
export const nftImageUrl = (unit: string) => `/wallet/nft/${encodeURIComponent(unit)}/image`;
