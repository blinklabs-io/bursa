import type {
  Status,
  Balance,
  AddressView,
  Tx,
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
  MigrateLegacyKeystoreRequest,
  PoolInfo,
  DRepInfo,
  DelegationRequest,
  DelegationPreview,
  PoolCredentials,
  KESPeriodInfo,
  OpCert,
  OpCertPayload,
  PoolMetadataInput,
  PoolMetadataResult,
  PoolRegistrationParams,
  PoolCertResult,
  PoolIDResult,
  VerifyDataRequest,
  VerifyDataResult,
  UnsignedTx,
  WitnessResult,
  SignTxRequest,
  SubmitSignedRequest,
  MultiSigAccount,
  CreateMultiSigRequest,
  MultiSigMyKey,
  MultiSigBalance,
  MultiSigBuildRequest,
  MultiSigUnsignedTx,
  MultiSigSignRequest,
  MultiSigSubmitRequest,
  DexPoolsResponse,
  DexQuoteRequest,
  DexQuote,
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

async function request<T>(method: string, path: string, body?: unknown): Promise<T> {
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
    // Normalize transport failures (network down, timeout/abort) into ApiError
    // so callers handle them uniformly; status 0 means no HTTP response.
    const msg =
      e instanceof DOMException && e.name === "AbortError" ? "request timed out" : "network error";
    throw new ApiError(0, msg);
  } finally {
    clearTimeout(timer);
  }
  if (!res.ok) {
    let message = `request failed (${res.status})`;
    try {
      const j = await res.json();
      if (j && typeof j.error === "string") message = j.error;
    } catch {
      /* non-JSON */
    }
    throw new ApiError(res.status, message);
  }
  // All our endpoints return JSON.
  return (await res.json()) as T;
}

export const apiGet = <T>(path: string) => request<T>("GET", path);
export const apiPost = <T>(path: string, body?: unknown) => request<T>("POST", path, body);

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
export const addWallet = (req: AddWalletRequest) => apiPost<WalletView>("/wallet", req);
export const activateWallet = (id: string) =>
  apiPost<WalletView>(`/wallet/${encodeURIComponent(id)}/activate`);
export const removeWallet = (id: string, vaultPassword: string) =>
  apiDelete<{ removed: boolean }>(`/wallet/${encodeURIComponent(id)}`, { vault_password: vaultPassword });

export const getBalance = () => apiGet<Balance>("/wallet/balance");
export const getAddresses = () => apiGet<AddressView>("/wallet/addresses");
export const getTransactions = () => apiGet<Tx[]>("/wallet/transactions");
export const getDelegation = () => apiGet<DelegationView>("/wallet/delegation");
export const buildSend = (req: SendRequest) => apiPost<Preview>("/wallet/send", req);
export const confirmSend = (id: string, password: string) =>
  apiPost<TxResult>(`/wallet/send/${encodeURIComponent(id)}/confirm`, { password });
export const signData = (req: SignDataRequest) => apiPost<SignDataResult>("/wallet/sign-data", req);

// Staking & governance. Pool/DRep lookups verify a pasted ID through the node;
// buildDelegation returns an itemized preview; confirmDelegation signs + submits
// through the same Confirm path the send flow uses.
export const getPool = (id: string) => apiGet<PoolInfo>(`/wallet/pool/${encodeURIComponent(id)}`);
export const getDRep = (id: string) => apiGet<DRepInfo>(`/wallet/drep/${encodeURIComponent(id)}`);
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
export const poolBuildRegistrationAirGap = (
  req: PoolRegistrationParams & { vrf_key_hash_hex: string },
) => apiPost<PoolCertResult>("/wallet/pool/registration/airgap", req);
export const poolBuildRetirementCert = (req: {
  password?: string;
  cold_vkey_hex?: string;
  epoch: number;
}) => apiPost<PoolCertResult>("/wallet/pool/retirement/cert", req);
export const poolSubmitRetirement = (req: { password: string; epoch: number }) =>
  apiPost<TxResult>("/wallet/pool/retirement/submit", req);

// CIP-8/CIP-30 verification + air-gap signing.
export const verifyData = (req: VerifyDataRequest) =>
  apiPost<VerifyDataResult>("/wallet/verify-data", req);
export const exportUnsigned = (id: string) =>
  apiPost<UnsignedTx>(`/wallet/send/${encodeURIComponent(id)}/export-unsigned`);
export const signTx = (req: SignTxRequest) => apiPost<WitnessResult>("/wallet/sign-tx", req);
export const submitSigned = (req: SubmitSignedRequest) =>
  apiPost<TxResult>("/wallet/submit-signed", req);

// --- Native multi-signature ---
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

// --- Node-local DEX swap quotes ---
export const getDexPools = () => apiGet<DexPoolsResponse>("/wallet/dex/pools");
export const getDexQuote = (req: DexQuoteRequest) => apiPost<DexQuote>("/wallet/dex/quote", req);
