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
  HistoryExpirySetting,
  VerifyDataRequest,
  VerifyDataResult,
  UnsignedTx,
  WitnessResult,
  SignTxRequest,
  SubmitSignedRequest,
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
  TPMStatus,
  EnableTPMRequest,
  DisableTPMRequest,
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
export const getHistoryExpiry = () =>
  apiGet<HistoryExpirySetting>("/wallet/settings/history-expiry");
export const setHistoryExpiry = (enabled: boolean) =>
  apiPut<HistoryExpirySetting>("/wallet/settings/history-expiry", { enabled });
export const verifyData = (req: VerifyDataRequest) =>
  apiPost<VerifyDataResult>("/wallet/verify-data", req);
export const exportUnsigned = (id: string) =>
  apiPost<UnsignedTx>(`/wallet/send/${encodeURIComponent(id)}/export-unsigned`);
export const signTx = (req: SignTxRequest) => apiPost<WitnessResult>("/wallet/sign-tx", req);
export const submitSigned = (req: SubmitSignedRequest) =>
  apiPost<TxResult>("/wallet/submit-signed", req);

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
