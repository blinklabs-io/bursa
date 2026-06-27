import type {
  Status,
  Account,
  Balance,
  AddressView,
  Tx,
  DelegationView,
  Preview,
  TxResult,
  SendRequest,
  LoadWalletRequest,
  CreateKeystoreRequest,
  SignDataRequest,
  SignDataResult,
  PoolCredentials,
  KESPeriodInfo,
  OpCert,
  OpCertPayload,
  PoolMetadataInput,
  PoolMetadataResult,
  PoolRegistrationParams,
  PoolCertResult,
  PoolIDResult,
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

export const getStatus = () => apiGet<Status>("/status");
export const loadWallet = (req: LoadWalletRequest) => apiPost<Account>("/wallet", req);
export const createKeystore = (req: CreateKeystoreRequest) => apiPost<Account>("/wallet/keystore", req);
export const getBalance = () => apiGet<Balance>("/wallet/balance");
export const getAddresses = () => apiGet<AddressView>("/wallet/addresses");
export const getTransactions = () => apiGet<Tx[]>("/wallet/transactions");
export const getDelegation = () => apiGet<DelegationView>("/wallet/delegation");
export const buildSend = (req: SendRequest) => apiPost<Preview>("/wallet/send", req);
export const confirmSend = (id: string, password: string) =>
  apiPost<TxResult>(`/wallet/send/${encodeURIComponent(id)}/confirm`, { password });
export const signData = (req: SignDataRequest) => apiPost<SignDataResult>("/wallet/sign-data", req);

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
