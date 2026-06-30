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

async function request<T>(method: string, path: string, body?: unknown): Promise<T> {
  let lastNetworkError: ApiError | null = null;

  for (let attempt = 0; attempt < RETRY_ATTEMPTS; attempt++) {
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
