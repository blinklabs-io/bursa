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
