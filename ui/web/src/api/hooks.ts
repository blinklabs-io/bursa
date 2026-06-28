import { useState, useEffect, useCallback } from "react";
import type {
  Status,
  Balance,
  AddressView,
  Tx,
  DelegationView,
  VaultStatus,
  HistoryExpirySetting,
} from "./types";
import {
  getStatus,
  getVaultStatus,
  getBalance,
  getAddresses,
  getTransactions,
  getDelegation,
  getHistoryExpiry,
} from "./client";

export interface AsyncState<T> {
  data: T | null;
  error: Error | null;
  loading: boolean;
  refresh: () => void;
}

export function useAsync<T>(fn: () => Promise<T>, opts?: { pollMs?: number }): AsyncState<T> {
  const [data, setData] = useState<T | null>(null);
  const [error, setError] = useState<Error | null>(null);
  const [loading, setLoading] = useState(true);
  const [tick, setTick] = useState(0);

  const refresh = useCallback(() => setTick((t) => t + 1), []);

  useEffect(() => {
    let cancelled = false;
    let inFlight = false;

    const run = (isInitial: boolean) => {
      // Skip if a request is still pending: prevents overlapping polls and
      // out-of-order responses from overwriting fresher data.
      if (inFlight) return;
      inFlight = true;
      // Only show loading spinner on the initial fetch; polls update data in place.
      if (isInitial) setLoading(true);
      fn()
        .then((result) => {
          if (!cancelled) {
            setData(result);
            setError(null);
          }
        })
        .catch((err: Error) => {
          if (!cancelled) setError(err);
        })
        .finally(() => {
          inFlight = false;
          if (!cancelled && isInitial) setLoading(false);
        });
    };

    run(true);

    let id: ReturnType<typeof setInterval> | undefined;
    if (opts?.pollMs) {
      id = setInterval(() => run(false), opts.pollMs);
    }

    return () => {
      cancelled = true;
      if (id !== undefined) clearInterval(id);
    };
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [tick]);

  return { data, error, loading, refresh };
}

export const useStatus = (): AsyncState<Status> => useAsync(getStatus, { pollMs: 2000 });
export const useVaultStatus = (): AsyncState<VaultStatus> => useAsync(getVaultStatus);
export const useBalance = (): AsyncState<Balance> => useAsync(getBalance);
export const useAddresses = (): AsyncState<AddressView> => useAsync(getAddresses);
export const useTransactions = (): AsyncState<Tx[]> => useAsync(getTransactions);
export const useDelegation = (): AsyncState<DelegationView> => useAsync(getDelegation);
export const useHistoryExpiry = (): AsyncState<HistoryExpirySetting> => useAsync(getHistoryExpiry);
