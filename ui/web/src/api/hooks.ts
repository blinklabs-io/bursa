import { useState, useEffect, useCallback } from "react";
import type {
  Status,
  Balance,
  AddressView,
  Tx,
  DelegationView,
  VaultStatus,
  HistoryExpirySetting,
  AutoLockSetting,
  TPMStatus,
} from "./types";
import {
  getStatus,
  getVaultStatus,
  getBalance,
  getAddresses,
  getTransactions,
  getDelegation,
  getHistoryExpiry,
  getAutoLock,
  getTPMStatus,
} from "./client";

export interface AsyncState<T> {
  data: T | null;
  error: Error | null;
  loading: boolean;
  refresh: () => void;
  // setData lets a caller apply a fresher value it already holds (e.g. the body
  // a mutation POST returned), so the UI reflects the new state even if the
  // follow-up refresh GET later fails.
  setData: (value: T) => void;
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
      // Suspend polling when the network is down or the page is hidden — avoid
      // firing requests into a dead network or a backgrounded tab.
      if (!isInitial && (!navigator.onLine || document.hidden)) return;
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

    // When the network comes back, trigger an immediate refetch so the UI
    // recovers without waiting for the next poll interval.
    const onOnline = () => run(false);
    window.addEventListener("online", onOnline);

    // When the app returns from the background (tab/app becomes visible),
    // trigger an immediate refetch so the UI reflects any state changes that
    // occurred while it was suspended. The run() guard already skips the call
    // when document.hidden is true, so a hidden→hidden transition is a no-op.
    const onVisibilityChange = () => run(false);
    document.addEventListener("visibilitychange", onVisibilityChange);

    return () => {
      cancelled = true;
      if (id !== undefined) clearInterval(id);
      window.removeEventListener("online", onOnline);
      document.removeEventListener("visibilitychange", onVisibilityChange);
    };
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [tick]);

  const applyData = useCallback((value: T) => {
    setData(value);
    setError(null);
  }, []);

  return { data, error, loading, refresh, setData: applyData };
}

export const useStatus = (): AsyncState<Status> => useAsync(getStatus, { pollMs: 2000 });
export const useVaultStatus = (): AsyncState<VaultStatus> => useAsync(getVaultStatus);
export const useBalance = (): AsyncState<Balance> => useAsync(getBalance);
export const useAddresses = (): AsyncState<AddressView> => useAsync(getAddresses);
export const useTransactions = (): AsyncState<Tx[]> => useAsync(getTransactions);
export const useDelegation = (): AsyncState<DelegationView> => useAsync(getDelegation);
export const useHistoryExpiry = (): AsyncState<HistoryExpirySetting> => useAsync(getHistoryExpiry);
export const useAutoLock = (): AsyncState<AutoLockSetting> => useAsync(getAutoLock);
export const useTPMStatus = (): AsyncState<TPMStatus> => useAsync(getTPMStatus);
