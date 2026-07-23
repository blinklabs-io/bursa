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
  Contact,
  DexPoolsResponse,
  AssetInfo,
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
  getContacts,
  getDexPools,
  getAssetMetadata,
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

export function useAsync<T>(
  fn: () => Promise<T>,
  opts?: { pollMs?: number; enabled?: boolean },
): AsyncState<T> {
  const [data, setData] = useState<T | null>(null);
  const [error, setError] = useState<Error | null>(null);
  const [loading, setLoading] = useState(true);
  const [tick, setTick] = useState(0);
  const enabled = opts?.enabled ?? true;
  const pollMs = opts?.pollMs;

  const refresh = useCallback(() => setTick((t) => t + 1), []);

  useEffect(() => {
    if (!enabled) {
      setLoading(false);
      return;
    }
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
    if (pollMs) {
      id = setInterval(() => run(false), pollMs);
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
  // CONTRACT: `fn` is deliberately omitted from the dependency array. Including
  // it would re-run this effect (tearing down the poll interval and event
  // listeners, then refetching) on every render where the caller passes a
  // freshly-created function — which is the common case, since inline
  // closures/arrow functions are new identities each render. Callers MUST
  // therefore pass a STABLE `fn`: a module-level function (as the useStatus,
  // useBalance, etc. helpers below do) or one wrapped in useCallback. A caller
  // that passes an unstable `fn` will silently only ever see the value from the
  // first render's closure. `refresh`/`tick` is the supported way to refetch.
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [tick, enabled, pollMs]);

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
export const useContacts = (): AsyncState<Contact[]> => useAsync(getContacts);
export const useDexPools = (): AsyncState<DexPoolsResponse> =>
  useAsync(getDexPools, { pollMs: 15000 });

// useAssetMetadata looks up on-chain metadata for a set of native-asset units
// (in parallel) and returns whatever resolved, keyed by unit. It is
// deliberately NOT a single useAsync call: assets are looked up individually
// against the node, and a lookup failing for one unit (not indexed, request
// error, etc.) must not prevent the others from displaying — the Portfolio
// screen falls back to the raw unit/quantity for any unit missing from the
// returned map.
export function useAssetMetadata(units: string[]): Record<string, AssetInfo | undefined> {
  const [metadata, setMetadata] = useState<Record<string, AssetInfo | undefined>>({});
  // Units are hex (policy id + asset name), so \0 can't collide with real
  // content; this just gives useEffect a stable dependency for "same set".
  // Dedupe + sort first so the key reflects set semantics — the caller only
  // cares which units are present, not their order or repeat count — so a
  // reorder (or a duplicate) of the same units doesn't retrigger lookups.
  const uniqueUnits = [...new Set(units)].sort();
  const key = uniqueUnits.join("\0");

  useEffect(() => {
    let cancelled = false;

    // Do not expose results for units from the previous request set while the
    // new lookups are pending.
    setMetadata({});

    // Publish each successful lookup immediately. A slow or rejected unit
    // must not delay metadata that the node has already returned for another.
    for (const unit of uniqueUnits) {
      getAssetMetadata(unit)
        .then((info) => {
          if (!cancelled) {
            setMetadata((current) => ({ ...current, [unit]: info }));
          }
        })
        .catch(() => {
          // Silently omit failures: callers fall back to the raw unit and
          // quantity, and the return type makes that absence explicit.
        });
    }

    return () => {
      cancelled = true;
    };
    // key summarizes `uniqueUnits` for this effect's purposes.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [key]);

  return metadata;
}
