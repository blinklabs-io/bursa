import { useState, useEffect, useCallback } from "react";
import type {
  Status,
  Balance,
  AddressView,
  Tx,
  DelegationView,
  RewardHistory,
  VaultStatus,
  AccountsResponse,
  HistoryExpirySetting,
  AutoLockSetting,
  TPMStatus,
  Contact,
  DexPoolsResponse,
  AssetInfo,
  NFT,
  Diagnostics,
} from "./types";
import {
  getStatus,
  getVaultStatus,
  getAccounts,
  getBalance,
  getAddresses,
  getTransactions,
  getDelegation,
  getRewards,
  getHistoryExpiry,
  getAutoLock,
  getTPMStatus,
  getContacts,
  getDexPools,
  getAssetMetadata,
  getNfts,
  getNftMedia,
  setNftMedia,
  getNotifications,
  setNotifications,
  getActivity,
  getDiagnostics,
} from "./client";
import {
  notificationPermission,
  requestNotificationPermission,
  notificationsSupported,
  raiseActivityNotification,
} from "../notifications";

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
  // that passes an unstable `fn` keeps the previously-captured closure only
  // until one of the effect deps (`refresh`/`tick`, `enabled`, or `pollMs`)
  // changes and re-runs the effect, at which point the LATEST `fn` is captured;
  // it is not permanently stuck on the first render's closure. `refresh` is the
  // supported way to refetch.
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
export const useRewards = (): AsyncState<RewardHistory> => useAsync(getRewards);
export const useHistoryExpiry = (): AsyncState<HistoryExpirySetting> => useAsync(getHistoryExpiry);
export const useAutoLock = (): AsyncState<AutoLockSetting> => useAsync(getAutoLock);
export const useTPMStatus = (): AsyncState<TPMStatus> => useAsync(getTPMStatus);
export const useContacts = (): AsyncState<Contact[]> => useAsync(getContacts);
// useAccounts lists the active wallet's BIP44 accounts (with node-local balance
// summaries). It is enabled only once a wallet is active; the caller refreshes
// it after an account is added or the active wallet changes.
export const useAccounts = (enabled: boolean): AsyncState<AccountsResponse> =>
  useAsync(getAccounts, { enabled });
export const useDexPools = (): AsyncState<DexPoolsResponse> =>
  useAsync(getDexPools, { pollMs: 15000 });
export const useNfts = (): AsyncState<NFT[]> => useAsync(getNfts);
// Diagnostics live-polls like status (node-local, cheap). 5s is frequent
// enough to watch peers/sync move without hammering the node.
export const useDiagnostics = (): AsyncState<Diagnostics> =>
  useAsync(getDiagnostics, { pollMs: 5000 });

export interface NftMediaState {
  enabled: boolean;
  loading: boolean;
  saving: boolean;
  error: Error | null;
  setEnabled: (next: boolean) => Promise<void>;
}

export function useNftMedia(): NftMediaState {
  const [enabled, setEnabled] = useState(false);
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState<Error | null>(null);

  useEffect(() => {
    let cancelled = false;
    getNftMedia()
      .then((setting) => {
        if (!cancelled) setEnabled(setting.enabled);
      })
      .catch((err: Error) => {
        if (!cancelled) setError(err);
      })
      .finally(() => {
        if (!cancelled) setLoading(false);
      });
    return () => { cancelled = true; };
  }, []);

  const set = useCallback(async (next: boolean) => {
    setSaving(true);
    setError(null);
    try {
      const setting = await setNftMedia(next);
      setEnabled(setting.enabled);
    } catch (err) {
      setError(err as Error);
    } finally {
      setSaving(false);
    }
  }, []);

  return { enabled, loading, saving, error, setEnabled: set };
}

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

// NotificationsState backs the Settings toggle for node-local wallet-activity
// notifications. `enabled` is the persisted preference (default off);
// `permission` is the browser Notification permission ("unsupported" when the
// API is absent, e.g. an OS-bridge-only desktop build). setEnabled(true)
// requests the browser permission first (only ever in response to the user
// opting in) and then persists the preference to the backend.
export interface NotificationsState {
  enabled: boolean;
  permission: NotificationPermission | "unsupported";
  supported: boolean;
  loading: boolean;
  saving: boolean;
  error: Error | null;
  setEnabled: (next: boolean) => Promise<void>;
}

export function useNotifications(): NotificationsState {
  const [enabled, setEnabledState] = useState(false);
  const [permission, setPermission] = useState<NotificationPermission | "unsupported">(
    () => notificationPermission(),
  );
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState<Error | null>(null);

  useEffect(() => {
    let cancelled = false;
    getNotifications()
      .then((setting) => {
        if (!cancelled) setEnabledState(setting.enabled);
      })
      .catch((err: Error) => {
        if (!cancelled) setError(err);
      })
      .finally(() => {
        if (!cancelled) setLoading(false);
      });
    return () => {
      cancelled = true;
    };
  }, []);

  const set = useCallback(async (next: boolean) => {
    setSaving(true);
    setError(null);
    try {
      // Ask for the OS/browser permission only when turning notifications ON,
      // and only here — i.e. as a direct result of the user opting in.
      if (next) {
        setPermission(await requestNotificationPermission());
      }
      const setting = await setNotifications(next);
      setEnabledState(setting.enabled);
    } catch (err) {
      setError(err as Error);
    } finally {
      setSaving(false);
    }
  }, []);

  return {
    enabled,
    permission,
    supported: notificationsSupported(),
    loading,
    saving,
    error,
    setEnabled: set,
  };
}

// How often the activity poller asks the node for new wallet activity. Kept well
// above the status poll (2s) so it stays cheap — notifications are not
// latency-critical, and each poll runs the wallet's tx-history enrichment.
const ACTIVITY_POLL_MS = 30000;

// useActivityNotifications polls GET /wallet/activity while `active` and raises a
// desktop/browser notification for each new event the backend reports. The
// backend dedups server-side (its first poll after a wallet binds primes a
// baseline and returns nothing, so history never notifies); a client-side seen
// set guards against a re-render or overlapping poll double-raising within a
// session. Pass active=false (wallet locked, notifications disabled, or no way
// to notify) to stop polling entirely.
//
// walletId restarts the poller (and its seen set) whenever the active wallet
// changes: the backend's dedup baseline is per-wallet, so a client-side seen
// set that outlived a wallet switch could suppress a reward/tx notification
// for the newly active wallet just because the same id was already seen for
// the previous one (e.g. reward ids are only "reward:<epoch>").
export function useActivityNotifications(active: boolean, walletId: string | null): void {
  useEffect(() => {
    if (!active) return;
    let cancelled = false;
    let inFlight = false;
    const seen = new Set<string>();

    const run = () => {
      // Match useAsync: don't poll into a dead network or a backgrounded tab,
      // and never overlap requests.
      if (!navigator.onLine || document.hidden || inFlight) return;
      inFlight = true;
      getActivity()
        .then(async (res) => {
          if (cancelled) return;
          for (const event of res.events) {
            if (seen.has(event.id)) continue;
            // Re-check cancellation before every raise, not just once above:
            // raiseActivityNotification is async, so each iteration's await
            // can yield past a wallet switch/lock that tore this effect down
            // mid-loop. Without this, a still-in-flight iteration would go on
            // to notify for a wallet that is no longer active.
            if (cancelled) return;
            // Delivery here is best-effort/fire-and-forget: the server-side
            // activity detector (ui/internal/activity) already removes each
            // event from what it will ever report again the moment it is
            // included in a poll response, regardless of what happens to it
            // client-side. So a failed raise (constructor/bridge failure, or
            // on the desktop bridge a failed OS notifier start) is NOT
            // retried on a later poll — there is no redelivery. Gating on the
            // result still avoids adding a failed event to this session's
            // local dedup set for no reason, but it is not a retry mechanism.
            if (await raiseActivityNotification(event, walletId ?? "")) {
              seen.add(event.id);
            }
          }
        })
        .catch(() => {
          // Best-effort: a failed poll (node busy, transient error) must not
          // break the loop or surface an error — the next tick retries.
        })
        .finally(() => {
          inFlight = false;
        });
    };

    // Prime immediately so the backend establishes its baseline right away, then
    // poll on the interval.
    run();
    const id = setInterval(run, ACTIVITY_POLL_MS);
    return () => {
      cancelled = true;
      clearInterval(id);
    };
  }, [active, walletId]);
}
