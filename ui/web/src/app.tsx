import { useState, useEffect } from "react";
import type { ReactElement } from "react";
import type { Account, WalletView } from "./api/types";
import { useStatus, useVaultStatus, useAutoLock } from "./api/hooks";
import { lockVault, ApiError } from "./api/client";
import { getStoredDeviceKind } from "./hw/deviceKind";
import { useIdleLock } from "./useIdleLock";
import { Button } from "./components/Button";
import { SyncBanner } from "./components/SyncBanner";
import { WalletSwitcher } from "./components/WalletSwitcher";
import { MobileNav } from "./components/MobileNav";
import { ErrorBoundary } from "./components/ErrorBoundary";
import { useHashRoute, navigate } from "./router";
import { CreateVault } from "./screens/CreateVault";
import { UnlockVault } from "./screens/UnlockVault";
import { AddWallet } from "./screens/AddWallet";
import { MigrateLegacyKeystore } from "./screens/MigrateLegacyKeystore";
import { Syncing } from "./screens/Syncing";
import { Portfolio } from "./screens/Portfolio";
import { Receive } from "./screens/Receive";
import { Activity } from "./screens/Activity";
import { Send } from "./screens/Send";
import { Swap } from "./screens/Swap";
import { Stake } from "./screens/Stake";
import { Offline } from "./screens/Offline";
import { Operate } from "./screens/Operate";
import { MultiSig } from "./screens/MultiSig";
import { ImportTransaction } from "./screens/ImportTransaction";
import { Settings } from "./screens/Settings";
import { ConnectorApproval } from "./screens/ConnectorApproval";

// A Map (not a plain object) so a crafted hash like "#/constructor" or
// "#/toString" can't resolve to an inherited Object.prototype member and get
// rendered as a screen — unknown routes always fall back to Portfolio.
//
// Dual purpose, and NOT the same for every entry: `ROUTES.has(route)` (below,
// in the activeRoute/sidebar-highlight logic) treats every key here — plus
// "staking"/"sign"/etc., which aren't in this map at all — as a real,
// highlightable route. But `ROUTES.get(route)` is only reached by the final
// `else` in the content-selection branches further down, and "receive" and
// "activity" never reach it: they're intercepted by their own explicit
// `else if` branches earlier so they can be passed the active wallet's real
// `network` (this map's factories take no props). So `receive`/`activity`
// stay listed here for route-highlighting and prototype-pollution-safe
// lookup purposes only — their actual content never comes from this map.
const ROUTES = new Map<string, () => ReactElement>([
  ["portfolio", Portfolio],
  ["receive", Receive],
  ["activity", Activity],
  ["send", Send],
  ["swap", Swap],
]);

// Stake merged three screens; the old routes stay valid and open the matching
// tab so existing bookmarks and links keep working.
const STAKE_ROUTES = new Map<string, "delegation" | "rewards" | "pools">([
  ["stake", "delegation"],
  ["staking", "delegation"],
  ["rewards", "rewards"],
  ["pools", "pools"],
]);

// Settings absorbed the address book, message signing/verification and node
// diagnostics as panels; these routes still resolve so old links keep working.
const SETTINGS_ROUTES = new Map<string, "general" | "contacts" | "tools" | "diagnostics">([
  ["settings", "general"],
  ["contacts", "contacts"],
  ["sign", "tools"],
  ["verify", "tools"],
  ["diagnostics", "diagnostics"],
]);

// Send and Receive are actions on the Portfolio rather than destinations, so
// they keep their routes (deep links, and the Portfolio buttons) without
// costing a nav entry.
const PORTFOLIO_ROUTES = new Set(["portfolio", "send", "receive"]);

const NAV: { key: string; label: string }[] = [
  { key: "portfolio", label: "Portfolio" },
  { key: "activity", label: "Activity" },
  { key: "stake", label: "Stake" },
  { key: "swap", label: "Swap" },
  { key: "multisig", label: "Multi-sig" },
  { key: "import", label: "Import Tx" },
  { key: "offline", label: "Offline" },
  { key: "operate", label: "Operate" },
  { key: "settings", label: "Settings" },
];

// The active wallet drives the read/spend screens. Settings/SignMessage take an
// Account; map the active WalletView onto that shape (the server binds the
// active wallet, so only its display fields are needed here).
function toAccount(w: WalletView): Account {
  return {
    network: w.network,
    stake_address: w.stake_address,
    receive_addresses: w.addresses,
  };
}

export function App() {
  const status = useStatus();
  const vaultStatus = useVaultStatus();
  // Lifted here (rather than called again inside Settings/AutoLockCard) so
  // there is a single shared copy of the auto-lock setting: useIdleLock below
  // reads autoLock.data directly, and Settings is handed this same AsyncState
  // (autoLock.setData) so a save there updates the value useIdleLock sees in
  // this same session, with no reload. A second independent useAutoLock()
  // instance inside Settings would have its own useState and never be seen by
  // the idle timer here (see useAsync in api/hooks.ts: no shared cache).
  const autoLock = useAutoLock();
  const route = useHashRoute();

  // Vault session state, established after create/unlock and kept in memory.
  const [wallets, setWallets] = useState<WalletView[]>([]);
  const [activeId, setActiveId] = useState<string | null>(null);
  // unlocked tracks whether this session has unlocked the vault (create or
  // unlock). The server is the source of truth via /vault/status, but we keep a
  // client flag so the UI transitions immediately after the action.
  const [unlocked, setUnlocked] = useState(false);
  // addingWallet overlays the Add-wallet form on top of the unlocked UI.
  const [addingWallet, setAddingWallet] = useState(false);
  const [skipLegacyImport, setSkipLegacyImport] = useState(false);
  // Set when the user chooses to open the vault flow while the node is still
  // syncing, dismissing the boot Syncing view for this session.
  const [loadAnyway, setLoadAnyway] = useState(false);
  const [lockError, setLockError] = useState<string | null>(null);

  const activeWallet = wallets.find((w) => w.id === activeId) ?? null;
  const isReady = status.data?.state === "ready";
  const canQueryNode = status.data?.state === "ready" || status.data?.state === "syncing";
  // Regular sends require a fully synced node and either a full wallet (local
  // seed signing) or a hardware wallet (on-device signing). Read-only and
  // multi-signature wallets use their own non-local signing flows.
  const canSend = isReady && (
    activeWallet?.type === "full" || activeWallet?.type === "hardware"
  );
  // Sign/Offline/Operate all need the wallet's seed (message signing, air-gap
  // signing, and cold/VRF/KES key derivation respectively). Hardware wallets
  // are seedless (xpub-only) and sign only via the on-device path Send uses,
  // so these flows must stay off for them.
  const canSign = activeWallet?.type === "full";
  // Multi-sig build/collect/submit only needs the same synced-node access as a
  // regular send. Its optional "Sign here" and participant-key reveal actions
  // derive CIP-1854 keys from the local seed, so those actions remain gated by
  // canSign until Ledger multi-sig signing is available.
  // Swap shows node-local DEX prices/quotes (no spending, no signing), but
  // the DEX pool locators are mainnet-only. On preview/preprod the backend
  // returns ErrNotMainnet, so do not expose the route for testnet wallets.
  const canSwap = canQueryNode && activeWallet?.network === "mainnet";

  function applyWallets(list: WalletView[]) {
    setLockError(null);
    setWallets(list);
    const active = list.find((w) => w.active);
    setActiveId(active ? active.id : null);
    setUnlocked(true);
  }

  function applyAdded(wallet: WalletView) {
    // A newly added wallet becomes active server-side; merge it in and select it.
    setLockError(null);
    setWallets((prev) => {
      const without = prev.filter((w) => w.id !== wallet.id);
      return [...without.map((w) => ({ ...w, active: false })), { ...wallet, active: true }];
    });
    setActiveId(wallet.id);
    setUnlocked(true);
    setAddingWallet(false);
  }

  function applyActivated(wallet: WalletView) {
    setLockError(null);
    setWallets((prev) => prev.map((w) => ({ ...w, active: w.id === wallet.id })));
    setActiveId(wallet.id);
  }

  // applyAccountChanged replaces the active wallet's record with the updated one
  // returned after a BIP44 account switch / new-account derivation, so the whole
  // app (keyed by wallet id + active account index) rebinds to it.
  function applyAccountChanged(wallet: WalletView) {
    setLockError(null);
    setWallets((prev) => prev.map((w) => (w.id === wallet.id ? { ...wallet, active: true } : w)));
    setActiveId(wallet.id);
  }

  async function handleLock() {
    setLockError(null);
    try {
      await lockVault();
      setWallets([]);
      setActiveId(null);
      setUnlocked(false);
      setAddingWallet(false);
      navigate("portfolio");
      vaultStatus.refresh();
    } catch (err) {
      setLockError(err instanceof ApiError ? err.message : "Could not lock vault");
      vaultStatus.refresh();
    }
  }

  // Idle auto-lock: re-locks the vault after the persisted timeout elapses
  // with no pointer/keyboard/visibility activity (see useIdleLock). Only runs
  // once the vault is actually unlocked — locking an already-locked vault is
  // harmless but pointless. Default to Off (0) only while the setting is
  // still loading (nothing is known yet); if loading finishes and the fetch
  // failed (autoLock.data stays null), fail SAFE by assuming the default
  // timeout rather than fail OPEN by leaving auto-lock permanently disabled.
  useIdleLock(autoLock.loading ? 0 : (autoLock.data?.minutes ?? 15), () => void handleLock(), unlocked);

  // --- Pre-unlock flows: render full-screen, no sidebar -------------------

  // While the vault status is loading, show nothing (avoids a flash of the
  // wrong screen before we know whether a vault exists).
  if (!vaultStatus.data && vaultStatus.loading) {
    return <div className="app" />;
  }

  const vault = vaultStatus.data;
  // The embedded node runs exactly one network; the create/add-wallet flows
  // derive it from the live node status rather than letting the user pick a
  // network that would never match the node (the backend rejects a mismatch).
  const network = status.data?.network ?? "";

  if (!vault) {
    return (
      <FullScreen status={status.data}>
        <VaultStatusUnavailable
          error={vaultStatus.error}
          onRetry={vaultStatus.refresh}
        />
      </FullScreen>
    );
  }

  // Boot gate: before the vault is open, if the node isn't ready and the user
  // hasn't opted to proceed, the Syncing view takes the whole screen. The escape
  // hatch drops to the vault create/unlock flow for read-only operation while
  // syncing continues.
  if (!unlocked && !loadAnyway && status.data && status.data.state !== "ready") {
    return (
      <div className="app">
        <OfflineBanner />
        <SyncBanner status={status.data} />
        <main className="content content-boot">
          <Syncing status={status.data} onLoadAnyway={() => setLoadAnyway(true)} />
        </main>
      </div>
    );
  }

  // No vault yet → first-run: create vault + add first wallet.
  if (vault && !vault.exists && !unlocked) {
    if (vault.legacy_keystore && !skipLegacyImport) {
      return (
        <FullScreen status={status.data}>
          <MigrateLegacyKeystore
            onReady={(wallet) => applyWallets([{ ...wallet, active: true }])}
            onCreateNew={() => setSkipLegacyImport(true)}
          />
        </FullScreen>
      );
    }
    return (
      <FullScreen status={status.data}>
        <CreateVault network={network} onReady={applyAdded} />
      </FullScreen>
    );
  }

  // Vault exists but this session has not unlocked it → unlock (vault pw only).
  if (vault && vault.exists && !unlocked) {
    return (
      <FullScreen status={status.data}>
        <UnlockVault walletCount={vault.wallet_count} onUnlocked={applyWallets} />
      </FullScreen>
    );
  }

  // Staking/governance needs a fully synced node AND a wallet that can witness a
  // certificate tx: a full (local-seed) wallet, or a SeedSigner hardware wallet
  // (its air-gapped QR device supports certificates/votes). Ledger/Trezor/
  // Keystone hardware wallets can't sign certificates on-device yet, so they —
  // like read-only and unsynced wallets — fall back to Portfolio.
  const canStake =
    isReady &&
    (activeWallet?.type === "full" ||
      (activeWallet?.type === "hardware" &&
        getStoredDeviceKind(activeWallet.id) === "seedsigner"));

  // --- Unlocked: the normal wallet UI bound to the active wallet ----------

  // Which nav entry maps to the screen currently shown (mirrors the content
  // resolution below) so the sidebar can highlight the active route.
  let activeRoute = "";
  if (!addingWallet && activeWallet !== null) {
    if (SETTINGS_ROUTES.has(route)) activeRoute = "settings";
    else if (PORTFOLIO_ROUTES.has(route)) activeRoute = "portfolio";
    else if (route === "swap" && canSwap) activeRoute = "swap";
    // The legacy per-screen routes now resolve to tabs of the merged screen,
    // so an old bookmark or a link in the wild still highlights Stake. No node
    // condition here: the screen itself is ungated, and a highlight that
    // disagreed with what is rendered would point at Portfolio while Stake is
    // on screen — and mislabel the error boundary with it.
    else if (STAKE_ROUTES.has(route)) activeRoute = "stake";
    else if (route === "offline" && canSign) activeRoute = "offline";
    else if (route === "operate" && canSign) activeRoute = "operate";
    else if (route === "multisig") activeRoute = "multisig";
    else if (route === "import" && canSign) activeRoute = "import";
    else if (ROUTES.has(route) && route !== "swap") activeRoute = route;
    else activeRoute = "portfolio";
  }

  // What the boundary calls the failed screen. Deliberately NOT activeRoute:
  // that is the NAV highlight, which collapses several routes onto one entry
  // (send/receive highlight Portfolio, the stake family highlights Stake), so a
  // fallback reading "the portfolio screen could not be displayed" while Send
  // is what broke sends the reader to the wrong place.
  //
  // Nor is the raw route enough on its own: several branches below decline the
  // requested screen and render Portfolio instead, and naming the route the
  // user ASKED for would point at a screen that is not on display either. Each
  // such branch corrects this to what it actually rendered.
  let screenLabel = route || "wallet";

  let content: ReactElement;
  if (addingWallet) {
    screenLabel = "add wallet";
    content = (
      <AddWallet
        network={network}
        onAdded={applyAdded}
        onCancel={() => setAddingWallet(false)}
      />
    );
  } else if (activeWallet === null) {
    screenLabel = "wallet";
    // Unlocked with multiple wallets and none selected yet: prompt to pick one.
    // On mobile the sidebar is hidden, so direct the user to the drawer instead.
    content = (
      <section className="card">
        <h2>Select a wallet</h2>
        <p className="helper-text">
          Add or select a wallet to continue.{" "}
          <span className="mobile-hint">Open the menu (☰) to see your wallets.</span>
          <span className="desktop-hint">Choose a wallet from the sidebar.</span>
        </p>
      </section>
    );
  } else if (SETTINGS_ROUTES.has(route)) {
    content = (
      <Settings
        account={toAccount(activeWallet)}
        walletType={activeWallet.type}
        autoLock={autoLock}
        canSign={canSign}
        initialTab={SETTINGS_ROUTES.get(route)}
      />
    );
  } else if (route === "send" && !canSend) {
    screenLabel = "portfolio";
    content = <Portfolio canSend={canSend} />;
  } else if (route === "send" && canSend) {
    content = <Send isHardware={activeWallet.type === "hardware"} walletId={activeWallet.id} />;
  } else if (route === "swap" && !canSwap) {
    // Guard deep-links (#/swap): DEX quotes need a queryable mainnet node, so
    // fall back to Portfolio while the node or active wallet cannot support it.
    screenLabel = "portfolio";
    content = <Portfolio canSend={canSend} />;
  } else if (STAKE_ROUTES.has(route)) {
    // Delegation, rewards and the pool directory are one screen, and it is not
    // gated as a whole: reward history is a plain account read that the old
    // #/rewards route offered to any active wallet whatever the node was
    // doing, and merging the screens must not quietly take that away. Each tab
    // states its own requirement instead — Delegation when this wallet cannot
    // sign a certificate, Pools when the node cannot answer queries.
    content = (
      <Stake
        network={activeWallet.network}
        isHardware={activeWallet.type === "hardware"}
        walletId={activeWallet.id}
        canDelegate={canStake}
        canQueryNode={canQueryNode}
        initialTab={STAKE_ROUTES.get(route)}
      />
    );
  } else if (route === "offline") {
    // Air-gap signing needs the active wallet's seed (to sign) but no node for
    // the sign step; falls back to Portfolio without an active wallet.
    if (!canSign) screenLabel = "portfolio";
    content = canSign ? <Offline /> : <Portfolio canSend={canSend} />;
  } else if (route === "operate") {
    // Pool operations derive cold/VRF/KES keys from the seed and need the spend
    // password. A wallet must be active; otherwise fall back to Portfolio. Most
    // pool ops are offline; only retirement submission needs a synced node,
    // gated at the API.
    if (!canSign) screenLabel = "portfolio";
    content = canSign ? <Operate account={toAccount(activeWallet)} /> : <Portfolio canSend={canSend} />;
  } else if (route === "multisig") {
    // Managing multi-sig accounts (list/create/view) is local state and works on
    // any active wallet. Building and submitting spends requires a synced node;
    // only local CIP-1854 key derivation/signing additionally requires a seed.
    content = <MultiSig canSpend={isReady} canSign={canSign} />;
  } else if (route === "import") {
    // Importing a transaction built elsewhere needs the active wallet's seed
    // to add a signature (like Offline/Operate); submitting is separately
    // gated inside the screen on the node being ready (canSubmit).
    if (!canSign) screenLabel = "portfolio";
    content = canSign ? <ImportTransaction canSubmit={isReady} /> : <Portfolio canSend={canSend} />;
  } else if (route === "receive") {
    // Explorer links on each address need the active wallet's real network
    // (preview/preprod/mainnet), which the generic ROUTES map (no props)
    // can't carry.
    content = <Receive network={activeWallet.network} />;
  } else if (route === "activity") {
    // Same reasoning as "receive": the tx-hash explorer link needs the
    // active wallet's network.
    content = <Activity network={activeWallet.network} />;
  } else {
    // Portfolio is both a listed route and the fallback for anything
    // unrecognised, and it needs canSend for its Send action — which, now that
    // Send is not in the nav, is the only way to reach the send flow. Resolving
    // it through the props-less ROUTES map would silently disable it.
    const Screen = ROUTES.get(route);
    if (!Screen) screenLabel = "portfolio";
    content = Screen && route !== "portfolio" ? <Screen /> : <Portfolio canSend={canSend} />;
  }

  // Build the nav item descriptors once, shared between desktop sidebar and
  // mobile drawer so gating logic only lives in one place.
  const navItems = NAV.map(({ key, label }) => {
    const gated =
      activeWallet === null ||
      addingWallet ||
      (key === "swap" && !canSwap) ||
      (key === "offline" && !canSign) ||
      (key === "operate" && !canSign) ||
      (key === "import" && !canSign);
    return { key, label, disabled: gated, active: key === activeRoute };
  });

  return (
    <div className="app">
      <OfflineBanner />
      {status.data && <SyncBanner status={status.data} />}

      {/* Mobile-only: top bar + slide-out drawer. Hidden on desktop via CSS. */}
      <MobileNav
        status={status.data ?? null}
        activeWallet={activeWallet}
        wallets={wallets}
        activeId={activeId}
        lockError={lockError}
        navItems={navItems}
        onActivated={applyActivated}
        onAddWallet={() => setAddingWallet(true)}
        onLock={handleLock}
        onNavigate={navigate}
        onAccountChanged={applyAccountChanged}
      />

      <div className="layout">
        {/* Desktop sidebar. Hidden on mobile via CSS. */}
        <nav className="sidebar">
          <div className="brand">
            <span className="brand-mark">BVRSA</span>
            <span className="brand-motto">nodvs tvvs · claves tvæ</span>
          </div>
          <WalletSwitcher
            wallets={wallets}
            activeId={activeId}
            onActivated={applyActivated}
            onAddWallet={() => setAddingWallet(true)}
            onLock={handleLock}
            onAccountChanged={applyAccountChanged}
          />
          {lockError && (
            <p className="error-text" role="alert">
              {lockError}
            </p>
          )}
          {navItems.map(({ key, label, disabled, active }) => (
            <button
              key={key}
              className={active ? "nav-item active" : "nav-item"}
              aria-current={active ? "page" : undefined}
              disabled={disabled}
              onClick={() => navigate(key)}
            >
              {label}
            </button>
          ))}
        </nav>
        <main
          className="content"
          key={`${activeWallet?.id ?? "none"}:${activeWallet?.active_account_index ?? 0}`}
        >
          {/* Scoped to the screen, not the shell: a screen that throws must not
              take the nav and wallet switcher with it, or there is no way to
              navigate out of the failure. resetKey clears the error on
              navigation. */}
          {/* resetKey is the raw route, not activeRoute: the latter collapses
              stake/staking/rewards/pools to one nav key, so moving between
              those would not clear a caught error. addingWallet is in the key
              too — it swaps the content without changing the route, and is a
              shell recovery action that must not land on a stale fallback. */}
          <ErrorBoundary
            label={screenLabel}
            resetKey={`${route}:${addingWallet}`}
          >
            {content}
          </ErrorBoundary>
        </main>
      </div>
      {/* Global connector approval overlay: rendered on top of all screens when
          a dApp has pending consent requests. Mounts regardless of current route
          so requests are never silently missed. */}
      <ConnectorApproval />
    </div>
  );
}

// FullScreen wraps a pre-unlock screen (create/unlock) with the sync banner but
// no sidebar — there is no active wallet to navigate yet.
function FullScreen({
  status,
  children,
}: {
  status: ReturnType<typeof useStatus>["data"];
  children: ReactElement;
}) {
  return (
    <div className="app">
      <OfflineBanner />
      {status && <SyncBanner status={status} />}
      <main className="content content-centered">{children}</main>
    </div>
  );
}

function VaultStatusUnavailable({
  error,
  onRetry,
}: {
  error: Error | null;
  onRetry: () => void;
}) {
  return (
    <section className="card">
      <h2>Vault status unavailable</h2>
      <p className="error-text" role="alert">
        {error?.message ?? "Vault status is unavailable"}
      </p>
      <Button onClick={onRetry}>Retry</Button>
    </section>
  );
}

// Small dismissible banner that appears when the browser reports no network.
function OfflineBanner() {
  const [offline, setOffline] = useState(!navigator.onLine);
  const [dismissed, setDismissed] = useState(false);

  useEffect(() => {
    const onOffline = () => { setOffline(true); setDismissed(false); };
    const onOnline = () => { setOffline(false); setDismissed(false); };
    window.addEventListener("offline", onOffline);
    window.addEventListener("online", onOnline);
    return () => {
      window.removeEventListener("offline", onOffline);
      window.removeEventListener("online", onOnline);
    };
  }, []);

  if (!offline || dismissed) return null;

  return (
    <div
      role="alert"
      aria-label="offline"
      className="offline-banner"
    >
      <span>You are offline. Some features may be unavailable.</span>
      <button
        className="offline-banner-dismiss"
        aria-label="dismiss"
        onClick={() => setDismissed(true)}
      >
        ✕
      </button>
    </div>
  );
}
