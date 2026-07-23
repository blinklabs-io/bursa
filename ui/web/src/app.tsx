import { useState, useEffect } from "react";
import type { ReactElement } from "react";
import type { Account, WalletView } from "./api/types";
import { useStatus, useVaultStatus, useAutoLock } from "./api/hooks";
import { lockVault, ApiError } from "./api/client";
import { useIdleLock } from "./useIdleLock";
import { Button } from "./components/Button";
import { SyncBanner } from "./components/SyncBanner";
import { WalletSwitcher } from "./components/WalletSwitcher";
import { MobileNav } from "./components/MobileNav";
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
import { Contacts } from "./screens/Contacts";
import { Staking } from "./screens/Staking";
import { SignMessage } from "./screens/SignMessage";
import { VerifyMessage } from "./screens/VerifyMessage";
import { Offline } from "./screens/Offline";
import { Operate } from "./screens/Operate";
import { MultiSig } from "./screens/MultiSig";
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
  ["contacts", Contacts],
]);

const NAV: { key: string; label: string }[] = [
  { key: "portfolio", label: "Portfolio" },
  { key: "receive", label: "Receive" },
  { key: "activity", label: "Activity" },
  { key: "send", label: "Send" },
  { key: "swap", label: "Swap" },
  { key: "contacts", label: "Contacts" },
  { key: "staking", label: "Staking" },
  { key: "sign", label: "Sign" },
  { key: "verify", label: "Verify" },
  { key: "offline", label: "Offline" },
  { key: "operate", label: "Operate" },
  { key: "multisig", label: "Multi-sig" },
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
  const network = "preview";

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

  // Staking/governance is gated identically to send: a fully synced node AND an
  // active (spending-capable) wallet. A read-only or unsynced wallet falls back
  // to Portfolio. Certificates also aren't supported on hardware yet (see
  // spend.HardwareSignRequest), so hardware wallets are excluded too.
  const canStake = isReady && activeWallet?.type === "full";

  // --- Unlocked: the normal wallet UI bound to the active wallet ----------

  // Which nav entry maps to the screen currently shown (mirrors the content
  // resolution below) so the sidebar can highlight the active route.
  let activeRoute = "";
  if (!addingWallet && activeWallet !== null) {
    if (route === "settings") activeRoute = "settings";
    else if (route === "send" && canSend) activeRoute = "send";
    else if (route === "swap" && canSwap) activeRoute = "swap";
    else if (route === "staking" && canStake) activeRoute = "staking";
    else if (route === "sign" && canSign) activeRoute = "sign";
    else if (route === "verify") activeRoute = "verify";
    else if (route === "offline" && canSign) activeRoute = "offline";
    else if (route === "operate" && canSign) activeRoute = "operate";
    else if (route === "multisig") activeRoute = "multisig";
    else if (ROUTES.has(route) && route !== "send" && route !== "swap") activeRoute = route;
    else activeRoute = "portfolio";
  }

  let content: ReactElement;
  if (addingWallet) {
    content = (
      <AddWallet
        network={network}
        onAdded={applyAdded}
        onCancel={() => setAddingWallet(false)}
      />
    );
  } else if (activeWallet === null) {
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
  } else if (route === "settings") {
    content = (
      <Settings
        account={toAccount(activeWallet)}
        walletType={activeWallet.type}
        autoLock={autoLock}
      />
    );
  } else if (route === "send" && !canSend) {
    content = <Portfolio />;
  } else if (route === "send" && canSend) {
    content = <Send isHardware={activeWallet.type === "hardware"} />;
  } else if (route === "swap" && !canSwap) {
    // Guard deep-links (#/swap): DEX quotes need a queryable mainnet node, so
    // fall back to Portfolio while the node or active wallet cannot support it.
    content = <Portfolio />;
  } else if (route === "staking") {
    // Staking/governance is gated like send: a synced node AND a
    // spending-enabled wallet. A read-only or unsynced wallet falls back to
    // Portfolio.
    content = canStake ? <Staking network={activeWallet.network} /> : <Portfolio />;
  } else if (route === "sign") {
    content = canSign ? <SignMessage account={toAccount(activeWallet)} /> : <Portfolio />;
  } else if (route === "verify") {
    // Verification is pure crypto — available to any active wallet, even
    // read-only, since it neither needs a node nor the keystore.
    content = <VerifyMessage />;
  } else if (route === "offline") {
    // Air-gap signing needs the active wallet's seed (to sign) but no node for
    // the sign step; falls back to Portfolio without an active wallet.
    content = canSign ? <Offline /> : <Portfolio />;
  } else if (route === "operate") {
    // Pool operations derive cold/VRF/KES keys from the seed and need the spend
    // password. A wallet must be active; otherwise fall back to Portfolio. Most
    // pool ops are offline; only retirement submission needs a synced node,
    // gated at the API.
    content = canSign ? <Operate account={toAccount(activeWallet)} /> : <Portfolio />;
  } else if (route === "multisig") {
    // Managing multi-sig accounts (list/create/view) is local state and works on
    // any active wallet. Building and submitting spends requires a synced node;
    // only local CIP-1854 key derivation/signing additionally requires a seed.
    content = <MultiSig canSpend={isReady} canSign={canSign} />;
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
    const Screen = ROUTES.get(route) ?? Portfolio;
    content = <Screen />;
  }

  // Build the nav item descriptors once, shared between desktop sidebar and
  // mobile drawer so gating logic only lives in one place.
  const navItems = NAV.map(({ key, label }) => {
    const gated =
      activeWallet === null ||
      addingWallet ||
      (key === "send" && !canSend) ||
      (key === "swap" && !canSwap) ||
      (key === "staking" && !canStake) ||
      (key === "sign" && !canSign) ||
      (key === "offline" && !canSign) ||
      (key === "operate" && !canSign);
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
        <main className="content" key={activeWallet?.id ?? "none"}>{content}</main>
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
