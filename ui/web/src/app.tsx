import { useState } from "react";
import type { ReactElement } from "react";
import type { Account, WalletView } from "./api/types";
import { useStatus, useVaultStatus } from "./api/hooks";
import { lockVault } from "./api/client";
import { SyncBanner } from "./components/SyncBanner";
import { WalletSwitcher } from "./components/WalletSwitcher";
import { useHashRoute, navigate } from "./router";
import { CreateVault } from "./screens/CreateVault";
import { UnlockVault } from "./screens/UnlockVault";
import { AddWallet } from "./screens/AddWallet";
import { MigrateLegacyKeystore } from "./screens/MigrateLegacyKeystore";
import { Portfolio } from "./screens/Portfolio";
import { Receive } from "./screens/Receive";
import { Activity } from "./screens/Activity";
import { Send } from "./screens/Send";
import { SignMessage } from "./screens/SignMessage";
import { Settings } from "./screens/Settings";

// A Map (not a plain object) so a crafted hash like "#/constructor" or
// "#/toString" can't resolve to an inherited Object.prototype member and get
// rendered as a screen — unknown routes always fall back to Portfolio.
const ROUTES = new Map<string, () => ReactElement>([
  ["portfolio", Portfolio],
  ["receive", Receive],
  ["activity", Activity],
  ["send", Send],
]);

const NAV: { key: string; label: string }[] = [
  { key: "portfolio", label: "Portfolio" },
  { key: "receive", label: "Receive" },
  { key: "activity", label: "Activity" },
  { key: "send", label: "Send" },
  { key: "sign", label: "Sign" },
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

  const activeWallet = wallets.find((w) => w.id === activeId) ?? null;
  const isReady = status.data?.state === "ready";
  // Sending requires a fully synced node AND an active wallet (every vault
  // wallet has an encrypted seed, so any active wallet can spend with its
  // spending password).
  const canSend = isReady && activeWallet !== null;
  const canSign = activeWallet !== null;

  function applyWallets(list: WalletView[]) {
    setWallets(list);
    const active = list.find((w) => w.active);
    setActiveId(active ? active.id : null);
    setUnlocked(true);
  }

  function applyAdded(wallet: WalletView) {
    // A newly added wallet becomes active server-side; merge it in and select it.
    setWallets((prev) => {
      const without = prev.filter((w) => w.id !== wallet.id);
      return [...without.map((w) => ({ ...w, active: false })), { ...wallet, active: true }];
    });
    setActiveId(wallet.id);
    setUnlocked(true);
    setAddingWallet(false);
  }

  function applyActivated(wallet: WalletView) {
    setWallets((prev) => prev.map((w) => ({ ...w, active: w.id === wallet.id })));
    setActiveId(wallet.id);
  }

  async function handleLock() {
    try {
      await lockVault();
    } finally {
      setWallets([]);
      setActiveId(null);
      setUnlocked(false);
      setAddingWallet(false);
      navigate("portfolio");
      vaultStatus.refresh();
    }
  }

  // --- Pre-unlock flows: render full-screen, no sidebar -------------------

  // While the vault status is loading, show nothing (avoids a flash of the
  // wrong screen before we know whether a vault exists).
  if (!vaultStatus.data && vaultStatus.loading) {
    return <div className="app" />;
  }

  const vault = vaultStatus.data;
  const network = "preview";

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

  // --- Unlocked: the normal wallet UI bound to the active wallet ----------

  // Which nav entry maps to the screen currently shown (mirrors the content
  // resolution below) so the sidebar can highlight the active route.
  let activeRoute = "";
  if (!addingWallet && activeWallet !== null) {
    if (route === "settings") activeRoute = "settings";
    else if (route === "send" && canSend) activeRoute = "send";
    else if (route === "sign" && canSign) activeRoute = "sign";
    else if (ROUTES.has(route) && route !== "send") activeRoute = route;
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
    content = (
      <section className="card">
        <h2>Select a wallet</h2>
        <p className="helper-text">Choose a wallet from the sidebar to continue.</p>
      </section>
    );
  } else if (route === "settings") {
    content = <Settings account={toAccount(activeWallet)} spendingEnabled />;
  } else if (route === "send" && !canSend) {
    content = <Portfolio />;
  } else if (route === "sign") {
    content = canSign ? <SignMessage account={toAccount(activeWallet)} /> : <Portfolio />;
  } else {
    const Screen = ROUTES.get(route) ?? Portfolio;
    content = <Screen />;
  }

  return (
    <div className="app">
      {status.data && <SyncBanner status={status.data} />}
      <div className="layout">
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
          {NAV.map(({ key, label }) => {
            const gated =
              activeWallet === null ||
              addingWallet ||
              (key === "send" && !canSend) ||
              (key === "sign" && !canSign);
            const active = key === activeRoute;
            return (
              <button
                key={key}
                className={active ? "nav-item active" : "nav-item"}
                aria-current={active ? "page" : undefined}
                disabled={gated}
                onClick={() => navigate(key)}
              >
                {label}
              </button>
            );
          })}
        </nav>
        <main className="content">{content}</main>
      </div>
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
      {status && <SyncBanner status={status} />}
      <main className="content content-centered">{children}</main>
    </div>
  );
}
