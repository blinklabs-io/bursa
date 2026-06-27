import { useState } from "react";
import type { ReactElement } from "react";
import type { Account } from "./api/types";
import { useStatus } from "./api/hooks";
import { SyncBanner } from "./components/SyncBanner";
import { useHashRoute, navigate } from "./router";
import { Setup } from "./screens/Setup";
import { Syncing } from "./screens/Syncing";
import { Portfolio } from "./screens/Portfolio";
import { Receive } from "./screens/Receive";
import { Activity } from "./screens/Activity";
import { Send } from "./screens/Send";
import { Staking } from "./screens/Staking";
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
  { key: "staking", label: "Staking" },
  { key: "sign", label: "Sign" },
  { key: "settings", label: "Settings" },
];

export function App() {
  const [account, setAccount] = useState<Account | null>(null);
  const [spendingEnabled, setSpendingEnabled] = useState(false);
  // Set when the user chooses to load a wallet while the node is still syncing,
  // dismissing the boot Syncing view in favour of Setup (read-only).
  const [loadAnyway, setLoadAnyway] = useState(false);
  const status = useStatus();
  const route = useHashRoute();

  const isReady = status.data?.state === "ready";

  // Boot gate: before any wallet is loaded, if the node isn't ready and the
  // user hasn't opted to proceed, the Syncing view takes the whole screen —
  // there is nothing to operate yet, and a balance shown now would be wrong.
  // The escape hatch drops to Setup for a read-only load against a syncing node.
  if (account === null && !loadAnyway && status.data && status.data.state !== "ready") {
    return (
      <div className="app">
        <SyncBanner status={status.data} />
        <main className="content content-boot">
          <Syncing status={status.data} onLoadAnyway={() => setLoadAnyway(true)} />
        </main>
      </div>
    );
  }
  // Sending and staking both require BOTH a fully synced node and a
  // spending-enabled wallet (a keystore created with a password). A read-only
  // wallet (loaded without a password) can never sign, so it must not enter
  // these flows. Staking is gated identically to send.
  const canSend = isReady && spendingEnabled;
  const canStake = isReady && spendingEnabled;

  // Which nav entry maps to the screen currently shown (mirrors the content
  // resolution below) so the sidebar can highlight the active route.
  let activeRoute = "";
  if (account !== null) {
    if (route === "settings") activeRoute = "settings";
    else if (route === "send" && canSend) activeRoute = "send";
    else if (route === "staking" && canStake) activeRoute = "staking";
    else if (route === "sign" && spendingEnabled) activeRoute = "sign";
    else if (ROUTES.has(route) && route !== "send") activeRoute = route;
    else activeRoute = "portfolio";
  }

  // Determine which screen to show in the content area.
  // If no account is loaded, always show Setup regardless of route.
  let content: ReactElement;
  if (account === null) {
    content = (
      <Setup
        network="preview"
        onLoaded={(a, s) => {
          setAccount(a);
          setSpendingEnabled(s);
        }}
      />
    );
  } else if (route === "settings") {
    content = <Settings account={account} spendingEnabled={spendingEnabled} />;
  } else if (route === "send" && !canSend) {
    // Guard deep-links (#/send) the same way the nav button is gated: sending
    // needs a synced node AND a spending-enabled (password) wallet, so fall back
    // to Portfolio otherwise.
    content = <Portfolio />;
  } else if (route === "staking") {
    // Staking/governance is gated like send: a synced node AND a
    // spending-enabled wallet. A read-only or unsynced wallet falls back to
    // Portfolio.
    content = canStake ? <Staking /> : <Portfolio />;
  } else if (route === "sign") {
    // Message signing needs a spending-enabled (keystore) wallet but no node;
    // a read-only wallet falls back to Portfolio.
    content = spendingEnabled ? <SignMessage account={account} /> : <Portfolio />;
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
          {NAV.map(({ key, label }) => {
            const gated =
              (key === "send" && !canSend) ||
              (key === "staking" && !canStake) ||
              (key === "sign" && !spendingEnabled);
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
        <main className="content">
          {content}
        </main>
      </div>
    </div>
  );
}
