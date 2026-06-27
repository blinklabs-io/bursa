import { useState } from "react";
import type { ReactElement } from "react";
import type { Account } from "./api/types";
import { useStatus } from "./api/hooks";
import { SyncBanner } from "./components/SyncBanner";
import { useHashRoute, navigate } from "./router";
import { Setup } from "./screens/Setup";
import { Portfolio } from "./screens/Portfolio";
import { Receive } from "./screens/Receive";
import { Activity } from "./screens/Activity";
import { Send } from "./screens/Send";
import { Swap } from "./screens/Swap";
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
  ["swap", Swap],
]);

const NAV: { key: string; label: string }[] = [
  { key: "portfolio", label: "Portfolio" },
  { key: "receive", label: "Receive" },
  { key: "activity", label: "Activity" },
  { key: "send", label: "Send" },
  { key: "swap", label: "Swap" },
  { key: "sign", label: "Sign" },
  { key: "settings", label: "Settings" },
];

export function App() {
  const [account, setAccount] = useState<Account | null>(null);
  const [spendingEnabled, setSpendingEnabled] = useState(false);
  const status = useStatus();
  const route = useHashRoute();

  const isReady = status.data?.state === "ready";
  // Sending requires BOTH a fully synced node and a spending-enabled wallet (a
  // keystore created with a password). A read-only wallet (loaded without a
  // password) can never complete a send, so it must not enter the send flow.
  const canSend = isReady && spendingEnabled;
  // Swap shows node-local DEX prices/quotes (no spending, no signing — it never
  // builds or submits a tx), so it needs only a synced node and a loaded wallet.
  const canSwap = isReady;

  // Which nav entry maps to the screen currently shown (mirrors the content
  // resolution below) so the sidebar can highlight the active route.
  let activeRoute = "";
  if (account !== null) {
    if (route === "settings") activeRoute = "settings";
    else if (route === "send" && canSend) activeRoute = "send";
    else if (route === "swap" && canSwap) activeRoute = "swap";
    else if (route === "sign" && spendingEnabled) activeRoute = "sign";
    else if (ROUTES.has(route) && route !== "send" && route !== "swap") activeRoute = route;
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
  } else if (route === "swap" && !canSwap) {
    // Guard deep-links (#/swap): the DEX quote screen needs a synced node to
    // read pool UTxOs, so fall back to Portfolio until the node is ready.
    content = <Portfolio />;
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
              (key === "swap" && !canSwap) ||
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
