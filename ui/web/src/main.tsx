// MUST stay the first import: it installs the Node globals that the hardware
// wallet dependencies reach for while they are being evaluated.
import "./polyfills";
import { StrictMode } from "react";
import { createRoot } from "react-dom/client";
import { App } from "./app";
import { establishControlSession, hasControlSession } from "./api/session";
import "./styles/global.css";
import "./styles/wallet.css";
import "./styles/screens.css";

function renderApp() {
  createRoot(document.getElementById("root")!).render(
    hasControlSession() ? <StrictMode><App /></StrictMode> :
      <main className="card" role="alert">
        <h1>Wallet authorization required</h1>
        <p>This page no longer has its launch authorization. Reopen the wallet using its complete launch URL or relaunch the desktop application.</p>
      </main>
  );
}

void establishControlSession().then(renderApp, renderApp);
