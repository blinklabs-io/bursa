// MUST stay the first import: it installs the Node globals that the hardware
// wallet dependencies reach for while they are being evaluated.
import "./polyfills";
import { StrictMode } from "react";
import { createRoot } from "react-dom/client";
import { App } from "./app";
import { establishControlSession } from "./api/session";
import "./styles/global.css";
import "./styles/wallet.css";
import "./styles/screens.css";

function renderApp() {
  createRoot(document.getElementById("root")!).render(<StrictMode><App /></StrictMode>);
}

void establishControlSession().then(renderApp, renderApp);
