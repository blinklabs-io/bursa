// MUST stay the first import: it installs the Node globals that the hardware
// wallet dependencies reach for while they are being evaluated.
import "./polyfills";
import { StrictMode } from "react";
import { createRoot } from "react-dom/client";
import { App } from "./app";
import "./styles/global.css";

createRoot(document.getElementById("root")!).render(<StrictMode><App /></StrictMode>);
