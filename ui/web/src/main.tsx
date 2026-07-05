import { StrictMode } from "react";
import { createRoot } from "react-dom/client";
import { App } from "./app";
import { initTheme } from "./theme";
import "./styles/global.css";

// Resolve and apply the theme (persisted choice, else OS preference) before
// the first render so there's no flash of the wrong theme.
initTheme();

createRoot(document.getElementById("root")!).render(<StrictMode><App /></StrictMode>);
