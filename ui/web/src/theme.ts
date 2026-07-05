import { useCallback, useEffect, useState } from "react";

export type Theme = "light" | "dark";

// STORAGE_KEY is the localStorage key that persists the user's explicit
// choice. Nothing stored means "follow the OS preference" (see resolveTheme).
const STORAGE_KEY = "bursa:theme";

function isTheme(value: unknown): value is Theme {
  return value === "light" || value === "dark";
}

// getStoredTheme reads the user's persisted choice, if any. Returns null on
// first run (nothing saved yet) or if storage throws (private browsing,
// disabled storage, quota) so callers fall back to the OS preference.
export function getStoredTheme(): Theme | null {
  try {
    const raw = window.localStorage.getItem(STORAGE_KEY);
    return isTheme(raw) ? raw : null;
  } catch {
    return null;
  }
}

// persistTheme saves an explicit choice. Failures are swallowed on purpose:
// the theme still applies for this session via the DOM attribute, it just
// won't survive a reload.
function persistTheme(theme: Theme): void {
  try {
    window.localStorage.setItem(STORAGE_KEY, theme);
  } catch {
    // ignore
  }
}

// getSystemTheme reads the OS-level light/dark preference. Defaults to "dark"
// (Bursa's native cockpit theme) when the environment can't report one at all
// (no matchMedia support).
export function getSystemTheme(): Theme {
  if (typeof window === "undefined" || typeof window.matchMedia !== "function") {
    return "dark";
  }
  return window.matchMedia("(prefers-color-scheme: light)").matches ? "light" : "dark";
}

// resolveTheme is the effective theme: the user's explicit choice if they've
// made one, else the OS preference.
export function resolveTheme(): Theme {
  return getStoredTheme() ?? getSystemTheme();
}

// applyTheme sets the data-theme attribute that tokens.css keys off of.
export function applyTheme(theme: Theme): void {
  document.documentElement.setAttribute("data-theme", theme);
}

// listeners holds every mounted `useTheme` instance's resync callback. Theme
// state is otherwise global (a single DOM attribute + localStorage key), but
// each `useTheme` call keeps its own React state mirroring it — without this
// fan-out, flipping the theme from one instance (e.g. the sidebar
// ThemeToggle) would apply immediately in the DOM while a second mounted
// instance (e.g. the Settings > Appearance ThemeToggle) kept rendering the
// stale value until some unrelated re-render caught it up.
const listeners = new Set<(theme: Theme) => void>();

// setTheme applies and persists an explicit user choice, then notifies every
// subscribed `useTheme` instance so they all stay in sync.
export function setTheme(theme: Theme): void {
  applyTheme(theme);
  persistTheme(theme);
  listeners.forEach((listener) => listener(theme));
}

// initTheme resolves and applies the initial theme. Call once at startup
// (before the app renders) to avoid a flash of the wrong theme.
export function initTheme(): Theme {
  const theme = resolveTheme();
  applyTheme(theme);
  return theme;
}

// watchSystemTheme invokes `cb` whenever the OS-level preference changes and
// returns an unsubscribe function. Callers should only listen while the user
// has not made an explicit choice of their own (getStoredTheme() === null).
export function watchSystemTheme(cb: (theme: Theme) => void): () => void {
  if (typeof window === "undefined" || typeof window.matchMedia !== "function") {
    return () => {};
  }
  const mql = window.matchMedia("(prefers-color-scheme: light)");
  const handler = (e: MediaQueryListEvent) => cb(e.matches ? "light" : "dark");
  if (typeof mql.addEventListener === "function") {
    mql.addEventListener("change", handler);
    return () => mql.removeEventListener("change", handler);
  }
  // Safari < 14 only exposes the deprecated addListener/removeListener pair;
  // without this fallback, subscribing throws during effect setup there.
  mql.addListener(handler);
  return () => mql.removeListener(handler);
}

// useTheme gives components the current theme plus a setter that both applies
// and persists the choice. While the user hasn't made an explicit choice
// (tracked by `hasExplicit`, seeded from storage and flipped true the moment
// `set` is called), it also tracks live OS-preference changes, applying them
// to the DOM as they happen; once the user picks a theme this session, the
// subscription is torn down so a later OS change can't silently override it.
export function useTheme(): [Theme, (theme: Theme) => void] {
  const [theme, setThemeState] = useState<Theme>(() => resolveTheme());
  const [hasExplicit, setHasExplicit] = useState<boolean>(() => getStoredTheme() !== null);

  useEffect(() => {
    if (hasExplicit) return undefined;
    return watchSystemTheme((next) => {
      applyTheme(next);
      setThemeState(next);
    });
  }, [hasExplicit]);

  // Resync with explicit choices made by any OTHER mounted `useTheme`
  // instance (see `listeners` above). Also fires for this instance's own
  // `set` call below, which is a harmless no-op re-render.
  useEffect(() => {
    const listener = (next: Theme) => {
      setThemeState(next);
      setHasExplicit(true);
    };
    listeners.add(listener);
    return () => {
      listeners.delete(listener);
    };
  }, []);

  const set = useCallback((next: Theme) => {
    setTheme(next);
    setThemeState(next);
    setHasExplicit(true);
  }, []);

  return [theme, set];
}
