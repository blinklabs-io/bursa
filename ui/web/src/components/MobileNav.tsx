// Copyright 2026 Blink Labs Software
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

import { useEffect, useRef, useState } from "react";
import type { Status, WalletView } from "../api/types";
import type { Tone } from "./StatusPill";
import { WalletSwitcher } from "./WalletSwitcher";

const FOCUSABLE_SELECTOR = [
  "a[href]",
  "button:not([disabled])",
  "textarea:not([disabled])",
  "input:not([disabled])",
  "select:not([disabled])",
  '[tabindex]:not([tabindex="-1"])',
].join(",");

const DESKTOP_MEDIA_QUERY = "(min-width: 768px)";

export interface MobileNavItem {
  key: string;
  label: string;
  disabled?: boolean;
  active?: boolean;
}

interface MobileNavProps {
  status: Status | null;
  activeWallet: WalletView | null;
  wallets: WalletView[];
  activeId: string | null;
  lockError: string | null;
  navItems: MobileNavItem[];
  onActivated: (wallet: WalletView) => void;
  onAddWallet: () => void;
  onLock: () => void;
  onNavigate: (key: string) => void;
}

// MobileNav renders on viewports narrower than 768 px. It replaces the fixed
// left sidebar with:
//   - A compact top bar: BVRSA mark · active wallet name · sync chip · ☰
//   - A slide-out drawer (wallet switcher + full nav list) behind the hamburger
//
// The desktop sidebar is hidden at the same breakpoint via CSS, so both can live
// in the DOM without either duplicating server state.
export function MobileNav({
  status,
  activeWallet,
  wallets,
  activeId,
  lockError,
  navItems,
  onActivated,
  onAddWallet,
  onLock,
  onNavigate,
}: MobileNavProps) {
  const [open, setOpen] = useState(false);
  const drawerRef = useRef<HTMLDivElement>(null);
  const hamburgerRef = useRef<HTMLButtonElement>(null);

  useEffect(() => {
    if (typeof window.matchMedia !== "function") return;

    const desktopQuery = window.matchMedia(DESKTOP_MEDIA_QUERY);
    function closeOnDesktop(event: MediaQueryList | MediaQueryListEvent) {
      if (event.matches) {
        setOpen(false);
      }
    }

    closeOnDesktop(desktopQuery);
    desktopQuery.addEventListener("change", closeOnDesktop);
    return () => desktopQuery.removeEventListener("change", closeOnDesktop);
  }, []);

  useEffect(() => {
    if (!open) return;
    const previousOverflow = document.body.style.overflow;
    document.body.style.overflow = "hidden";
    return () => {
      if (document.body.style.overflow === "hidden") {
        document.body.style.overflow = previousOverflow;
      }
    };
  }, [open]);

  useEffect(() => {
    if (!open) return;
    const hamburgerButton = hamburgerRef.current;
    const focusable = drawerRef.current?.querySelector<HTMLElement>(FOCUSABLE_SELECTOR);
    focusable?.focus();
    return () => {
      if (hamburgerButton?.isConnected) {
        hamburgerButton.focus();
      }
    };
  }, [open]);

  // Let keyboard users dismiss the drawer with Escape and keep Tab traversal
  // inside the drawer while it is acting as a modal mobile menu.
  useEffect(() => {
    if (!open) return;
    function handleKeyDown(event: KeyboardEvent) {
      if (event.key === "Escape") {
        setOpen(false);
        return;
      }
      if (event.key !== "Tab") {
        return;
      }

      const drawer = drawerRef.current;
      const focusable = Array.from(
        drawer?.querySelectorAll<HTMLElement>(FOCUSABLE_SELECTOR) ?? [],
      );
      if (focusable.length === 0) {
        event.preventDefault();
        return;
      }

      const first = focusable[0];
      const last = focusable[focusable.length - 1];
      const activeElement = document.activeElement;
      const focusInsideDrawer = activeElement ? drawer?.contains(activeElement) : false;

      if (event.shiftKey) {
        if (!focusInsideDrawer || activeElement === first) {
          event.preventDefault();
          last.focus();
        }
      } else if (!focusInsideDrawer || activeElement === last) {
        event.preventDefault();
        first.focus();
      }
    }
    document.addEventListener("keydown", handleKeyDown);
    return () => document.removeEventListener("keydown", handleKeyDown);
  }, [open]);

  function handleNavClick(key: string) {
    onNavigate(key);
    setOpen(false);
  }

  // A compact text chip for the node state so the top bar stays narrow.
  const stateChip = status ? (
    <span
      className={`mobile-sync-chip mobile-sync-chip-${chipTone(status.state)}`}
      aria-label={`Node: ${status.state}`}
    >
      {status.state}
    </span>
  ) : null;

  return (
    <>
      {/* ── Top bar ─────────────────────────────────────────────────── */}
      <div className="mobile-topbar" role="banner">
        <span className="mobile-brand-mark" aria-label="BVRSA">
          BVRSA
        </span>

        <div className="mobile-topbar-center">
          {activeWallet ? (
            <span className="mobile-wallet-name">{activeWallet.name}</span>
          ) : (
            <span className="mobile-wallet-name mobile-wallet-name-empty">
              No wallet
            </span>
          )}
          {stateChip}
        </div>

        <button
          ref={hamburgerRef}
          className="mobile-hamburger"
          aria-label="Open menu"
          aria-controls="mobile-navigation-drawer"
          aria-expanded={open}
          aria-hidden={open}
          tabIndex={open ? -1 : undefined}
          onClick={() => setOpen(true)}
        >
          ☰
        </button>
      </div>

      {/* ── Drawer overlay + panel ───────────────────────────────────── */}
      {open && (
        <div
          className="mobile-drawer-overlay"
          aria-hidden="true"
          onClick={() => setOpen(false)}
        />
      )}

      <div
        ref={drawerRef}
        id="mobile-navigation-drawer"
        className={`mobile-drawer${open ? " mobile-drawer-open" : ""}`}
        role="navigation"
        aria-label="Wallet and navigation"
      >
        <div className="mobile-drawer-inner">
          <div className="mobile-drawer-header">
            <button
              type="button"
              className="mobile-drawer-close"
              aria-label="Close menu"
              onClick={() => setOpen(false)}
            >
              ✕
            </button>
          </div>

          {/* Wallet switcher block */}
          <WalletSwitcher
            wallets={wallets}
            activeId={activeId}
            onActivated={(w) => { onActivated(w); setOpen(false); }}
            onAddWallet={() => { onAddWallet(); setOpen(false); }}
            onLock={onLock}
          />

          {lockError && (
            <p className="error-text" role="alert">
              {lockError}
            </p>
          )}

          {/* Full nav list */}
          <div className="mobile-nav-list">
            {navItems.map(({ key, label, disabled, active }) => (
              <button
                key={key}
                className={`nav-item${active ? " active" : ""}`}
                aria-current={active ? "page" : undefined}
                disabled={disabled}
                onClick={() => handleNavClick(key)}
              >
                {label}
              </button>
            ))}
          </div>
        </div>
      </div>
    </>
  );
}

const CHIP_TONE_BY_STATE = {
  stopped: "muted",
  starting: "muted",
  bootstrapping: "warn",
  syncing: "warn",
  ready: "ok",
  error: "error",
} satisfies Record<Status["state"], Tone>;

function chipTone(state: Status["state"]): Tone {
  return CHIP_TONE_BY_STATE[state];
}
