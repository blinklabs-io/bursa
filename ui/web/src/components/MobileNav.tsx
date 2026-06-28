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

import { useState } from "react";
import type { Status } from "../api/types";
import type { WalletView } from "../api/types";
import { WalletSwitcher } from "./WalletSwitcher";

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
          className="mobile-hamburger"
          aria-label={open ? "Close menu" : "Open menu"}
          aria-expanded={open}
          onClick={() => setOpen((o) => !o)}
        >
          {open ? "✕" : "☰"}
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
        className={`mobile-drawer${open ? " mobile-drawer-open" : ""}`}
        role="navigation"
        aria-label="Wallet and navigation"
      >
        <div className="mobile-drawer-inner">
          {/* Wallet switcher block */}
          <WalletSwitcher
            wallets={wallets}
            activeId={activeId}
            onActivated={(w) => { onActivated(w); setOpen(false); }}
            onAddWallet={() => { onAddWallet(); setOpen(false); }}
            onLock={() => { onLock(); setOpen(false); }}
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

function chipTone(state: string): string {
  switch (state) {
    case "ready":
      return "ok";
    case "error":
      return "error";
    case "syncing":
    case "bootstrapping":
      return "warn";
    default:
      return "muted";
  }
}
