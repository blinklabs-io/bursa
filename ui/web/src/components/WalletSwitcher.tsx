import { useState } from "react";
import type { WalletView } from "../api/types";
import { activateWallet, ApiError } from "../api/client";

interface WalletSwitcherProps {
  wallets: WalletView[];
  activeId: string | null;
  onActivated: (wallet: WalletView) => void;
  onAddWallet: () => void;
  onLock: () => void;
}

// WalletSwitcher lists the vault's wallets in the sidebar and lets the user pick
// the active one (read-only switch — no password). Selecting a wallet binds it
// server-side as the active wallet that the read/spend endpoints operate on.
export function WalletSwitcher({
  wallets,
  activeId,
  onActivated,
  onAddWallet,
  onLock,
}: WalletSwitcherProps) {
  const [busyId, setBusyId] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  async function select(id: string) {
    if (id === activeId || busyId !== null) return;
    setError(null);
    setBusyId(id);
    try {
      const wallet = await activateWallet(id);
      onActivated(wallet);
    } catch (err) {
      setError(err instanceof ApiError ? err.message : "Could not switch wallet");
    } finally {
      setBusyId(null);
    }
  }

  return (
    <div className="wallet-switcher">
      <div className="wallet-switcher-label">Wallets</div>
      <ul className="wallet-list" aria-label="Wallets">
        {wallets.map((w) => {
          const active = w.id === activeId;
          return (
            <li key={w.id}>
              <button
                type="button"
                className={active ? "wallet-item active" : "wallet-item"}
                aria-current={active ? "true" : undefined}
                disabled={busyId !== null}
                onClick={() => select(w.id)}
              >
                <span className="wallet-name">{w.name}</span>
                <span className="wallet-net">{w.network}</span>
              </button>
            </li>
          );
        })}
      </ul>
      {error && (
        <p className="error-text" role="alert">
          {error}
        </p>
      )}
      <div className="wallet-switcher-actions">
        <button type="button" className="wallet-action" onClick={onAddWallet}>
          + Add wallet
        </button>
        <button type="button" className="wallet-action" onClick={onLock}>
          Lock vault
        </button>
      </div>
    </div>
  );
}
