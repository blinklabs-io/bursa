import { useState } from "react";
import type { WalletView, Balance } from "../api/types";
import { selectAccount, addAccount, ApiError } from "../api/client";
import { useAccounts } from "../api/hooks";
import { formatAda } from "../format";

interface AccountSwitcherProps {
  wallet: WalletView;
  onChanged: (wallet: WalletView) => void;
}

// AccountSwitcher lists the active wallet's BIP44 accounts and lets the user
// switch between them (read-only switch — no password) or derive a new one.
// Switching rebinds the account server-side so every screen (Portfolio, Send,
// Staking, addresses) reflects the selected account. Deriving a new account
// needs the vault password (to re-seal the index) and the spending password (to
// derive the hardened account), so it is offered only for seed-backed wallets.
export function AccountSwitcher({ wallet, onChanged }: AccountSwitcherProps) {
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [adding, setAdding] = useState(false);
  const [vaultPassword, setVaultPassword] = useState("");
  const [spendPassword, setSpendPassword] = useState("");

  const activeIndex = wallet.active_account_index ?? 0;
  const accounts = [...(wallet.accounts ?? [])].sort((a, b) => a.index - b.index);
  const canAddAccount = wallet.type === "full";
  const nextIndex = accounts.reduce((max, a) => Math.max(max, a.index), -1) + 1;

  // Per-account balances come from GET /wallet/accounts — a node-local,
  // best-effort summary. The WalletView the switcher is handed carries account
  // metadata but no balances, so overlay them by index: the list still renders
  // offline (just without balances) and fills in once the node responds.
  const accountsState = useAccounts(true);
  const balanceByIndex = new Map<number, Balance>();
  for (const a of accountsState.data?.accounts ?? []) {
    if (a.balance) balanceByIndex.set(a.index, a.balance);
  }

  async function switchTo(index: number) {
    if (index === activeIndex || busy) return;
    setError(null);
    setBusy(true);
    try {
      onChanged(await selectAccount(index));
      accountsState.refresh();
    } catch (err) {
      setError(err instanceof ApiError ? err.message : "Could not switch account");
    } finally {
      setBusy(false);
    }
  }

  function resetAddForm() {
    setAdding(false);
    setVaultPassword("");
    setSpendPassword("");
  }

  async function submitAdd(e: React.FormEvent) {
    e.preventDefault();
    if (busy) return;
    setError(null);
    setBusy(true);
    try {
      const added = await addAccount({
        account_index: nextIndex,
        vault_password: vaultPassword,
        spend_password: spendPassword,
      });
      // Report the newly derived account immediately: it already exists
      // server-side, so the parent must not be left showing the stale account
      // list if the follow-up switch below fails.
      onChanged(added);
      resetAddForm();
    } catch (err) {
      setError(err instanceof ApiError ? err.message : "Could not add account");
      setBusy(false);
      return;
    }
    // The account is derived and added at this point; a failure past here is a
    // separate, non-fatal selection error — report it distinctly so it isn't
    // mistaken for the add itself having failed (which would invite a retry
    // that duplicates the already-derived account).
    try {
      onChanged(await selectAccount(nextIndex));
      accountsState.refresh();
    } catch (err) {
      setError(
        err instanceof ApiError
          ? `Account added, but switching to it failed: ${err.message}`
          : "Account added, but switching to it failed",
      );
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="account-switcher">
      <div className="account-switcher-label">Accounts</div>
      <ul className="account-list" aria-label="Accounts">
        {accounts.map((a) => {
          const active = a.index === activeIndex;
          const bal = balanceByIndex.get(a.index) ?? a.balance;
          return (
            <li key={a.index}>
              <button
                type="button"
                className={active ? "account-item active" : "account-item"}
                aria-current={active ? "true" : undefined}
                disabled={busy}
                onClick={() => switchTo(a.index)}
              >
                <span className="account-name">{a.label}</span>
                {bal && (
                  <span className="account-balance">{formatAda(bal.lovelace)} ADA</span>
                )}
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

      {canAddAccount &&
        (adding ? (
          <form className="account-add-form" onSubmit={submitAdd}>
            <label className="account-add-label" htmlFor="account-add-vault">
              Add {`Account #${nextIndex}`}
            </label>
            <input
              id="account-add-vault"
              type="password"
              className="account-add-input"
              placeholder="Vault password"
              autoComplete="off"
              value={vaultPassword}
              onChange={(e) => setVaultPassword(e.target.value)}
            />
            <input
              type="password"
              className="account-add-input"
              placeholder="Spending password"
              aria-label="Spending password"
              autoComplete="off"
              value={spendPassword}
              onChange={(e) => setSpendPassword(e.target.value)}
            />
            <div className="account-add-actions">
              <button
                type="submit"
                className="account-add-submit"
                disabled={busy || vaultPassword === "" || spendPassword === ""}
              >
                {busy ? "Adding…" : "Derive account"}
              </button>
              <button
                type="button"
                className="wallet-action"
                disabled={busy}
                onClick={resetAddForm}
              >
                Cancel
              </button>
            </div>
          </form>
        ) : (
          <button
            type="button"
            className="wallet-action"
            disabled={busy}
            onClick={() => {
              setError(null);
              setAdding(true);
            }}
          >
            + Add account
          </button>
        ))}
    </div>
  );
}
