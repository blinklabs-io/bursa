import { useState, useEffect } from "react";
import { Card } from "../components/Card";
import { StatusPill } from "../components/StatusPill";
import { CopyButton } from "../components/CopyButton";
import { useStatus, useHistoryExpiry } from "../api/hooks";
import { setHistoryExpiry as putHistoryExpiry, ApiError } from "../api/client";
import type { Account, NodeState } from "../api/types";

interface SettingsProps {
  account: Account;
  spendingEnabled: boolean;
}

function syncTone(state: NodeState): "ok" | "warn" | "error" | "muted" {
  if (state === "ready") return "ok";
  if (state === "error") return "error";
  if (state === "stopped") return "muted";
  return "warn";
}

// LeanStorageCard is the user-facing control for the lean-node (history-expiry)
// profile. It shows the persisted state, signals when a change still needs a
// node restart to take effect, and renders the tradeoff copy.
function LeanStorageCard() {
  const setting = useHistoryExpiry();
  // Optimistic local view of the toggle, so it reflects the user's click
  // immediately while the PUT is in flight (then reconciles with the server).
  const [enabled, setEnabled] = useState<boolean | null>(null);
  const [restartRequired, setRestartRequired] = useState(false);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState<string | null>(null);

  // Seed local state from the server once it loads (and whenever it refreshes
  // while we are not mid-save).
  useEffect(() => {
    if (setting.data && !saving) {
      setEnabled(setting.data.enabled);
      setRestartRequired(setting.data.restart_required);
    }
  }, [setting.data, saving]);

  async function handleToggle(next: boolean) {
    setError(null);
    setSaving(true);
    setEnabled(next); // optimistic
    try {
      const res = await putHistoryExpiry(next);
      setEnabled(res.enabled);
      setRestartRequired(res.restart_required);
    } catch (e) {
      // Roll back the optimistic flip on failure.
      setEnabled(!next);
      setError(e instanceof ApiError ? e.message : "An unexpected error occurred");
    } finally {
      setSaving(false);
    }
  }

  const loading = setting.loading && enabled === null;
  const checked = enabled ?? false;

  return (
    <Card title="Lean Storage">
      <div className="setting-toggle-row">
        <label htmlFor="lean-storage" className="setting-toggle-label">
          Lean storage (history expiry)
        </label>
        <label className="switch">
          <input
            id="lean-storage"
            type="checkbox"
            role="switch"
            aria-checked={checked}
            checked={checked}
            disabled={loading || saving}
            onChange={(e) => handleToggle(e.target.checked)}
          />
          <span className="switch-track" aria-hidden="true">
            <span className="switch-thumb" />
          </span>
        </label>
      </div>

      {loading ? (
        <p className="muted">Loading…</p>
      ) : (
        <p className="setting-state">
          {checked ? "Enabled" : "Disabled"}
          {saving && " · saving…"}
        </p>
      )}

      {error && (
        <p role="alert" className="error-text">
          {error}
        </p>
      )}

      {restartRequired && (
        <p role="status" className="setting-restart-note">
          Takes effect after a node restart.
        </p>
      )}

      <div className="setting-copy">
        <p>
          Prune old blockchain history from local storage. Your node keeps the
          current ledger state, your wallet&apos;s data, and recent blocks — and
          drops older block history it no longer needs.
        </p>
        <ul>
          <li>
            <strong>Saves significant disk space</strong> — typically tens of GB
            down to a few GB.
          </li>
          <li>
            <strong>The wallet stays fully functional</strong> — balances,
            sending, staking, and governance all rely on current ledger state and
            your own transaction history, not deep chain history.
          </li>
          <li>
            <strong>Tradeoff:</strong> historical chain data beyond the recent
            window is removed locally; recovering it requires a re-sync.
          </li>
          <li>
            <strong>Your Mithril snapshot is kept</strong>, so re-syncing stays
            fast — it won&apos;t re-download.
          </li>
          <li>
            <strong>One-way until re-sync:</strong> turning this on starts
            pruning; turning it back off stops further pruning but doesn&apos;t
            restore already-pruned history without a re-sync.
          </li>
          <li>
            <strong>Takes effect after a node restart.</strong>
          </li>
        </ul>
      </div>
    </Card>
  );
}

export function Settings({ account, spendingEnabled }: SettingsProps) {
  const status = useStatus();

  return (
    <div className="screen-settings">
      <Card title="Network">
        <p>{account.network}</p>
      </Card>

      <Card title="Stake Address">
        <div className="row-copy">
          <code className="mono">{account.stake_address}</code>
          <CopyButton value={account.stake_address} />
        </div>
      </Card>

      <Card title="Sync">
        {status.data ? (
          <dl className="stat-list">
            <dt>State</dt>
            <dd>
              <StatusPill tone={syncTone(status.data.state)}>
                {status.data.state}
              </StatusPill>
            </dd>
            <dt>Tip</dt>
            <dd>{status.data.tip}</dd>
            {status.data.caughtUp && (
              <>
                <dt>Caught up</dt>
                <dd>Yes</dd>
              </>
            )}
          </dl>
        ) : status.loading ? (
          <p>Loading…</p>
        ) : (
          <p className="muted">Unavailable</p>
        )}
      </Card>

      <LeanStorageCard />

      <Card title="Keystore">
        <p>{spendingEnabled ? "Spending enabled" : "Read-only"}</p>
      </Card>
    </div>
  );
}
