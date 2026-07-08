import { useState, useEffect } from "react";
import { Card } from "../components/Card";
import { StatusPill } from "../components/StatusPill";
import { CopyButton } from "../components/CopyButton";
import { Button } from "../components/Button";
import { Input } from "../components/Input";
import { Select } from "../components/Select";
import { useStatus, useHistoryExpiry, useTPMStatus } from "../api/hooks";
import type { AsyncState } from "../api/hooks";
import {
  setHistoryExpiry as putHistoryExpiry,
  setAutoLock as putAutoLock,
  ApiError,
  enableTPM,
  disableTPM,
} from "../api/client";
import type { Account, AutoLockSetting, NodeState, TPMStatus } from "../api/types";

interface SettingsProps {
  account: Account;
  spendingEnabled: boolean;
  // The auto-lock AsyncState, lifted up to and owned by App (see app.tsx) so
  // this screen's save path and App's useIdleLock share the same value — a
  // change here must be visible to the idle timer in the same session, with
  // no reload.
  autoLock: AsyncState<AutoLockSetting>;
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

  // Seed local state from the server once it loads, and whenever the hook data
  // itself refreshes. Do not key this off saving: the hook may still hold the
  // pre-PUT value when a successful save finishes.
  useEffect(() => {
    if (setting.data) {
      setEnabled(setting.data.enabled);
      setRestartRequired(setting.data.restart_required);
    }
  }, [setting.data]);

  async function handleToggle(next: boolean) {
    if (enabled === null || saving) return;
    const previous = enabled;
    setError(null);
    setSaving(true);
    setEnabled(next); // optimistic
    try {
      const res = await putHistoryExpiry(next);
      setEnabled(res.enabled);
      setRestartRequired(res.restart_required);
    } catch (e) {
      // Roll back the optimistic flip on failure.
      setEnabled(previous);
      setError(e instanceof ApiError ? e.message : "An unexpected error occurred");
    } finally {
      setSaving(false);
    }
  }

  const hasLoaded = enabled !== null;
  const loading = setting.loading && !hasLoaded;
  const unavailable = !loading && !hasLoaded;
  const checked = enabled ?? false;
  const loadError = setting.error?.message ?? null;
  const cardError = error ?? loadError;

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
            disabled={!hasLoaded || loading || saving}
            onChange={(e) => handleToggle(e.target.checked)}
          />
          <span className="switch-track" aria-hidden="true">
            <span className="switch-thumb" />
          </span>
        </label>
      </div>

      {loading ? (
        <p className="muted">Loading…</p>
      ) : unavailable ? (
        <p className="muted">Unavailable</p>
      ) : (
        <p className="setting-state">
          {checked ? "Enabled" : "Disabled"}
          {saving && " · saving…"}
        </p>
      )}

      {cardError && (
        <p role="alert" className="error-text">
          {cardError}
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

// Mirrors settings.AutoLockOptions (ui/internal/settings/settings.go) and
// autoLockOptions (ui/internal/api/api.go) — those two are guarded against
// drift by TestAutoLockOptionsMatchesSettingsPackage in ui/internal/api, but
// this frontend copy lives outside the Go module and must be kept in sync by
// hand.
const AUTO_LOCK_OPTIONS = [
  { value: "0", label: "Off" },
  { value: "1", label: "1 minute" },
  { value: "5", label: "5 minutes" },
  { value: "15", label: "15 minutes" },
  { value: "30", label: "30 minutes" },
];

// AutoLockCard is the user-facing control for the idle auto-lock timeout: how
// long the app waits with no pointer/keyboard/visibility activity before
// re-locking the vault (see useIdleLock, wired up in app.tsx). Mirrors
// LeanStorageCard's optimistic-update pattern, minus the restart-required
// concept — this setting is a pure frontend behaviour and takes effect on the
// very next idle check.
//
// `setting` is App's useAutoLock() AsyncState, passed down rather than called
// again here (compare TPMCard, which is handed tpmStatusQuery the same way).
// A second independent useAutoLock() call here would have its own useState
// (useAsync keeps no shared cache) and App's useIdleLock would never see a
// save made through this card until a full reload.
function AutoLockCard({ setting }: { setting: AsyncState<AutoLockSetting> }) {
  const [minutes, setMinutes] = useState<AutoLockSetting["minutes"] | null>(null);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (setting.data) {
      setMinutes(setting.data.minutes);
    }
  }, [setting.data]);

  async function handleChange(next: AutoLockSetting["minutes"]) {
    if (minutes === null || saving || next === minutes) return;
    const previous = minutes;
    setError(null);
    setSaving(true);
    setMinutes(next); // optimistic
    try {
      const res = await putAutoLock(next);
      setMinutes(res.minutes);
      // Propagate the authoritative saved value into the shared AsyncState
      // App reads for useIdleLock, so the new timeout (including Off) takes
      // effect immediately in this session — not just in this card's local
      // echo of it.
      setting.setData(res);
    } catch (e) {
      // Roll back the optimistic change on failure.
      setMinutes(previous);
      setError(e instanceof ApiError ? e.message : "An unexpected error occurred");
    } finally {
      setSaving(false);
    }
  }

  const hasLoaded = minutes !== null;
  const loading = setting.loading && !hasLoaded;
  const unavailable = !loading && !hasLoaded;
  const loadError = setting.error?.message ?? null;
  const cardError = error ?? loadError;

  return (
    <Card title="Auto-Lock">
      <div className="setting-toggle-row">
        <label htmlFor="auto-lock" className="setting-toggle-label">
          Lock after inactivity
        </label>
        <Select
          id="auto-lock"
          aria-label="Lock after inactivity"
          options={AUTO_LOCK_OPTIONS}
          value={String(minutes ?? 0)}
          disabled={!hasLoaded || loading || saving}
          onChange={(e) => handleChange(Number(e.target.value) as AutoLockSetting["minutes"])}
        />
      </div>

      {loading ? (
        <p className="muted">Loading…</p>
      ) : unavailable ? (
        <p className="muted">Unavailable</p>
      ) : (
        <p className="setting-state">
          {minutes === 0
            ? "Off — the vault will not auto-lock"
            : `Locks after ${minutes} minute${minutes === 1 ? "" : "s"} of inactivity`}
          {saving && " · saving…"}
        </p>
      )}

      {cardError && (
        <p role="alert" className="error-text">
          {cardError}
        </p>
      )}

      <div className="setting-copy">
        <p>
          Automatically re-locks the vault after a period with no pointer,
          keyboard, or tab activity — so a wallet left open and unattended
          doesn&apos;t stay unlocked indefinitely.
        </p>
      </div>
    </Card>
  );
}

// TPM hardware security card. Fetches /vault/tpm/status on mount.
// When unavailable: shows a disabled explanatory state (platform note + reason).
// When available:
//   - Not enabled: "Enable" button → password dialog → optional PCR (with warning).
//   - Enabled: shows current state (PCR bound?) + "Disable" button → password dialog.
function TPMCard({
  tpmStatus,
  onRefresh,
  onApplyStatus,
}: {
  tpmStatus: TPMStatus;
  onRefresh: () => void;
  // onApplyStatus applies the authoritative status returned by the mutation POST
  // so the card never shows stale hardware-security state if the follow-up GET
  // (onRefresh) fails after the mutation already succeeded.
  onApplyStatus?: (status: TPMStatus) => void;
}) {
  const [mode, setMode] = useState<"idle" | "enabling" | "disabling">("idle");
  const [password, setPassword] = useState("");
  const [pcrBound, setPcrBound] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const resetDialog = () => {
    setMode("idle");
    setPassword("");
    setPcrBound(false);
    setError(null);
  };

  const runTPMMutation = async (action: () => Promise<TPMStatus>) => {
    if (!password) return;
    setBusy(true);
    setError(null);
    try {
      const status = await action();
      resetDialog();
      // Trust the POST's authoritative status first; refresh is a best-effort
      // re-sync that must not, on failure, revert the card to stale state.
      onApplyStatus?.(status);
      onRefresh();
    } catch (e) {
      setError(e instanceof Error ? e.message : "Unknown error");
    } finally {
      setBusy(false);
    }
  };

  const handleEnable = () => runTPMMutation(() => enableTPM({ password, pcrBound }));
  const handleDisable = () => runTPMMutation(() => disableTPM({ password }));

  if (!tpmStatus.available && !tpmStatus.enabled) {
    return (
      <Card title="Hardware security">
        <p className="muted">No TPM detected</p>
        {tpmStatus.reason && (
          <p className="helper-text">{tpmStatus.reason}</p>
        )}
        <p className="helper-text">
          TPM vault binding is only available on desktop/server platforms with a TPM 2.0 device.
          On Linux, ensure the <code>tss</code> group permission is set for <code>/dev/tpmrm0</code> or <code>/dev/tpm0</code>.
        </p>
      </Card>
    );
  }

  if (mode === "enabling") {
    return (
      <Card title="Hardware security">
        <p>Enter your vault password to add TPM-backed machine binding with password recovery.</p>
        <Input
          type="password"
          aria-label="Vault password"
          placeholder="vault password"
          value={password}
          onChange={(e) => setPassword(e.target.value)}
          disabled={busy}
        />
        <label className="checkbox-label">
          <input
            type="checkbox"
            role="checkbox"
            aria-label="Also require PCR measurement (boot state)"
            checked={pcrBound}
            onChange={(e) => setPcrBound(e.target.checked)}
            disabled={busy}
          />
          {" "}Also require unchanged boot state (PCR)
        </label>
        {pcrBound && (
          <p className="warning-text" role="status">
            Warning: PCR binding is brittle. A firmware update or boot configuration
            change may prevent TPM unsealing. Your password always remains as recovery,
            but you may need to re-enroll after a firmware update.
          </p>
        )}
        {error && <p className="error-text" role="alert">{error}</p>}
        <div className="row-actions">
          <Button onClick={handleEnable} disabled={busy || !password}>
            Confirm
          </Button>
          <Button variant="ghost" onClick={resetDialog} disabled={busy}>
            Cancel
          </Button>
        </div>
      </Card>
    );
  }

  if (mode === "disabling") {
    return (
      <Card title="Hardware security">
        <p>Enter your vault password to remove TPM-backed machine binding.</p>
        <Input
          type="password"
          aria-label="Vault password"
          placeholder="vault password"
          value={password}
          onChange={(e) => setPassword(e.target.value)}
          disabled={busy}
        />
        {error && <p className="error-text" role="alert">{error}</p>}
        <div className="row-actions">
          <Button onClick={handleDisable} disabled={busy || !password}>
            Confirm
          </Button>
          <Button variant="ghost" onClick={resetDialog} disabled={busy}>
            Cancel
          </Button>
        </div>
      </Card>
    );
  }

  // idle: available, show current state
  return (
    <Card title="Hardware security">
      {tpmStatus.enabled ? (
        <>
          <p>
            TPM-backed machine binding is <strong>enabled</strong> with password recovery.
            {tpmStatus.pcrBound && " PCR-bound (boot state required)."}
          </p>
          {!tpmStatus.available && tpmStatus.reason && (
            <p className="helper-text">{tpmStatus.reason}</p>
          )}
          <Button variant="ghost" onClick={() => setMode("disabling")}>
            Disable TPM binding
          </Button>
        </>
      ) : (
        <>
          <p>Add TPM-backed machine binding while keeping password recovery.</p>
          <Button onClick={() => setMode("enabling")}>
            Enable TPM binding
          </Button>
        </>
      )}
    </Card>
  );
}

export function Settings({ account, spendingEnabled, autoLock }: SettingsProps) {
  const status = useStatus();
  const tpmStatusQuery = useTPMStatus();

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

      <AutoLockCard setting={autoLock} />

      <Card title="Keystore">
        <p>{spendingEnabled ? "Spending enabled" : "Read-only"}</p>
      </Card>

      {tpmStatusQuery.data ? (
        <TPMCard
          tpmStatus={tpmStatusQuery.data}
          onRefresh={tpmStatusQuery.refresh}
          onApplyStatus={tpmStatusQuery.setData}
        />
      ) : tpmStatusQuery.loading ? (
        <Card title="Hardware security">
          <p>Loading…</p>
        </Card>
      ) : (
        <Card title="Hardware security">
          <p className="muted">Unavailable</p>
          {tpmStatusQuery.error && (
            <p className="error-text" role="alert">{tpmStatusQuery.error.message}</p>
          )}
        </Card>
      )}
    </div>
  );
}
