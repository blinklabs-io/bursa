import { useState, useEffect, useCallback, type FormEvent } from "react";
import { Card } from "../components/Card";
import { StatusPill } from "../components/StatusPill";
import { CopyButton } from "../components/CopyButton";
import { Button } from "../components/Button";
import { useStatus, useHistoryExpiry, useAsync } from "../api/hooks";
import { setHistoryExpiry as putHistoryExpiry, ApiError } from "../api/client";
import { getConnectorState, revokeGrant, unpair, pendingPairings } from "../api/connector";
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

export function Settings({ account, spendingEnabled }: SettingsProps) {
  const status = useStatus();
  const [connectorMissing, setConnectorMissing] = useState(false);
  const loadConnectorState = useCallback(async () => {
    try {
      const state = await getConnectorState();
      setConnectorMissing(false);
      return state;
    } catch (e) {
      if (e instanceof ApiError && e.status === 404) {
        setConnectorMissing(true);
        return null;
      }
      throw e;
    }
  }, []);
  const connectorState = useAsync(loadConnectorState, {
    pollMs: 3000,
  });
  const connectorAvailable = !connectorMissing && connectorState.data !== null;
  const pendingPairs = useAsync(pendingPairings, {
    pollMs: connectorAvailable ? 3000 : undefined,
    enabled: connectorAvailable,
  });
  const [pairingPassword, setPairingPassword] = useState("");
  const [revealingPairCode, setRevealingPairCode] = useState(false);
  const [pairingRevealError, setPairingRevealError] = useState<string | null>(null);
  const [revealedPairCodes, setRevealedPairCodes] = useState<Record<string, string>>({});

  useEffect(() => {
    if (!pendingPairs.data) return;
    const pending = new Set(pendingPairs.data.map((p) => p.extension_id));
    setRevealedPairCodes((prev) => {
      const next: Record<string, string> = {};
      for (const [extensionID, code] of Object.entries(prev)) {
        if (pending.has(extensionID)) next[extensionID] = code;
      }
      return next;
    });
  }, [pendingPairs.data]);

  async function handleRevoke(origin: string) {
    try {
      await revokeGrant(origin);
      connectorState.refresh();
    } catch {
      // ignore — UI will re-poll
    }
  }

  async function handleUnpair() {
    try {
      await unpair();
      connectorState.refresh();
    } catch {
      // ignore — UI will re-poll
    }
  }

  async function handleRevealPairCode(e: FormEvent<HTMLFormElement>) {
    e.preventDefault();
    if (!pairingPassword || revealingPairCode) return;
    setPairingRevealError(null);
    setRevealingPairCode(true);
    try {
      const pairings = await pendingPairings(pairingPassword);
      const codes: Record<string, string> = {};
      for (const p of pairings) {
        if (p.code) codes[p.extension_id] = p.code;
      }
      setRevealedPairCodes(codes);
      setPairingPassword("");
    } catch (e) {
      setPairingRevealError(e instanceof ApiError ? e.message : "Unable to reveal pairing code");
    } finally {
      setRevealingPairCode(false);
    }
  }

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

      {!connectorMissing && (
        <Card title="dApp Connector">
        {connectorState.loading && !connectorState.data ? (
          <p>Loading…</p>
        ) : connectorState.data ? (
          <>
            <dl className="stat-list">
              <dt>Status</dt>
              <dd>
                <StatusPill tone={connectorState.data.paired ? "ok" : "muted"}>
                  {connectorState.data.paired ? "Paired" : "Not paired"}
                </StatusPill>
              </dd>
              {connectorState.data.paired && connectorState.data.extension_id && (
                <>
                  <dt>Extension</dt>
                  <dd>
                    <code className="mono" style={{ fontSize: "0.8em", wordBreak: "break-all" }}>
                      {connectorState.data.extension_id}
                    </code>
                  </dd>
                </>
              )}
            </dl>

            {/* Pending pairings — reveal code after vault-password confirmation. */}
            {pendingPairs.data && pendingPairs.data.length > 0 && (
              <section className="connector-pending-pairings" style={{ marginTop: "1rem" }}>
                <h3 style={{ fontSize: "0.9em", marginBottom: "0.5rem", fontWeight: 600 }}>
                  Pending pairing
                </h3>
                <form
                  onSubmit={handleRevealPairCode}
                  style={{ display: "flex", gap: "0.5rem", alignItems: "center", marginBottom: "0.75rem" }}
                >
                  <input
                    type="password"
                    autoComplete="current-password"
                    aria-label="Vault password"
                    placeholder="Vault password"
                    value={pairingPassword}
                    disabled={revealingPairCode}
                    onChange={(e) => setPairingPassword(e.target.value)}
                    style={{ minWidth: 0, flex: 1 }}
                  />
                  <Button type="submit" disabled={!pairingPassword || revealingPairCode}>
                    {revealingPairCode ? "Revealing…" : "Reveal code"}
                  </Button>
                </form>
                {pairingRevealError && (
                  <p role="alert" className="error-text">
                    {pairingRevealError}
                  </p>
                )}
                {pendingPairs.data.map((p) => {
                  const code = p.code ?? revealedPairCodes[p.extension_id];
                  return (
                    <div
                      key={p.extension_id}
                      className="connector-pair-entry"
                      style={{
                        marginBottom: "0.75rem",
                        padding: "0.75rem",
                        border: "1px solid var(--border, #e0e0e0)",
                        borderRadius: "6px",
                      }}
                    >
                      <p style={{ fontSize: "0.8em", color: "var(--muted, #666)", marginBottom: "0.4rem" }}>
                        {p.extension_id}
                      </p>
                      {code ? (
                        <>
                          <p
                            className="connector-pair-code"
                            aria-label="Pairing code"
                            style={{
                              fontSize: "2rem",
                              fontWeight: 700,
                              letterSpacing: 0,
                              fontVariantNumeric: "tabular-nums",
                              margin: "0.25rem 0",
                            }}
                          >
                            {code}
                          </p>
                          <p style={{ fontSize: "0.8em", color: "var(--muted, #666)" }}>
                            Enter this code in the Bursa extension to complete pairing.
                          </p>
                        </>
                      ) : (
                        <p style={{ fontSize: "0.8em", color: "var(--muted, #666)" }}>
                          Reveal the code to complete pairing.
                        </p>
                      )}
                    </div>
                  );
                })}
              </section>
            )}

            {/* Connected sites */}
            {connectorState.data.origins.length > 0 && (
              <section style={{ marginTop: "1rem" }}>
                <h3 style={{ fontSize: "0.9em", marginBottom: "0.5rem", fontWeight: 600 }}>
                  Connected sites
                </h3>
                <ul style={{ listStyle: "none", padding: 0, margin: 0 }}>
                  {connectorState.data.origins.map((origin) => (
                    <li
                      key={origin}
                      style={{
                        display: "flex",
                        alignItems: "center",
                        justifyContent: "space-between",
                        padding: "0.4rem 0",
                        borderBottom: "1px solid var(--border, #e0e0e0)",
                      }}
                    >
                      <code className="mono" style={{ fontSize: "0.85em" }}>
                        {origin}
                      </code>
                      <Button
                        variant="ghost"
                        aria-label={`Revoke ${origin}`}
                        style={{ fontSize: "0.8em", padding: "0.2rem 0.5rem" }}
                        onClick={() => void handleRevoke(origin)}
                      >
                        Revoke
                      </Button>
                    </li>
                  ))}
                </ul>
              </section>
            )}

            {connectorState.data.paired && (
              <div style={{ marginTop: "1rem" }}>
                <Button variant="ghost" onClick={() => void handleUnpair()}>
                  Unpair extension
                </Button>
              </div>
            )}
          </>
        ) : connectorState.error ? (
          <p className="muted">Unavailable</p>
        ) : null}
        </Card>
      )}
    </div>
  );
}
