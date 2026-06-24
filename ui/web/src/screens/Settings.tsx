import { Card } from "../components/Card";
import { StatusPill } from "../components/StatusPill";
import { CopyButton } from "../components/CopyButton";
import { useStatus } from "../api/hooks";
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

      <Card title="Keystore">
        <p>{spendingEnabled ? "Spending enabled" : "Read-only"}</p>
      </Card>
    </div>
  );
}
