import { useMemo } from "react";
import { useRewards } from "../api/hooks";
import type { RewardEntry } from "../api/types";
import { Table } from "../components/Table";
import { CopyButton } from "../components/CopyButton";
import { ExplorerLink } from "../components/ExplorerLink";
import { formatAda } from "../format";

interface RewardHistoryProps {
  // Optional so no-prop callers/tests keep working; the app always passes the
  // active wallet's real network so the pool explorer links resolve.
  network?: string;
}

/** Truncate a bech32 pool id for display: first 10 … last 6 chars. */
function truncatePool(id: string): string {
  if (id.length <= 20) return id;
  return id.slice(0, 10) + "…" + id.slice(-6);
}

/** Sum reward amounts (decimal lovelace strings) with BigInt precision. */
function totalLovelace(rewards: RewardEntry[]): string {
  let sum = 0n;
  for (const r of rewards) {
    if (/^\d+$/.test(r.amount)) sum += BigInt(r.amount);
  }
  return sum.toString();
}

export function RewardHistory({ network = "preview" }: RewardHistoryProps = {}) {
  const rewards = useRewards();

  const list = useMemo(() => {
    const rows = rewards.data?.rewards ?? [];
    // Node returns oldest-first; show newest epoch first, like Activity.
    return [...rows].sort((a, b) => b.epoch - a.epoch);
  }, [rewards.data]);

  if (rewards.loading) {
    return <p>Loading…</p>;
  }

  if (rewards.error) {
    return (
      <p role="alert" className="error-text">
        {rewards.error.message}
      </p>
    );
  }

  if (list.length === 0) {
    return (
      <div className="reward-history">
        <p className="muted">No rewards yet</p>
        {rewards.data?.provisional && rewards.data.note && (
          <p className="helper-text">{rewards.data.note}</p>
        )}
      </div>
    );
  }

  const columns = [
    { key: "epoch", label: "Epoch" },
    { key: "amount", label: "Reward" },
    { key: "type", label: "Type" },
    { key: "pool", label: "Pool" },
  ];

  const rows = list.map((r) => ({
    epoch: r.epoch,
    amount: <span className="mono">{formatAda(r.amount)} ADA</span>,
    type: r.type ? r.type : <span className="muted">—</span>,
    pool: r.pool_id ? (
      <span className="hash-cell">
        <span className="mono">{truncatePool(r.pool_id)}</span>
        <CopyButton value={r.pool_id} />
        <ExplorerLink
          network={network}
          kind="pool"
          id={r.pool_id}
          label={`View pool ${truncatePool(r.pool_id)} on block explorer`}
        />
      </span>
    ) : (
      <span className="muted">—</span>
    ),
  }));

  const total = totalLovelace(list);

  return (
    <div className="reward-history">
      <div className="reward-summary">
        <span className="field-label">Total rewards</span>
        <span className="total-accent mono">{formatAda(total)} ADA</span>
      </div>

      <Table columns={columns} rows={rows} />

      {rewards.data?.provisional && rewards.data.note && (
        <p className="helper-text">{rewards.data.note}</p>
      )}
    </div>
  );
}
