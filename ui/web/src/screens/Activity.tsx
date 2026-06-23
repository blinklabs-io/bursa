import { useTransactions } from "../api/hooks";
import { Table } from "../components/Table";
import { CopyButton } from "../components/CopyButton";

/** Truncate a tx hash for display: first 8 … last 6 chars. */
function truncateHash(hash: string): string {
  if (hash.length <= 18) return hash;
  return hash.slice(0, 8) + "…" + hash.slice(-6);
}

/**
 * Format a Unix timestamp (seconds) into a readable date string.
 * Uses toLocaleString so the year is always present.
 */
function formatBlockTime(unixSeconds: number): string {
  return new Date(unixSeconds * 1000).toLocaleString();
}

export function Activity() {
  const txs = useTransactions();

  if (txs.loading) {
    return <p>Loading…</p>;
  }

  if (txs.error) {
    return (
      <p role="alert" className="error-text">
        {txs.error.message}
      </p>
    );
  }

  const list = txs.data ?? [];

  if (list.length === 0) {
    return (
      <div className="activity">
        <p className="muted">No transactions yet</p>
      </div>
    );
  }

  const columns = [
    { key: "tx_hash", label: "Tx Hash" },
    { key: "block_height", label: "Block" },
    { key: "block_time", label: "Time" },
  ];

  // API returns newest-first; preserve that order.
  const rows = list.map((tx) => ({
    tx_hash: (
      <span className="hash-cell">
        <span className="mono">{truncateHash(tx.tx_hash)}</span>
        <CopyButton value={tx.tx_hash} />
      </span>
    ),
    block_height: tx.block_height,
    block_time: formatBlockTime(tx.block_time),
  }));

  return (
    <div className="activity">
      <Table columns={columns} rows={rows} />
    </div>
  );
}
