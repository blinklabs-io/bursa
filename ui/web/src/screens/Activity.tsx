import { useEffect, useMemo, useState } from "react";
import { useTransactions } from "../api/hooks";
import { getTransactionDetail } from "../api/client";
import type { Tx, TxDetail, TxDirection, TxIO } from "../api/types";
import { Table } from "../components/Table";
import { CopyButton } from "../components/CopyButton";
import { Input } from "../components/Input";
import { Select } from "../components/Select";
import { DownloadButton } from "../components/DownloadButton";
import { Drawer } from "../components/Drawer";
import { ExplorerLink } from "../components/ExplorerLink";
import { formatAda } from "../format";
import { toCsv } from "../csv";
import { errorMessage } from "../errorMessage";

interface ActivityProps {
  // Optional so existing no-prop callers/tests keep working; the app always
  // passes the active wallet's real network when routing to this screen.
  network?: string;
}

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

const DIRECTION_LABEL: Record<Exclude<TxDirection, "">, string> = {
  received: "Received",
  sent: "Sent",
  self: "Self",
};

const DIRECTION_ARROW: Record<Exclude<TxDirection, "">, string> = {
  received: "↓",
  sent: "↑",
  self: "↔",
};

function DirectionBadge({ direction }: { direction: TxDirection }) {
  if (!direction) {
    return <span className="muted">Unknown</span>;
  }
  return (
    <span className={`tx-direction tx-direction-${direction}`}>
      <span className="tx-direction-arrow">{DIRECTION_ARROW[direction]}</span>
      {DIRECTION_LABEL[direction]}
    </span>
  );
}

/** The signed net ADA amount for a tx, colored to match its direction. */
function NetAmount({ tx }: { tx: Tx }) {
  if (!tx.direction) {
    return <span className="muted">—</span>;
  }
  const sign = tx.net_lovelace.startsWith("-") ? "" : "+";
  const cls =
    tx.direction === "sent"
      ? "tx-amount-out"
      : tx.direction === "received"
        ? "tx-amount-in"
        : "tx-amount-self";
  return <span className={cls}>{`${sign}${formatAda(tx.net_lovelace)} ADA`}</span>;
}

/** Confirmations column: a "Pending" pill, or the confirmation count. */
function Confirmations({ tx }: { tx: Tx }) {
  if (tx.pending) {
    return <span className="pill pill-warn">Pending</span>;
  }
  if (!tx.direction) {
    return <span className="muted">{tx.confirmations}</span>;
  }
  return <span>{tx.confirmations}</span>;
}

/**
 * Builds a CSV document of the given transactions, entirely client-side.
 *
 * Every optional/enrichment field (direction, net_lovelace, fee, asset_deltas)
 * is guarded the same way the row rendering guards it: a pruned transaction
 * (the node no longer has a record of it, e.g. lean-node history-expiry)
 * carries `direction: ""` and a null `asset_deltas` from the API despite the
 * TS type, so it must export cleanly with blank cells rather than throw.
 */
function transactionsToCsv(txs: Tx[]): string {
  const headers = [
    "tx_hash",
    "direction",
    "net_ada",
    "fee_ada",
    "block_height",
    "block_time",
    "confirmations",
    "asset_deltas",
  ];
  const rows = txs.map((t) => [
    t.tx_hash,
    t.direction || "unknown",
    t.direction ? formatAda(t.net_lovelace) : "",
    t.direction ? formatAda(t.fee) : "",
    t.block_height,
    new Date(t.block_time * 1000).toISOString(),
    t.pending ? "pending" : String(t.confirmations),
    (t.asset_deltas ?? []).map((a) => `${a.unit}:${a.quantity}`).join(";"),
  ]);
  return toCsv(headers, rows);
}

function TxIORow({ io }: { io: TxIO }) {
  const ownerLabel = io.is_mine ? "Mine" : "External";
  return (
    <div className={`io-row${io.is_mine ? " is-mine" : ""}`}>
      <span className="io-address-group">
        <span className="io-address mono">{io.address}</span>
        <span className="io-owner">{ownerLabel}</span>
      </span>
      <span className="io-amount">
        {formatAda(io.lovelace)} ADA
        {io.assets.length > 0 && (
          <> · {io.assets.map((a) => `${a.quantity} ${a.unit}`).join(", ")}</>
        )}
      </span>
    </div>
  );
}

function TransactionDetailDrawer({ hash, onClose }: { hash: string; onClose: () => void }) {
  const [detail, setDetail] = useState<TxDetail | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    let cancelled = false;
    setLoading(true);
    setError(null);
    setDetail(null);
    getTransactionDetail(hash)
      .then((d) => {
        if (!cancelled) setDetail(d);
      })
      .catch((e: unknown) => {
        if (!cancelled) setError(errorMessage(e));
      })
      .finally(() => {
        if (!cancelled) setLoading(false);
      });
    return () => {
      cancelled = true;
    };
  }, [hash]);

  return (
    <Drawer title="Transaction Detail" onClose={onClose}>
      {loading && <p>Loading…</p>}
      {error && (
        <p role="alert" className="error-text">
          {error}
        </p>
      )}
      {detail && (
        <>
          <div className="drawer-section">
            <h3>Summary</h3>
            <div className="dl-row">
              <dt>Hash</dt>
              <dd className="tx-hash-row">
                <span className="tx-hash">{detail.tx_hash}</span>
                <CopyButton value={detail.tx_hash} />
              </dd>
            </div>
            <div className="dl-row">
              <dt>Direction</dt>
              <dd>
                <DirectionBadge direction={detail.direction} />
              </dd>
            </div>
            <div className="dl-row">
              <dt>Amount</dt>
              <dd>
                <NetAmount tx={detail} />
              </dd>
            </div>
            <div className="dl-row">
              <dt>Fee</dt>
              <dd>
                {detail.direction ? (
                  `${formatAda(detail.fee)} ADA`
                ) : (
                  <span className="muted">—</span>
                )}
              </dd>
            </div>
            <div className="dl-row">
              <dt>Block</dt>
              <dd>{detail.block_height}</dd>
            </div>
            <div className="dl-row">
              <dt>Time</dt>
              <dd>{formatBlockTime(detail.block_time)}</dd>
            </div>
            <div className="dl-row">
              <dt>Confirmations</dt>
              <dd>{detail.pending ? "Pending" : detail.confirmations}</dd>
            </div>
            {(detail.asset_deltas ?? []).map((a) => (
              <div className="dl-row" key={a.unit}>
                <dt>{a.unit}</dt>
                <dd>{a.quantity}</dd>
              </div>
            ))}
          </div>

          <div className="drawer-section">
            <h3>Inputs ({detail.inputs.length})</h3>
            {detail.inputs.map((io, i) => (
              <TxIORow io={io} key={`${io.address}-${i}`} />
            ))}
          </div>

          <div className="drawer-section">
            <h3>Outputs ({detail.outputs.length})</h3>
            {detail.outputs.map((io, i) => (
              <TxIORow io={io} key={`${io.address}-${i}`} />
            ))}
          </div>
        </>
      )}
    </Drawer>
  );
}

type DirectionFilter = "all" | "received" | "sent" | "self";

export function Activity({ network = "preview" }: ActivityProps = {}) {
  const txs = useTransactions();
  const [search, setSearch] = useState("");
  const [directionFilter, setDirectionFilter] = useState<DirectionFilter>("all");
  const [selectedHash, setSelectedHash] = useState<string | null>(null);

  const list = useMemo(() => txs.data ?? [], [txs.data]);

  const filtered = useMemo(() => {
    const needle = search.trim().toLowerCase();
    return list.filter((tx) => {
      if (directionFilter !== "all" && tx.direction !== directionFilter) return false;
      if (needle && !tx.tx_hash.toLowerCase().includes(needle)) return false;
      return true;
    });
  }, [list, search, directionFilter]);

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

  if (list.length === 0) {
    return (
      <div className="activity">
        <p className="muted">No transactions yet</p>
      </div>
    );
  }

  const columns = [
    { key: "direction", label: "Direction" },
    { key: "amount", label: "Amount" },
    { key: "fee", label: "Fee" },
    { key: "block_height", label: "Block" },
    { key: "time", label: "Time" },
    { key: "confirmations", label: "Confirmations" },
    { key: "tx_hash", label: "Tx Hash" },
    { key: "actions", label: "" },
  ];

  // API returns newest-first; preserve that order.
  const rows = filtered.map((tx) => ({
    direction: <DirectionBadge direction={tx.direction} />,
    amount: <NetAmount tx={tx} />,
    fee: tx.direction ? `${formatAda(tx.fee)} ADA` : <span className="muted">—</span>,
    block_height: tx.block_height,
    time: formatBlockTime(tx.block_time),
    confirmations: <Confirmations tx={tx} />,
    tx_hash: (
      <span className="hash-cell">
        <span className="mono">{truncateHash(tx.tx_hash)}</span>
        <CopyButton value={tx.tx_hash} />
        <ExplorerLink
          network={network}
          kind="tx"
          id={tx.tx_hash}
          label={`View transaction ${truncateHash(tx.tx_hash)} on block explorer`}
        />
      </span>
    ),
    actions: (
      <button
        type="button"
        className="btn ghost"
        onClick={() => setSelectedHash(tx.tx_hash)}
        aria-label={`View details for ${tx.tx_hash}`}
      >
        Details
      </button>
    ),
  }));

  return (
    <div className="activity">
      <div className="activity-filters">
        <Input
          type="text"
          placeholder="Search by tx hash…"
          value={search}
          onChange={(e) => setSearch(e.target.value)}
          aria-label="Search transactions by hash"
        />
        <Select
          value={directionFilter}
          onChange={(e) => setDirectionFilter(e.target.value as DirectionFilter)}
          aria-label="Filter by direction"
          options={[
            { value: "all", label: "All Directions" },
            { value: "received", label: "Received" },
            { value: "sent", label: "Sent" },
            { value: "self", label: "Self" },
          ]}
        />
        <DownloadButton
          getValue={() => transactionsToCsv(filtered)}
          filename="bursa-transactions.csv"
          label="Export CSV"
        />
      </div>

      {filtered.length === 0 ? (
        <p className="muted">No transactions match your filters</p>
      ) : (
        <Table columns={columns} rows={rows} />
      )}

      {selectedHash && (
        <TransactionDetailDrawer hash={selectedHash} onClose={() => setSelectedHash(null)} />
      )}
    </div>
  );
}
