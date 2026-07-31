import { useState, useEffect } from "react";
import type { PoolDirectoryResponse } from "../api/types";
import { getPoolDirectory } from "../api/client";
import { Card } from "../components/Card";
import { Input } from "../components/Input";
import { Button } from "../components/Button";
import { Table } from "../components/Table";
import { CopyButton } from "../components/CopyButton";
import { ExplorerLink } from "../components/ExplorerLink";
import { formatAda } from "../format";
import { errorMessage } from "../errorMessage";

// Debounce for the search box so each keystroke doesn't fire a request.
const SEARCH_DEBOUNCE_MS = 250;

// Percent display for a fraction (0.02 → "2.0%"). Non-finite/absent → "—".
function pct(fraction: number): string {
  if (!Number.isFinite(fraction)) return "—";
  return `${(fraction * 100).toFixed(1)}%`;
}

// Truncate a long bech32 pool id in the middle so rows stay scannable.
function shortId(id: string): string {
  if (id.length <= 24) return id;
  return `${id.slice(0, 14)}…${id.slice(-6)}`;
}

const POOL_COLUMNS = [
  { key: "pool", label: "Pool ID" },
  { key: "margin", label: "Margin" },
  { key: "pledge", label: "Pledge (ADA)" },
  { key: "live_stake", label: "Live stake (ADA)" },
  { key: "saturation", label: "Saturation" },
  { key: "actions", label: "" },
];

interface PoolDirectoryProps {
  network: string;
}

// PoolDirectory is a read-only browse/search screen for the stake pools the
// embedded node has indexed. Data comes entirely from the local node (no
// external service), so it needs no consent gate. It does not delegate: copy a
// pool ID and paste it into Staking to delegate to it.
export function PoolDirectory({ network }: PoolDirectoryProps) {
  const [query, setQuery] = useState("");
  const [page, setPage] = useState(1);
  const [data, setData] = useState<PoolDirectoryResponse | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    const q = query.trim();
    let cancelled = false;
    setLoading(true);
    const timer = setTimeout(() => {
      getPoolDirectory({ q, page })
        .then((d) => {
          if (!cancelled) {
            setData(d);
            setError(null);
          }
        })
        .catch((e) => {
          if (!cancelled) setError(errorMessage(e));
        })
        .finally(() => {
          if (!cancelled) setLoading(false);
        });
    }, SEARCH_DEBOUNCE_MS);
    return () => {
      cancelled = true;
      clearTimeout(timer);
    };
  }, [query, page]);

  const pools = data?.pools ?? [];
  const count = data?.count ?? 0;
  const total = data?.total ?? 0;
  const pageCount = count > 0 ? Math.ceil(total / count) : 1;
  const hasPrev = page > 1;
  const hasNext = page < pageCount;

  const rows = pools.map((p) => ({
    pool: (
      <span className="pool-id-cell">
        <code>{shortId(p.pool_id)}</code>
        <ExplorerLink network={network} kind="pool" id={p.pool_id} />
      </span>
    ),
    margin: pct(p.margin_cost),
    pledge: formatAda(p.declared_pledge),
    live_stake: formatAda(p.live_stake),
    saturation: pct(p.live_saturation),
    actions: <CopyButton value={p.pool_id} aria-label={`Copy pool id ${p.pool_id}`} />,
  }));

  return (
    <div className="send-form">
      <Card title="Stake Pool Directory">
        <p className="helper-text">
          Browse and search stake pools your embedded node has indexed — read
          directly from the node, no external service is contacted. To delegate,
          copy a pool ID and paste it into <strong>Staking</strong>.
        </p>

        <label htmlFor="pool-search">Search by pool ID</label>
        <Input
          id="pool-search"
          type="text"
          placeholder="pool1… or hex id"
          value={query}
          onChange={(e) => {
            setQuery(e.target.value);
            setPage(1);
          }}
        />

        {error && (
          <p role="alert" className="error-text">
            {error}
          </p>
        )}

        {loading && !data ? (
          <p className="muted">Reading pools from the local node…</p>
        ) : rows.length === 0 ? (
          <p className="muted">
            {query.trim() ? "No pools match your search." : "No pools found."}
          </p>
        ) : (
          <>
            <Table columns={POOL_COLUMNS} rows={rows} />
            <div className="pager">
              <Button
                variant="ghost"
                disabled={!hasPrev}
                onClick={() => setPage((p) => Math.max(1, p - 1))}
              >
                Previous
              </Button>
              <span className="muted">
                Page {page} of {pageCount} · {total} pool{total === 1 ? "" : "s"}
              </span>
              <Button
                variant="ghost"
                disabled={!hasNext}
                onClick={() => setPage((p) => p + 1)}
              >
                Next
              </Button>
            </div>
          </>
        )}
      </Card>
    </div>
  );
}
