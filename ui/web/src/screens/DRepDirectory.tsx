import { useState, useEffect } from "react";
import type { DRepDirectoryResponse, DRepListItem } from "../api/types";
import { getDReps } from "../api/client";
import { Card } from "../components/Card";
import { Input } from "../components/Input";
import { Button } from "../components/Button";
import { Table } from "../components/Table";
import { CopyButton } from "../components/CopyButton";
import { ExplorerLink } from "../components/ExplorerLink";
import { formatAda } from "../format";
import { errorMessage } from "../errorMessage";
import { navigate } from "../router";

// Debounce for the search box so each keystroke doesn't fire a request.
const SEARCH_DEBOUNCE_MS = 250;

// Truncate a long bech32 drep id in the middle so rows stay scannable.
function shortId(id: string): string {
  if (id.length <= 24) return id;
  return `${id.slice(0, 14)}…${id.slice(-6)}`;
}

// Voting power in ADA, or "—" when the node did not expose an amount.
function power(amount: string): string {
  if (!amount) return "—";
  return formatAda(amount);
}

// The two predefined voting targets. The node interleaves them into its DRep
// list at the position of their first delegation, with an empty hex and no
// metadata. They are real delegation targets carrying real voting power, so
// the directory lists them — but they have no on-chain registration to look up
// and no id worth pasting: Staking offers them as their own options.
const PREDEFINED_DREP_IDS = new Set([
  "drep_always_abstain",
  "drep_always_no_confidence",
]);

// CIP-1694 status. The node reports two independent facts rather than one
// "active" flag: retired means the DRep deregistered, expired means it is
// still registered but has not acted within the node's DRep inactivity period.
// Retired is the terminal one, so it wins when both are set.
function status(d: DRepListItem): { label: string; title?: string } {
  if (PREDEFINED_DREP_IDS.has(d.drep_id)) {
    return {
      label: "Predefined",
      title: "A predefined voting target — choose it directly in Staking.",
    };
  }
  if (d.retired) {
    return { label: "Retired", title: "Deregistered on chain." };
  }
  if (d.expired) {
    return {
      label: "Expired",
      title:
        d.last_active_epoch === null
          ? "Registered, but inactive past the node's DRep inactivity period."
          : `Registered, but inactive since epoch ${d.last_active_epoch}.`,
    };
  }
  return { label: "Registered" };
}

const DREP_COLUMNS = [
  { key: "drep", label: "DRep ID" },
  { key: "power", label: "Voting power (ADA)" },
  { key: "status", label: "Status" },
  { key: "metadata", label: "Metadata" },
  { key: "actions", label: "" },
];

interface DRepDirectoryProps {
  network: string;
  // Whether the active wallet can reach Staking (a synced node AND a
  // spending-enabled wallet — see app.tsx's canStake). Read-only and hardware
  // wallets cannot, so the per-row "Delegate" shortcut is hidden for them
  // rather than silently landing on Portfolio when clicked. Defaults to true
  // so existing callers/tests that don't pass it keep the prior behavior.
  canDelegate?: boolean;
}

// DRepDirectory is a read-only browse/search screen for the delegated
// representatives the embedded node has indexed. Data comes entirely from the
// local node (no external service), so it needs no consent gate. It does not
// delegate: copy a DRep ID and paste it into Staking, or use "Delegate" to jump
// there.
export function DRepDirectory({ network, canDelegate = true }: DRepDirectoryProps) {
  const [query, setQuery] = useState("");
  const [page, setPage] = useState(1);
  const [data, setData] = useState<DRepDirectoryResponse | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    const q = query.trim();
    let cancelled = false;
    setLoading(true);
    const timer = setTimeout(() => {
      getDReps({ q, page })
        .then((d) => {
          if (!cancelled) {
            setData(d);
            setError(null);
          }
        })
        .catch((e) => {
          if (!cancelled) {
            setError(errorMessage(e));
            setData(null);
          }
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

  const dreps = data?.dreps ?? [];
  const count = data?.count ?? 0;
  const total = data?.total ?? 0;
  const pageCount = count > 0 ? Math.ceil(total / count) : 1;
  const hasPrev = page > 1;
  const hasNext = page < pageCount;

  const rows = dreps.map((d) => {
    const predefined = PREDEFINED_DREP_IDS.has(d.drep_id);
    const { label, title } = status(d);
    const anchorURL = d.metadata?.url ?? "";
    return {
      drep: (
        <span className="pool-id-cell">
          <code>{shortId(d.drep_id)}</code>
          {/* A predefined target has no on-chain credential, so there is
              nothing for an explorer to resolve. */}
          {!predefined && <ExplorerLink network={network} kind="drep" id={d.drep_id} />}
        </span>
      ),
      power: power(d.amount),
      status: <span title={title}>{label}</span>,
      metadata: anchorURL ? (
        <span className="muted" title={anchorURL}>
          {shortId(anchorURL)}
        </span>
      ) : (
        "—"
      ),
      actions: (
        <span className="pool-id-cell">
          {/* "drep_always_abstain" is not an id Staking accepts in its DRep
              field — it is a separate option there — so copying it would hand
              the user a value that cannot be pasted anywhere. */}
          {!predefined && (
            <CopyButton value={d.drep_id} aria-label={`Copy drep id ${d.drep_id}`} />
          )}
          {canDelegate && (
            <Button variant="ghost" onClick={() => navigate("staking")}>
              Delegate
            </Button>
          )}
        </span>
      ),
    };
  });

  return (
    <div className="send-form">
      <Card title="DRep Directory">
        <p className="helper-text">
          Browse and search the delegated representatives your embedded node has
          indexed — read directly from the node, no external service is
          contacted. To delegate your voting power, copy a DRep ID and paste it
          into <strong>Staking</strong>
          {canDelegate && (
            <>
              , or use <strong>Delegate</strong>
            </>
          )}
          .
        </p>

        <label htmlFor="drep-search">Search by DRep ID or metadata</label>
        <Input
          id="drep-search"
          type="text"
          placeholder="drep1… or hex id"
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
          <p className="muted">Reading DReps from the local node…</p>
        ) : error ? null : (
          // aria-busy while a debounced request is in flight: the pager below
          // reflects the requested page immediately, so without this the rows
          // for the previous query/page read as the answer to the new one.
          // Kept visible rather than blanked so typing does not flicker.
          //
          // This wraps the empty state too: a previous search that matched
          // nothing would otherwise keep saying "No DReps match your search."
          // for the whole of the next in-flight request, contradicting the
          // pager and offering no sign that anything is happening.
          <div aria-busy={loading}>
            {rows.length === 0 ? (
              <p className="muted">
                {query.trim() ? "No DReps match your search." : "No DReps found."}
              </p>
            ) : (
              <>
                <Table columns={DREP_COLUMNS} rows={rows} />
                <div className="pager">
                  <Button
                    variant="ghost"
                    disabled={!hasPrev}
                    onClick={() => setPage((p) => Math.max(1, p - 1))}
                  >
                    Previous
                  </Button>
                  <span className="muted">
                    Page {page} of {pageCount} · {total} DRep{total === 1 ? "" : "s"}
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
            {loading && (
              <p className="muted" role="status">
                Updating…
              </p>
            )}
          </div>
        )}
      </Card>
    </div>
  );
}
