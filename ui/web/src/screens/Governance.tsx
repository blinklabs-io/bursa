import { useState } from "react";
import { useGovernanceActions } from "../api/hooks";
import { Card } from "../components/Card";
import { Input } from "../components/Input";
import { Button } from "../components/Button";
import { Table } from "../components/Table";
import { CopyButton } from "../components/CopyButton";
import { ExplorerLink } from "../components/ExplorerLink";
import { errorMessage } from "../errorMessage";
import { shortId } from "../format";

// Human-readable type label ("treasury-withdrawal" → "Treasury withdrawal").
function typeLabel(type: string): string {
  const spaced = type.replace(/-/g, " ");
  return spaced.charAt(0).toUpperCase() + spaced.slice(1);
}

// Status label ("active" → "Active").
function statusLabel(status: string): string {
  return status.charAt(0).toUpperCase() + status.slice(1);
}

const COLUMNS = [
  { key: "action", label: "Action ID" },
  { key: "type", label: "Type" },
  { key: "status", label: "Status" },
  { key: "proposed", label: "Proposed (epoch)" },
  { key: "votes", label: "Votes (Y / N / A)" },
  { key: "actions", label: "" },
];

interface GovernanceProps {
  network: string;
}

// Governance is a read-only browse/search screen for the Conway governance
// actions (proposals) the embedded node has recorded. Data comes entirely from
// the local node's metadata DB (no external service), so it needs no consent
// gate. It is a viewer only — it neither builds nor casts votes.
export function Governance({ network }: GovernanceProps) {
  const [query, setQuery] = useState("");
  const [page, setPage] = useState(1);
  const { data, error, loading } = useGovernanceActions({ q: query, page });

  const actions = data?.actions ?? [];
  const count = data?.count ?? 0;
  const total = data?.total ?? 0;
  const pageCount = count > 0 ? Math.ceil(total / count) : 1;
  const hasPrev = page > 1;
  const hasNext = page < pageCount;

  const rows = actions.map((a) => ({
    action: (
      <span className="pool-id-cell">
        <code>{shortId(a.action_id)}</code>
        {a.action_id.startsWith("gov_action") && (
          <ExplorerLink network={network} kind="govaction" id={a.action_id} />
        )}
      </span>
    ),
    type: typeLabel(a.type),
    status: statusLabel(a.status),
    proposed: a.proposed_epoch,
    votes: `${a.yes_votes} / ${a.no_votes} / ${a.abstain_votes}`,
    actions: <CopyButton value={a.action_id} aria-label={`Copy action id ${a.action_id}`} />,
  }));

  return (
    <div className="send-form">
      <Card title="Governance Actions">
        <p className="helper-text">
          Browse and search the on-chain governance actions (Conway proposals)
          your embedded node has recorded — read directly from the node, no
          external service is contacted. This is a read-only viewer with each
          action's type, status, and vote tallies.
        </p>

        <label htmlFor="gov-search">Search by action ID, tx hash, or type</label>
        <Input
          id="gov-search"
          type="text"
          placeholder="gov_action1… , tx hash, or type"
          value={query}
          onChange={(e) => {
            setQuery(e.target.value);
            setPage(1);
          }}
        />

        {error && (
          <p role="alert" className="error-text">
            {errorMessage(error)}
          </p>
        )}

        {loading && !data ? (
          <p className="muted">Reading governance actions from the local node…</p>
        ) : error && !data ? null : rows.length === 0 ? (
          <p className="muted">
            {query.trim()
              ? "No governance actions match your search."
              : "No governance actions found."}
          </p>
        ) : (
          <>
            <Table columns={COLUMNS} rows={rows} />
            <div className="pager">
              <Button
                variant="ghost"
                disabled={!hasPrev}
                onClick={() => setPage((p) => Math.max(1, p - 1))}
              >
                Previous
              </Button>
              <span className="muted">
                Page {page} of {pageCount} · {total} action{total === 1 ? "" : "s"}
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
