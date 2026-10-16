import { useState } from "react";
import type { Preview, SurveyStatus } from "../api/types";
import { useSurvey, useSurveys } from "../api/hooks";
import { cancelSurvey, revealSurvey } from "../api/client";
import { Card } from "../components/Card";
import { Input } from "../components/Input";
import { Button } from "../components/Button";
import { Select } from "../components/Select";
import { Table } from "../components/Table";
import { CopyButton } from "../components/CopyButton";
import { errorMessage } from "../errorMessage";
import { shortId } from "../format";
import { ROLE_LABELS, roundTime } from "../surveys";
import { SurveyConfirm } from "./SurveyConfirm";
import { SurveyResults } from "./SurveyResults";
import { SurveyRespond } from "./SurveyRespond";
import { SurveyBuilder } from "./SurveyBuilder";

const STATUS_OPTIONS = [
  { value: "", label: "All" },
  { value: "open", label: "Open" },
  { value: "closed", label: "Closed" },
  { value: "cancelled", label: "Cancelled" },
];

const DRAND_RELAY = "api.drand.sh";

type View = { name: "list" } | { name: "detail"; id: string } | { name: "create" };

interface Pending {
  preview: Preview;
  summary: string;
  signedContent: string;
}

interface SurveysProps {
  // Building a transaction needs a wallet that signs with a local seed and a
  // fully synced node; reading only needs a queryable node.
  canSubmit: boolean;
  // A survey to open directly, as a link from the governance browser does.
  initialId?: string;
}

// Surveys browses CIP-179 on-chain surveys and polls read from the embedded
// node, shows their per-role results, and lets this wallet respond to, create
// and cancel them.
export function Surveys({ canSubmit, initialId }: SurveysProps) {
  const [view, setView] = useState<View>(initialId ? { name: "detail", id: initialId } : { name: "list" });
  const [pending, setPending] = useState<Pending | null>(null);

  // After a transaction is submitted the node needs a block to show it, so go
  // back to the list rather than to a stale detail view.
  function done() {
    setPending(null);
    setView({ name: "list" });
  }

  if (pending) {
    return (
      <div className="staking">
        <SurveyConfirm
          summary={pending.summary}
          signedContent={pending.signedContent}
          preview={pending.preview}
          onBack={() => setPending(null)}
          onDone={done}
        />
      </div>
    );
  }
  if (view.name === "create") {
    return (
      <SurveyBuilder
        onBack={() => setView({ name: "list" })}
        onPreview={(preview, summary, signedContent) => setPending({ preview, summary, signedContent })}
      />
    );
  }
  if (view.name === "detail") {
    return (
      <SurveyDetailView
        id={view.id}
        canSubmit={canSubmit}
        onBack={() => setView({ name: "list" })}
        onPreview={(preview, summary, signedContent) => setPending({ preview, summary, signedContent })}
      />
    );
  }
  return (
    <SurveyList
      canSubmit={canSubmit}
      onOpen={(id) => setView({ name: "detail", id })}
      onCreate={() => setView({ name: "create" })}
    />
  );
}

interface SurveyListProps {
  canSubmit: boolean;
  onOpen: (id: string) => void;
  onCreate: () => void;
}

function SurveyList({ canSubmit, onOpen, onCreate }: SurveyListProps) {
  const [query, setQuery] = useState("");
  const [status, setStatus] = useState<SurveyStatus | "">("");
  const [page, setPage] = useState(1);
  const { data, error, loading } = useSurveys({ q: query, status, page });

  const surveys = data?.surveys ?? [];
  const count = data?.count ?? 0;
  const total = data?.total ?? 0;
  const pageCount = count > 0 ? Math.ceil(total / count) : 1;

  const rows = surveys.map((s) => ({
    title: (
      <Button variant="ghost" onClick={() => onOpen(s.id)}>
        {s.title || shortId(s.id)}
      </Button>
    ),
    status: s.status.charAt(0).toUpperCase() + s.status.slice(1),
    roles: s.roles.map((r) => ROLE_LABELS[r]).join(", "),
    ends: s.end_epoch,
    notes: [s.sealed ? "Sealed" : "", s.linked_actions.length > 0 ? "Linked to governance" : "", s.owned ? "Yours" : ""]
      .filter(Boolean)
      .join(" · "),
  }));

  return (
    <div className="send-form">
      <Card title="Surveys">
        <p className="helper-text">
          On-chain surveys and polls (CIP-179) read from your embedded node — no external service is contacted.
          Anyone can publish one, so check who is asking before you respond.
        </p>
        {data?.partial && (
          <p role="status" className="helper-text">
            Showing surveys indexed so far. More may appear while the node scans the CIP-179 history.
          </p>
        )}
        <div className="preview-actions">
          <Button onClick={onCreate} disabled={!canSubmit} title={canSubmit ? undefined : "Needs a synced node and a wallet with a local seed"}>
            New survey
          </Button>
        </div>

        <label htmlFor="survey-search">Search by title, description or id</label>
        <Input
          id="survey-search"
          value={query}
          onChange={(e) => {
            setQuery(e.target.value);
            setPage(1);
          }}
        />
        <label htmlFor="survey-status">Status</label>
        <Select
          id="survey-status"
          value={status}
          onChange={(e) => {
            setStatus(e.target.value as SurveyStatus | "");
            setPage(1);
          }}
          options={STATUS_OPTIONS}
        />

        {error && (
          <p role="alert" className="error-text">
            {error.message}
          </p>
        )}
        {loading && !data && <p className="helper-text">Loading…</p>}
        {loading && data && (
          <p className="helper-text" role="status">
            Updating…
          </p>
        )}
        {!error && !loading && surveys.length === 0 && <p className="helper-text">No surveys found.</p>}
        {surveys.length > 0 && (
          <div aria-busy={loading}>
            <Table
              columns={[
                { key: "title", label: "Survey" },
                { key: "status", label: "Status" },
                { key: "roles", label: "Open to" },
                { key: "ends", label: "Ends (epoch)" },
                { key: "notes", label: "" },
              ]}
              rows={rows}
            />
            <div className="preview-actions">
              <Button variant="ghost" disabled={page <= 1} onClick={() => setPage((p) => p - 1)}>
                Previous
              </Button>
              <span className="helper-text">
                Page {page} of {pageCount}
              </span>
              <Button variant="ghost" disabled={page >= pageCount} onClick={() => setPage((p) => p + 1)}>
                Next
              </Button>
            </div>
          </div>
        )}
      </Card>
    </div>
  );
}

interface SurveyDetailViewProps {
  id: string;
  canSubmit: boolean;
  onBack: () => void;
  onPreview: (preview: Preview, summary: string, signedContent: string) => void;
}

function SurveyDetailView({ id, canSubmit, onBack, onPreview }: SurveyDetailViewProps) {
  const { data: survey, error, loading, reload } = useSurvey(id);
  const [actionError, setActionError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  if (error) {
    return (
      <Card title="Survey">
        <p role="alert" className="error-text">
          {error.message}
        </p>
        <Button variant="ghost" onClick={onBack}>
          Back
        </Button>
      </Card>
    );
  }
  if (!survey) {
    return <Card title="Survey">{loading ? <p className="helper-text">Loading…</p> : null}</Card>;
  }
  const currentSurvey = survey;

  async function cancel() {
    setActionError(null);
    setBusy(true);
    try {
      onPreview(
        await cancelSurvey(id),
        `Cancel the survey “${currentSurvey.title}”`,
        JSON.stringify({ cancellation: currentSurvey.id }, null, 2),
      );
    } catch (e) {
      setActionError(errorMessage(e));
    } finally {
      setBusy(false);
    }
  }

  const open = survey.status === "open";
  const hasSealed = survey.tally?.roles.some((r) => (r.sealed ?? 0) > 0) ?? false;
  return (
    <div className="staking">
      <Card title={survey.title || "Survey"}>
        <p>{survey.description}</p>
        <dl className="preview-summary">
          <div className="dl-row">
            <dt>Status</dt>
            <dd>{survey.status}</dd>
          </div>
          <div className="dl-row">
            <dt>Last epoch for responses</dt>
            <dd>{survey.end_epoch}</dd>
          </div>
          <div className="dl-row">
            <dt>Open to</dt>
            <dd>{survey.roles.map((r) => ROLE_LABELS[r]).join(", ")}</dd>
          </div>
          <div className="dl-row">
            <dt>Owner</dt>
            <dd>
              <code>{shortId(survey.owner)}</code>
              {survey.owned ? " (this wallet)" : ""}
            </dd>
          </div>
          {survey.definition.anchor && (
            <div className="dl-row">
              <dt>Presentation document</dt>
              <dd>
                <code>{survey.definition.anchor.uri}</code> (hash <code>{shortId(survey.definition.anchor.hash)}</code>)
              </dd>
            </div>
          )}
          <div className="dl-row">
            <dt>Survey id</dt>
            <dd>
              <code>{shortId(survey.id)}</code> <CopyButton value={survey.id} ariaLabel={`Copy survey id ${survey.id}`} />
            </dd>
          </div>
        </dl>
        {survey.linked_actions.length > 0 && (
          <p className="helper-text">
            Linked from {survey.linked_actions.length === 1 ? "governance action" : "governance actions"}:{" "}
            {survey.linked_actions.map((a) => shortId(a)).join(", ")}. A link only advertises the survey; it
            never changes who may respond.
          </p>
        )}
        {survey.definition.mode.sealed && survey.definition.mode.round && (
          <p className="helper-text">
            Responses are sealed until {roundTime(survey.definition.mode.round).toLocaleString()} (Drand round{" "}
            {survey.definition.mode.round}).
          </p>
        )}
        {survey.status === "cancelled" && (
          <p className="helper-text">The owner cancelled this survey. Its responses are not tallied.</p>
        )}
        {actionError && (
          <p role="alert" className="error-text">
            {actionError}
          </p>
        )}
        <div className="preview-actions">
          <Button variant="ghost" onClick={onBack}>
            Back
          </Button>
          <Button variant="ghost" onClick={reload}>
            Refresh
          </Button>
          {survey.owned && open && (
            <Button variant="ghost" onClick={cancel} disabled={!canSubmit || busy}>
              Cancel survey
            </Button>
          )}
        </div>
      </Card>

      {hasSealed && <RevealPanel id={id} onRevealed={reload} />}
      <SurveyResults survey={survey} />
      {open && canSubmit && <SurveyRespond survey={survey} onPreview={onPreview} />}
      {open && !canSubmit && (
        <Card title="Respond">
          <p className="helper-text">Responding needs a synced node and a wallet that signs with a local seed.</p>
        </Card>
      )}
    </div>
  );
}

// RevealPanel opens a sealed survey's responses. Fetching the Drand beacon
// contacts a public relay, so it happens only when the user agrees to it here;
// a beacon pasted in avoids the request entirely.
function RevealPanel({ id, onRevealed }: { id: string; onRevealed: () => void }) {
  const [consent, setConsent] = useState(false);
  const [beacon, setBeacon] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);

  async function reveal() {
    setError(null);
    setLoading(true);
    try {
      const pasted = beacon.trim();
      await revealSurvey(id, pasted ? { beacon: pasted } : { consent });
      onRevealed();
    } catch (e) {
      setError(errorMessage(e));
    } finally {
      setLoading(false);
    }
  }

  return (
    <Card title="Reveal sealed responses">
      <div className="staking-form">
        <p className="helper-text">
          Some responses are still sealed. Once the reveal time has passed they can be opened with the Drand
          beacon for the reveal round.
        </p>
        <label>
          <input type="checkbox" checked={consent} onChange={(e) => setConsent(e.target.checked)} /> Fetch the beacon
          from {DRAND_RELAY} (an external service; your wallet contacts it only now)
        </label>
        <label htmlFor="survey-beacon">Or paste the beacon signature (hex)</label>
        <Input id="survey-beacon" value={beacon} onChange={(e) => setBeacon(e.target.value)} />
        {error && (
          <p role="alert" className="error-text">
            {error}
          </p>
        )}
        <Button onClick={reveal} disabled={loading || (!consent && beacon.trim() === "")}>
          {loading ? "Revealing…" : "Reveal responses"}
        </Button>
      </div>
    </Card>
  );
}
