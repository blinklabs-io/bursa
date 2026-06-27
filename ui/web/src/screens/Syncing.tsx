import type { Status, BootstrapProgress } from "../api/types";

interface SyncingProps {
  status: Status;
  onLoadAnyway: () => void;
}

// The Mithril bootstrap pipeline, in the order dingo emits it, with operator-
// facing labels. "complete" isn't shown — by the time it fires the node has
// moved on to chain sync (or ready), so it never needs a step of its own.
const PHASES: { key: string; label: string }[] = [
  { key: "bootstrap", label: "Download snapshot" },
  { key: "ledger_import", label: "Import ledger state" },
  { key: "immutable_copy", label: "Copy chain history" },
  { key: "gap_blocks", label: "Fetch gap blocks" },
  { key: "post_ledger_state", label: "Rebuild ledger state" },
  { key: "backfill", label: "Backfill blocks" },
  { key: "index_rebuild", label: "Rebuild indexes" },
];

function fmtBytes(n?: number): string {
  if (!n || n <= 0) return "0 B";
  const units = ["B", "KB", "MB", "GB", "TB"];
  let v = n;
  let i = 0;
  while (v >= 1024 && i < units.length - 1) {
    v /= 1024;
    i += 1;
  }
  return `${v.toFixed(i === 0 || v >= 100 ? 0 : 1)} ${units[i]}`;
}

function fmtInt(n?: number): string {
  return (n ?? 0).toLocaleString();
}

// Coarse, honest durations — "~8 min left", not "8:07". Returns "" when there's
// nothing meaningful to show (no rate / already done).
function fmtDuration(seconds: number, suffix: string): string {
  if (!isFinite(seconds) || seconds <= 0) return "";
  if (seconds < 90) return `~${Math.round(seconds)}s ${suffix}`;
  const m = seconds / 60;
  if (m < 90) return `~${Math.round(m)} min ${suffix}`;
  const h = m / 60;
  if (h < 36) return `~${Math.round(h)} h ${suffix}`;
  return `~${Math.round(h / 24)} d ${suffix}`;
}

// How far the node's latest block lags wall-clock time — the intuitive "where
// it is" for chain sync, since it shrinks toward zero as the node catches up.
// Units are spelled out: this is the view's hero readout, not a terse ETA.
function fmtBehind(latest: string | undefined, nowMs: number): string {
  if (!latest) return "waiting for first block";
  const ms = nowMs - Date.parse(latest);
  if (!isFinite(ms) || ms <= 0) return "at the chain tip";
  const s = ms / 1000;
  const pick = (v: number, unit: string) => {
    const n = Math.round(v);
    return `${n} ${unit}${n === 1 ? "" : "s"} behind`;
  };
  if (s < 90) return pick(s, "second");
  const m = s / 60;
  if (m < 90) return pick(m, "minute");
  const h = m / 60;
  if (h < 36) return pick(h, "hour");
  return pick(h / 24, "day");
}

function Bar({ percent, indeterminate }: { percent?: number; indeterminate?: boolean }) {
  if (indeterminate) {
    return (
      <div className="sync-bar" role="progressbar" aria-label="Syncing…">
        <div className="sync-bar-fill sync-bar-indeterminate" />
      </div>
    );
  }
  const p = Math.max(0, Math.min(100, percent ?? 0));
  return (
    <div
      className="sync-bar"
      role="progressbar"
      aria-valuenow={Math.round(p)}
      aria-valuemin={0}
      aria-valuemax={100}
    >
      <div className="sync-bar-fill" style={{ width: `${p}%` }} />
    </div>
  );
}

function PhaseSteps({ active }: { active: string }) {
  const idx = PHASES.findIndex((p) => p.key === active);
  return (
    <ol className="sync-steps">
      {PHASES.map((p, i) => {
        const state =
          idx < 0 ? "pending" : i < idx ? "done" : i === idx ? "active" : "pending";
        return (
          <li key={p.key} className={`sync-step sync-step-${state}`}>
            <span className="sync-step-dot" aria-hidden="true" />
            <span className="sync-step-label">{p.label}</span>
          </li>
        );
      })}
    </ol>
  );
}

// The detail readout for an in-flight Mithril bootstrap phase: a percent bar
// plus whichever positional pair the active phase populates (bytes for the
// download, count/slot for the block-replay phases).
function BootstrapDetail({ bp }: { bp: BootstrapProgress }) {
  const phaseLabel =
    PHASES.find((p) => p.key === bp.phase)?.label ?? bp.phase.replace(/_/g, " ");

  const readouts: string[] = [];
  if (bp.total_bytes && bp.total_bytes > 0) {
    let line = `${fmtBytes(bp.bytes_downloaded)} / ${fmtBytes(bp.total_bytes)}`;
    if (bp.bytes_per_second && bp.bytes_per_second > 0) {
      line += ` · ${fmtBytes(bp.bytes_per_second)}/s`;
      const remaining = (bp.total_bytes - (bp.bytes_downloaded ?? 0)) / bp.bytes_per_second;
      const eta = fmtDuration(remaining, "left");
      if (eta) line += ` · ${eta}`;
    }
    readouts.push(line);
  } else if (bp.total && bp.total > 0) {
    let line = `${fmtInt(bp.count)} / ${fmtInt(bp.total)} blocks`;
    if (bp.bytes_per_second && bp.bytes_per_second > 0) {
      line += ` · ${fmtBytes(bp.bytes_per_second)}/s`;
    }
    readouts.push(line);
  }
  if (bp.tip_slot && bp.tip_slot > 0) {
    readouts.push(`slot ${fmtInt(bp.current_slot)} → ${fmtInt(bp.tip_slot)}`);
  }

  return (
    <div className="sync-panel">
      <div className="sync-phase-head">
        <span className="sync-phase-label">
          {phaseLabel}
          {bp.description ? ` · ${bp.description}` : ""}
        </span>
        <span className="sync-percent">{bp.percent.toFixed(1)}%</span>
      </div>
      <Bar percent={bp.percent} />
      {readouts.map((r) => (
        <p key={r} className="sync-readout">
          {r}
        </p>
      ))}
      <PhaseSteps active={bp.phase} />
    </div>
  );
}

// The detail readout for P2P chain sync: how far behind the tip we are, the
// node's current block, and an indeterminate bar (there's no firm network-tip
// estimate to make into a percent, so we don't fake one).
function ChainSyncDetail({ status }: { status: Status }) {
  const nowMs = Date.now();
  return (
    <div className="sync-panel">
      <p className="sync-behind">{fmtBehind(status.latestBlockTime, nowMs)}</p>
      <Bar indeterminate />
      <dl className="sync-stats">
        <div>
          <dt>Block slot</dt>
          <dd>{status.tip > 0 ? fmtInt(status.tip) : "—"}</dd>
        </div>
        <div>
          <dt>Latest block</dt>
          <dd>
            {status.latestBlockTime
              ? new Date(status.latestBlockTime).toLocaleString()
              : "—"}
          </dd>
        </div>
      </dl>
    </div>
  );
}

export function Syncing({ status, onLoadAnyway }: SyncingProps) {
  let title: string;
  let subtitle: string;
  switch (status.state) {
    case "bootstrapping":
      title = "Bootstrapping from a Mithril snapshot";
      subtitle = "Fast-syncing the chain database from a verified snapshot. This runs once.";
      break;
    case "syncing":
      title = "Catching up to the chain";
      subtitle = "Following the Cardano network from your node’s last known block.";
      break;
    case "starting":
      title = "Starting your node";
      subtitle = "Bringing the embedded Cardano node online.";
      break;
    case "error":
      title = "Sync interrupted";
      subtitle = status.error || "The node reported an error.";
      break;
    default:
      title = "Preparing";
      subtitle = "Getting the node ready.";
  }

  let detail;
  if (status.state === "bootstrapping" && status.bootstrap) {
    detail = <BootstrapDetail bp={status.bootstrap} />;
  } else if (status.state === "syncing") {
    detail = <ChainSyncDetail status={status} />;
  } else if (status.state === "error") {
    detail = (
      <div className="sync-panel">
        <p className="error-text" role="alert">
          {status.error || "The node reported an error."}
        </p>
      </div>
    );
  } else {
    // starting / stopped / pre-first-poll: nothing to quantify yet.
    detail = (
      <div className="sync-panel">
        <Bar indeterminate />
      </div>
    );
  }

  return (
    <div className="syncing">
      <header className="sync-head">
        <h1 className="sync-title">{title}</h1>
        <p className="sync-subtitle">{subtitle}</p>
      </header>

      {detail}

      <footer className="sync-foot">
        <button type="button" className="btn ghost sync-escape" onClick={onLoadAnyway}>
          Load wallet anyway (read-only)
        </button>
        <p className="helper-text">
          You can open a wallet now, but balances and history stay incomplete
          until syncing finishes.
        </p>
      </footer>
    </div>
  );
}
