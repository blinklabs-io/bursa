import type { Tone } from "./StatusPill";
import type { Status, NodeState } from "../api/types";
import { bootstrapPhaseLabel, fmtBytes } from "../bootstrapPhases";

interface SyncBannerProps {
  status: Status;
}

function stateToTone(state: NodeState): Tone {
  switch (state) {
    case "ready":
      return "ok";
    case "syncing":
    case "bootstrapping":
      return "warn";
    case "error":
      return "error";
    default:
      return "muted";
  }
}

// SyncBanner is the cockpit's node-health strip: a lit status dot, the node
// state, and a monospace readout (bootstrap progress, chain tip, or error).
export function SyncBanner({ status }: SyncBannerProps) {
  const tone = stateToTone(status.state);

  let detail = "";
  if (status.state === "bootstrapping" && status.bootstrap) {
    // Name everything that is running, because more than one thing is: the node
    // fetches two downloads at once, then imports the ledger state while it
    // copies the chain, and reports all of it through a single field. A lone
    // percent here flipped between unrelated numbers every poll — and this
    // strip is on screen for the whole bootstrap, on every screen, which is
    // where that was seen most.
    const running = (status.bootstrap_phases ?? []).filter((p) => !p.done);
    const shown = running.length > 0 ? running : [status.bootstrap];
    // Two downloads share a phase name, so the percent alone would read as one
    // number contradicting itself.
    const phaseCounts = new Map<string, number>();
    for (const p of shown) phaseCounts.set(p.phase, (phaseCounts.get(p.phase) ?? 0) + 1);
    detail = shown
      .map((p) => {
        const label = bootstrapPhaseLabel(p.phase);
        const name =
          (phaseCounts.get(p.phase) ?? 0) > 1 && p.total_bytes
            ? `${label} (${fmtBytes(p.total_bytes)})`
            : label;
        return `${name} ${p.percent.toFixed(1)}%`;
      })
      .join(" · ");
  } else if (status.state === "ready") {
    detail = `tip ${status.tip} · ${status.caughtUp ? "caught up" : "catching up"}`;
  } else if (status.error) {
    detail = status.error;
  }

  return (
    <div className="sync-banner" role="status" aria-live="polite">
      <span className={`dot dot-${tone}`} aria-hidden="true" />
      <span className="sync-state">{status.state}</span>
      {detail && <span className="sync-detail">{detail}</span>}
    </div>
  );
}
