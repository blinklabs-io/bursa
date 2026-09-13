import type { Tone } from "./StatusPill";
import type { Status, NodeState } from "../api/types";
import { bootstrapPhaseLabel } from "../bootstrapPhases";

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
    // Name every phase that is running, because more than one can be. The node
    // imports the ledger state while it copies the immutable chain and reports
    // both through a single field, so a lone percent here flipped between two
    // unrelated numbers every poll — and this strip is on screen for the whole
    // bootstrap, on every screen, which is where that was seen most.
    const running = (status.bootstrap_phases ?? []).filter((p) => !p.done);
    const shown = running.length > 0 ? running : [status.bootstrap];
    detail = shown
      .map((p) => `${bootstrapPhaseLabel(p.phase)} ${p.percent.toFixed(1)}%`)
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
