import type { Tone } from "./StatusPill";
import type { Status, NodeState } from "../api/types";

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
    detail = `${status.bootstrap.phase} ${status.bootstrap.percent.toFixed(1)}%`;
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
