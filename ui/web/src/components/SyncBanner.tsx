import { StatusPill } from "./StatusPill";
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

export function SyncBanner({ status }: SyncBannerProps) {
  const tone = stateToTone(status.state);

  let label: string = status.state;
  if (status.bootstrap) {
    label = `${status.bootstrap.phase} ${status.bootstrap.percent.toFixed(0)}%`;
  }

  return (
    <div className="sync-banner">
      <StatusPill tone={tone}>{label}</StatusPill>
      {status.state === "ready" && (
        <span>
          tip: {status.tip} &mdash; {status.caughtUp ? "caught up" : "syncing"}
        </span>
      )}
    </div>
  );
}
