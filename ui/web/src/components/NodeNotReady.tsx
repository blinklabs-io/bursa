import { Card } from "./Card";
import { useStatus } from "../api/hooks";
import { bootstrapPhaseLabel } from "../bootstrapPhases";

// The read-only escape hatch on the Syncing screen invites people in before the
// node can answer anything, promising that "balances and history stay incomplete
// until syncing finishes". The screens that land them there have to keep that
// promise: a bare "node not ready" in an otherwise blank page reads as a broken
// wallet, not as a node that is still working — and it is the first thing a new
// user sees, since waiting out a multi-gigabyte bootstrap is the alternative.
//
// This is deliberately NOT a generic error view. It is the answer to one
// specific, expected, self-resolving condition (the node's own 503 while it
// starts up); real faults still surface as errors so they stay visible.
// `verb` agrees with `what`: some callers name one thing, some name two.
export function NodeNotReady({ what, verb = "comes" }: { what: string; verb?: string }) {
  const status = useStatus();
  const state = status.data?.state;
  const bootstrap = status.data?.bootstrap;

  return (
    <Card title="Waiting for the node">
      <p className="helper-text">
        {what} {verb} from your own node, which is still starting up. Nothing is
        wrong — this screen fills in by itself once the node can answer, and
        nothing here needs the network.
      </p>
      {bootstrap ? (
        <p className="setting-state">
          {bootstrapPhaseLabel(bootstrap.phase)} · {bootstrap.percent.toFixed(1)}%
        </p>
      ) : (
        state && <p className="setting-state">{state}</p>
      )}
      <p className="helper-text">
        Your keys are already in the vault — nothing is lost and nothing needs
        your attention. Balances, history and addresses are all read through the
        node, so they fill in together once it is ready.
      </p>
    </Card>
  );
}
