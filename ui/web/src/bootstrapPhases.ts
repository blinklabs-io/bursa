// The Mithril bootstrap pipeline, in the order dingo emits it, with operator-
// facing labels. "complete" isn't shown — by the time it fires the node has
// moved on to chain sync (or ready), so it never needs a step of its own.
//
// Shared rather than private to the Syncing screen: the sync banner rides along
// on every screen for the whole bootstrap, and the phase keys are dingo's
// internal identifiers ("immutable_copy", "post_ledger_state"). Showing those
// raw is worse the longer a phase lasts, and the long phases are exactly the
// ones a user sits through.
export const BOOTSTRAP_PHASES: { key: string; label: string }[] = [
  { key: "bootstrap", label: "Download snapshot" },
  { key: "ledger_import", label: "Import ledger state" },
  { key: "immutable_copy", label: "Copy chain history" },
  { key: "gap_blocks", label: "Fetch gap blocks" },
  { key: "post_ledger_state", label: "Rebuild ledger state" },
  { key: "backfill", label: "Backfill blocks" },
  { key: "index_rebuild", label: "Rebuild indexes" },
];

// An unknown key is de-underscored rather than hidden: a phase dingo adds later
// should still read as words, and something is more use than a blank.
export function bootstrapPhaseLabel(phase: string): string {
  return (
    BOOTSTRAP_PHASES.find((p) => p.key === phase)?.label ??
    phase.replace(/_/g, " ")
  );
}

// Where a phase sits in the pipeline, or null for a phase we do not know.
//
// The per-phase percent restarts at 0 on every handoff. Measured on preview
// (dingo v0.70.5): the snapshot download read 99.8% one moment and the next
// phase read 0.1% five seconds later, with the byte readout replaced by a block
// count. Showing the step position next to that percent is what keeps the reset
// legible as forward motion rather than a restart.
//
// dingo may skip a phase — that run went straight from "bootstrap" to
// "immutable_copy" — so the step can jump. This reports a position in the
// pipeline rather than a count of phases seen, so a skip reads as progress.
export function bootstrapStepPosition(
  phase: string,
): { step: number; total: number } | null {
  const idx = BOOTSTRAP_PHASES.findIndex((p) => p.key === phase);
  if (idx < 0) return null;
  return { step: idx + 1, total: BOOTSTRAP_PHASES.length };
}
