// The Mithril bootstrap pipeline with operator-facing labels. The order is a
// reading order for the checklist, NOT a sequence: dingo runs the ledger import
// and the immutable copy concurrently, and may skip a phase entirely, so a
// phase's position here says nothing about whether it has run. Only what the
// node reports for a phase does.
//
// "complete" isn't listed — by the time it fires the node has moved on to chain
// sync (or ready), so it never needs a row of its own.
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
