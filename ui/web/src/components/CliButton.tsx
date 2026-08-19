// The palette is this wallet's command line: with the nav down to five
// destinations, everything else — governance, the DRep directory, offline
// signing, finishing someone else's transaction, pool operations — is reached
// through it. So it deserves a permanent, compact affordance in the chrome
// rather than only the sidebar's wide "Search…" pill, which is desktop-only, and
// Cmd/Ctrl-K, which does not exist on a touch device.
//
// Glyph-only by design (compare CopyButton): a terminal prompt reads faster than
// a word at this size and gives the feature one identity across both layouts.
// The accessible name and the native tooltip carry the meaning for anyone who
// needs it spelled out.
function PromptGlyph() {
  return (
    <svg viewBox="0 0 16 16" width="14" height="14" aria-hidden="true" focusable="false">
      <path
        d="M3.5 5.25L6.25 8 3.5 10.75"
        fill="none"
        stroke="currentColor"
        strokeWidth="1.6"
        strokeLinecap="round"
        strokeLinejoin="round"
      />
      <path
        d="M8.75 11h3.75"
        fill="none"
        stroke="currentColor"
        strokeWidth="1.6"
        strokeLinecap="round"
      />
    </svg>
  );
}

interface CliButtonProps {
  onOpen: () => void;
  // Lets the two layouts size and place the same control differently without a
  // second component.
  className?: string;
  // True while another surface owns the screen — the mobile drawer, which covers
  // the top bar rather than unmounting it. Being covered is only a visual and
  // pointer fact: without this the control keeps its place in the accessibility
  // tree and the tab order, and a screen reader still offers it, ahead of the
  // drawer, because the top bar comes first in the DOM.
  inactive?: boolean;
}

export function CliButton({ onOpen, className, inactive }: CliButtonProps) {
  return (
    <button
      type="button"
      className={className ? `cli-button ${className}` : "cli-button"}
      onClick={onOpen}
      aria-haspopup="dialog"
      aria-label="Open the command line"
      title="Command line — search and run anything"
      aria-hidden={inactive}
      tabIndex={inactive ? -1 : undefined}
    >
      <PromptGlyph />
    </button>
  );
}
