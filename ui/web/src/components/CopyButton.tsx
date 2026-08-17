import { useEffect, useRef, useState } from "react";

interface CopyButtonProps {
  value: string;
  ariaLabel?: string;
  "aria-label"?: string;
}

// Icon-only: a copy control sits beside almost every address, hash and CBOR
// blob in the wallet, and 39 buttons reading "Copy" turned dense readouts into
// a wall of repeated words. The glyph carries the meaning; the label carries
// the accessible name.
function CopyGlyph() {
  return (
    <svg viewBox="0 0 16 16" width="14" height="14" aria-hidden="true" focusable="false">
      <rect x="5.5" y="5.5" width="8" height="8" rx="1.5" fill="none" stroke="currentColor" strokeWidth="1.4" />
      <path d="M10.5 3.5A1.5 1.5 0 0 0 9 2H3.5A1.5 1.5 0 0 0 2 3.5V9a1.5 1.5 0 0 0 1.5 1.5" fill="none" stroke="currentColor" strokeWidth="1.4" strokeLinecap="round" />
    </svg>
  );
}

function CheckGlyph() {
  return (
    <svg viewBox="0 0 16 16" width="14" height="14" aria-hidden="true" focusable="false">
      <path d="M3 8.5l3.2 3.2L13 5" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round" />
    </svg>
  );
}

export function CopyButton({
  value,
  ariaLabel,
  "aria-label": ariaLabelAttribute,
}: CopyButtonProps) {
  const [copied, setCopied] = useState(false);
  // Without a caller-supplied label the glyph would leave the button with no
  // accessible name at all, so fall back to something usable rather than
  // nothing — most call sites copy a single obvious value.
  const label = ariaLabel ?? ariaLabelAttribute ?? "Copy to clipboard";
  const timer = useRef<ReturnType<typeof setTimeout> | null>(null);

  // Clear the reset timer on unmount: rows unmount on refresh/pagination, and
  // a pending setCopied would land on a dead component.
  useEffect(() => {
    return () => {
      if (timer.current !== null) clearTimeout(timer.current);
    };
  }, []);

  function handleClick() {
    navigator.clipboard
      .writeText(value)
      .then(() => {
        setCopied(true);
        if (timer.current !== null) clearTimeout(timer.current);
        timer.current = setTimeout(() => setCopied(false), 1200);
      })
      .catch(() => {
        // Copy can fail (denied permission / insecure context); leave the
        // control unchanged rather than falsely reporting success.
      });
  }

  return (
    <button
      type="button"
      className={copied ? "btn-icon copied" : "btn-icon"}
      onClick={handleClick}
      // The name carries the state as well as the identity: with a copy
      // control beside every address and hash, a bare "Copied" would leave a
      // screen-reader user unable to tell WHICH one they copied.
      aria-label={copied ? `${label} (copied)` : label}
      title={copied ? `${label} (copied)` : label}
    >
      {copied ? <CheckGlyph /> : <CopyGlyph />}
      {/* A changed accessible name on an already-focused control is not
          reliably announced, so success also goes through a live region. It is
          rendered ONLY while copied, so the document never holds a crowd of
          empty status nodes competing to be "the" status. */}
      {copied && (
        <span className="sr-only" role="status">
          {label} copied
        </span>
      )}
    </button>
  );
}
