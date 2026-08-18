import { useEffect, useMemo, useRef, useState } from "react";

export interface Command {
  id: string;
  label: string;
  // Grouping shown beside the label, so "Sign" reads as a Tools action rather
  // than an ambiguous verb.
  group: string;
  // Extra words to match on that are not in the label — the terms someone
  // would actually type looking for this.
  keywords?: string;
  disabled?: boolean;
  // Why it is unavailable, shown in place of the command rather than leaving
  // the user to guess.
  disabledReason?: string;
  run: () => void;
}

interface CommandPaletteProps {
  open: boolean;
  commands: Command[];
  onClose: () => void;
}

function matches(cmd: Command, needle: string): boolean {
  if (!needle) return true;
  const haystack = `${cmd.label} ${cmd.group} ${cmd.keywords ?? ""}`.toLowerCase();
  // Every term must appear somewhere, so "gov vote" finds a governance vote
  // without demanding the words be adjacent or in order.
  return needle
    .toLowerCase()
    .split(/\s+/)
    .filter(Boolean)
    .every((term) => haystack.includes(term));
}

/**
 * A searchable list of everything the wallet can do.
 *
 * The nav carries the handful of places you go; this carries the long tail of
 * things you do — signing a message, going air-gapped, finishing someone else's
 * transaction. It is deliberately not the only way to reach any of them: a
 * palette is invisible to anyone who does not already know it exists, so every
 * command here is also reachable by pointing and clicking somewhere.
 */
export function CommandPalette({ open, commands, onClose }: CommandPaletteProps) {
  const [query, setQuery] = useState("");
  const [cursor, setCursor] = useState(0);
  const inputRef = useRef<HTMLInputElement>(null);
  const listRef = useRef<HTMLUListElement>(null);
  const dialogRef = useRef<HTMLDivElement>(null);
  // Whatever had focus before, so closing returns the user where they were
  // rather than dropping focus at the top of the document.
  const restoreFocusTo = useRef<HTMLElement | null>(null);

  const results = useMemo(
    () => commands.filter((c) => matches(c, query.trim())),
    [commands, query],
  );

  // Reopening should feel like a fresh start, not a resumed session.
  useEffect(() => {
    if (!open) return;
    restoreFocusTo.current = document.activeElement as HTMLElement | null;
    setQuery("");
    setCursor(0);
    inputRef.current?.focus();
    return () => {
      // Only take focus back if it is still going begging — a command may have
      // moved it somewhere deliberately.
      const active = document.activeElement;
      if (!active || active === document.body) restoreFocusTo.current?.focus();
    };
  }, [open]);

  // A shrinking result list must not strand the cursor past the end.
  useEffect(() => {
    setCursor((c) => (c >= results.length ? 0 : c));
  }, [results.length]);

  // Keep the selection visible: arrowing past the fold would otherwise let a
  // keyboard user run a command they cannot see.
  useEffect(() => {
    const active = listRef.current?.querySelector<HTMLElement>('[aria-selected="true"]');
    // Optional chaining on the method too: not every environment implements
    // it (jsdom does not), and keeping the selection visible is a nicety that
    // must not throw where it is unavailable.
    active?.scrollIntoView?.({ block: "nearest" });
  }, [cursor, results.length]);

  useEffect(() => {
    if (!open) return;
    const previousOverflow = document.body.style.overflow;
    document.body.style.overflow = "hidden";
    return () => {
      document.body.style.overflow = previousOverflow;
    };
  }, [open]);

  if (!open) return null;

  function choose(cmd: Command) {
    if (cmd.disabled) return;
    onClose();
    cmd.run();
  }

  function handleKeyDown(e: React.KeyboardEvent) {
    if (e.key === "Escape") {
      e.preventDefault();
      onClose();
      return;
    }
    if (e.key === "ArrowDown" || e.key === "ArrowUp") {
      e.preventDefault();
      if (results.length === 0) return;
      const delta = e.key === "ArrowDown" ? 1 : -1;
      setCursor((c) => (c + delta + results.length) % results.length);
      return;
    }
    if (e.key === "Enter") {
      e.preventDefault();
      const cmd = results[cursor];
      if (cmd) choose(cmd);
      return;
    }
    if (e.key === "Tab") {
      // aria-modal tells assistive tech this is modal, but without a trap Tab
      // still walks out into the sidebar behind it and lets the user operate
      // controls the dialog is supposedly covering.
      const focusable = dialogRef.current?.querySelectorAll<HTMLElement>(
        'input, button:not([disabled]), [tabindex]:not([tabindex="-1"])',
      );
      if (!focusable || focusable.length === 0) {
        e.preventDefault();
        return;
      }
      const first = focusable[0];
      const last = focusable[focusable.length - 1];
      if (e.shiftKey && document.activeElement === first) {
        e.preventDefault();
        last.focus();
      } else if (!e.shiftKey && document.activeElement === last) {
        e.preventDefault();
        first.focus();
      }
    }
  }

  return (
    <>
      <div className="palette-overlay" aria-hidden="true" onClick={onClose} />
      <div
        ref={dialogRef}
        className="palette"
        role="dialog"
        aria-modal="true"
        aria-label="Command palette"
        onKeyDown={handleKeyDown}
      >
        <input
          ref={inputRef}
          className="palette-input"
          type="text"
          role="combobox"
          aria-expanded="true"
          aria-controls="palette-results"
          aria-activedescendant={results[cursor] ? `palette-cmd-${results[cursor].id}` : undefined}
          aria-label="Search commands"
          placeholder="Search for anything…"
          value={query}
          onChange={(e) => setQuery(e.target.value)}
        />

        {results.length === 0 ? (
          <p className="palette-empty muted">Nothing matches “{query}”.</p>
        ) : (
          <ul className="palette-results" id="palette-results" role="listbox" ref={listRef}>
            {results.map((cmd, i) => (
              <li key={cmd.id}>
                <button
                  type="button"
                  id={`palette-cmd-${cmd.id}`}
                  role="option"
                  aria-selected={i === cursor}
                  className={i === cursor ? "palette-item active" : "palette-item"}
                  disabled={cmd.disabled}
                  onMouseEnter={() => setCursor(i)}
                  onClick={() => choose(cmd)}
                >
                  <span className="palette-label">{cmd.label}</span>
                  <span className="palette-group">
                    {cmd.disabled && cmd.disabledReason ? cmd.disabledReason : cmd.group}
                  </span>
                </button>
              </li>
            ))}
          </ul>
        )}
      </div>
    </>
  );
}
