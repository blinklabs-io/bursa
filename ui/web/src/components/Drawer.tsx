import { ReactNode, useEffect, useRef } from "react";

interface DrawerProps {
  title: string;
  onClose: () => void;
  children?: ReactNode;
}

// Matches the elements a keyboard user can land on. Kept intentionally
// simple (no visibility/offsetParent check, which jsdom can't compute
// anyway) since drawer content is never conditionally hidden in place.
const FOCUSABLE_SELECTOR =
  'a[href], button:not([disabled]), textarea:not([disabled]), input:not([disabled]), select:not([disabled]), [tabindex]:not([tabindex="-1"])';

/**
 * A slide-in side panel for a drill-down view (e.g. transaction detail),
 * layered over the current screen. Closes on Escape, on clicking the
 * backdrop, or via the close button.
 *
 * Manages focus like a modal: moves focus into the drawer on open, traps Tab
 * navigation within it so the background UI can't be reached, and restores
 * focus to whatever triggered the drawer once it closes.
 */
export function Drawer({ title, onClose, children }: DrawerProps) {
  const drawerRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    const previouslyFocused = document.activeElement as HTMLElement | null;
    const drawer = drawerRef.current;
    const firstFocusable = drawer?.querySelector<HTMLElement>(FOCUSABLE_SELECTOR);
    (firstFocusable ?? drawer)?.focus();

    function handleKeyDown(e: KeyboardEvent) {
      if (e.key === "Escape") {
        onClose();
        return;
      }
      if (e.key !== "Tab" || !drawerRef.current) return;
      const focusable = Array.from(
        drawerRef.current.querySelectorAll<HTMLElement>(FOCUSABLE_SELECTOR),
      );
      if (focusable.length === 0) return;
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
    document.addEventListener("keydown", handleKeyDown);
    return () => {
      document.removeEventListener("keydown", handleKeyDown);
      previouslyFocused?.focus();
    };
  }, [onClose]);

  return (
    <div className="drawer-overlay" onClick={onClose}>
      <div
        className="drawer"
        role="dialog"
        aria-modal="true"
        aria-label={title}
        ref={drawerRef}
        tabIndex={-1}
        onClick={(e) => e.stopPropagation()}
      >
        <div className="drawer-header">
          <span className="drawer-title">{title}</span>
          <button type="button" className="drawer-close" onClick={onClose} aria-label="Close">
            Close
          </button>
        </div>
        {children}
      </div>
    </div>
  );
}
