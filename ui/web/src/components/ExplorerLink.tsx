import type { MouseEvent } from "react";
import { explorerUrl } from "../explorer";
import type { ExplorerKind } from "../explorer";

interface ExplorerLinkProps {
  network: string;
  kind: ExplorerKind;
  id: string;
  /** Accessible name; defaults to a generic, clearly-external label. */
  label?: string;
}

/**
 * A clearly-labeled affordance ("↗") linking out to a PUBLIC block explorer.
 *
 * This is user-initiated navigation only: the wallet never fetches this URL
 * itself — nothing happens until the user clicks, at which point their own
 * browser opens the explorer in a new tab/window. `rel="noopener noreferrer"`
 * prevents a new tab from getting a `window.opener` handle back into the
 * wallet, and the title/aria-label make the "leaves the wallet" boundary
 * explicit rather than looking like an in-app link.
 *
 * The desktop build embeds a webview (see `ui/cmd/bursa-wallet/ui_webview.go`)
 * rather than a real browser tab-strip: a plain `target="_blank"` there would
 * NAVIGATE the wallet window itself to the explorer, turning it into a
 * general-purpose browser. To prevent that, the click handler always
 * `preventDefault()`s the anchor's own navigation and instead opens the URL
 * externally — through the webview-injected `window.bursaOpenExternal`
 * bridge when present, or `window.open` (a real new tab) otherwise. The
 * `href`/`target`/`rel` attributes are kept for accessibility, hover
 * previews, and "open in new tab" middle-click/ctrl-click in a real browser.
 */
export function ExplorerLink({ network, kind, id, label }: ExplorerLinkProps) {
  const accessibleLabel = label ?? "View on public block explorer (opens in a new tab)";
  const url = explorerUrl(network, kind, id);

  function handleClick(e: MouseEvent<HTMLAnchorElement>) {
    e.preventDefault();
    if (typeof window.bursaOpenExternal === "function") {
      window.bursaOpenExternal(url);
    } else {
      window.open(url, "_blank", "noopener,noreferrer");
    }
  }

  return (
    <a
      className="explorer-link"
      href={url}
      target="_blank"
      rel="noopener noreferrer"
      title={accessibleLabel}
      aria-label={accessibleLabel}
      onClick={handleClick}
    >
      ↗
    </a>
  );
}
