import { useRef } from "react";
import type { KeyboardEvent, ReactNode } from "react";

export interface TabDef<K extends string> {
  key: K;
  label: string;
}

interface TabsProps<K extends string> {
  // Namespace for the generated tab/panel ids, so two tab sets can coexist on
  // one page without colliding.
  id: string;
  tabs: readonly TabDef<K>[];
  active: K;
  onSelect: (key: K) => void;
  // Renders the panel body for a key. Only the active panel is rendered; the
  // others stay in the DOM as empty hidden containers so the tab/panel ARIA
  // relationship is never dangling.
  children: (key: K) => ReactNode;
}

/**
 * An ARIA tablist with roving tabindex and arrow-key navigation.
 *
 * Extracted from the SPO Operate screen, which had the only correct
 * implementation in the app, so that Stake (and anything else that groups
 * related views) doesn't reimplement the keyboard and ARIA wiring.
 */
export function Tabs<K extends string>({
  id,
  tabs,
  active,
  onSelect,
  children,
}: TabsProps<K>) {
  const tabRefs = useRef<(HTMLButtonElement | null)[]>([]);

  function handleKeyDown(e: KeyboardEvent<HTMLButtonElement>, idx: number) {
    let next = idx;
    if (e.key === "ArrowRight") {
      next = (idx + 1) % tabs.length;
    } else if (e.key === "ArrowLeft") {
      next = (idx - 1 + tabs.length) % tabs.length;
    } else if (e.key === "Home") {
      next = 0;
    } else if (e.key === "End") {
      next = tabs.length - 1;
    } else {
      return;
    }
    e.preventDefault();
    onSelect(tabs[next].key);
    tabRefs.current[next]?.focus();
  }

  return (
    <>
      <div className="tabset" role="tablist">
        {tabs.map(({ key, label }, idx) => (
          <button
            key={key}
            ref={(el) => {
              tabRefs.current[idx] = el;
            }}
            type="button"
            role="tab"
            id={`${id}-tab-${key}`}
            aria-selected={active === key}
            aria-controls={`${id}-panel-${key}`}
            tabIndex={active === key ? 0 : -1}
            className={active === key ? "tabset-tab active" : "tabset-tab"}
            onClick={() => onSelect(key)}
            onKeyDown={(e) => handleKeyDown(e, idx)}
          >
            {label}
          </button>
        ))}
      </div>

      {tabs.map(({ key }) => (
        <div
          key={key}
          role="tabpanel"
          id={`${id}-panel-${key}`}
          aria-labelledby={`${id}-tab-${key}`}
          hidden={active !== key}
        >
          {active === key ? children(key) : null}
        </div>
      ))}
    </>
  );
}
