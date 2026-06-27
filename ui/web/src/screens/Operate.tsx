import { useRef } from "react";
import { useState } from "react";
import type { KeyboardEvent } from "react";
import type { Account } from "../api/types";
import { Card } from "../components/Card";
import { Credentials } from "./operate/Credentials";
import { OperationalCert } from "./operate/OperationalCert";
import { Registration } from "./operate/Registration";
import { Retirement } from "./operate/Retirement";
import { MetadataBuilder } from "./operate/MetadataBuilder";

interface OperateProps {
  account: Account;
}

type Tab = "credentials" | "opcert" | "registration" | "retirement" | "metadata";

const TABS: { key: Tab; label: string }[] = [
  { key: "credentials", label: "Credentials" },
  { key: "opcert", label: "Operational cert" },
  { key: "registration", label: "Registration" },
  { key: "retirement", label: "Retirement" },
  { key: "metadata", label: "Metadata" },
];

// Operate is the Stake Pool Operations (SPO) toolkit: generate cold/VRF/KES
// credentials, issue/rotate operational certificates, build pool
// registration/update/retirement certificates, and build hostable pool
// metadata. Each tab maps to a backend /wallet/pool/… endpoint and operates on
// the active wallet (spending operations require the spend password).
export function Operate({ account }: OperateProps) {
  const [tab, setTab] = useState<Tab>("credentials");
  const tabRefs = useRef<(HTMLButtonElement | null)[]>([]);

  function handleKeyDown(e: KeyboardEvent<HTMLButtonElement>, idx: number) {
    let next = idx;
    if (e.key === "ArrowRight") {
      next = (idx + 1) % TABS.length;
    } else if (e.key === "ArrowLeft") {
      next = (idx - 1 + TABS.length) % TABS.length;
    } else {
      return;
    }
    e.preventDefault();
    setTab(TABS[next].key);
    tabRefs.current[next]?.focus();
  }

  function renderPanel(key: Tab) {
    switch (key) {
      case "credentials":
        return <Credentials />;
      case "opcert":
        return <OperationalCert />;
      case "registration":
        return <Registration account={account} />;
      case "retirement":
        return <Retirement />;
      case "metadata":
        return <MetadataBuilder />;
    }
  }

  return (
    <div className="operate">
      <Card title="Stake Pool Operations">
        <p className="helper-text">
          Operate a stake pool from this wallet&rsquo;s seed, or air-gap the cold
          key. All data comes from your own node — nothing is fetched externally.
        </p>
        <div className="operate-tabs" role="tablist">
          {TABS.map(({ key, label }, idx) => (
            <button
              key={key}
              ref={(el) => { tabRefs.current[idx] = el; }}
              role="tab"
              id={`operate-tab-${key}`}
              aria-selected={tab === key}
              aria-controls={`operate-panel-${key}`}
              tabIndex={tab === key ? 0 : -1}
              className={tab === key ? "operate-tab active" : "operate-tab"}
              onClick={() => setTab(key)}
              onKeyDown={(e) => handleKeyDown(e, idx)}
            >
              {label}
            </button>
          ))}
        </div>
      </Card>

      {TABS.map(({ key }) => (
        <div
          key={key}
          role="tabpanel"
          id={`operate-panel-${key}`}
          aria-labelledby={`operate-tab-${key}`}
          hidden={tab !== key}
        >
          {tab === key ? renderPanel(key) : null}
        </div>
      ))}
    </div>
  );
}
