import { useState } from "react";
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

  return (
    <div className="operate">
      <Card title="Stake Pool Operations">
        <p className="helper-text">
          Operate a stake pool from this wallet&rsquo;s seed, or air-gap the cold
          key. All data comes from your own node — nothing is fetched externally.
        </p>
        <div className="operate-tabs" role="tablist">
          {TABS.map(({ key, label }) => (
            <button
              key={key}
              role="tab"
              aria-selected={tab === key}
              className={tab === key ? "operate-tab active" : "operate-tab"}
              onClick={() => setTab(key)}
            >
              {label}
            </button>
          ))}
        </div>
      </Card>

      {tab === "credentials" && <Credentials />}
      {tab === "opcert" && <OperationalCert />}
      {tab === "registration" && <Registration account={account} />}
      {tab === "retirement" && <Retirement />}
      {tab === "metadata" && <MetadataBuilder />}
    </div>
  );
}
