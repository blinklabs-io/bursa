import { useState } from "react";
import type { Account } from "../api/types";
import { Card } from "../components/Card";
import { Tabs } from "../components/Tabs";
import type { TabDef } from "../components/Tabs";
import { Credentials } from "./operate/Credentials";
import { OperationalCert } from "./operate/OperationalCert";
import { Registration } from "./operate/Registration";
import { Retirement } from "./operate/Retirement";
import { MetadataBuilder } from "./operate/MetadataBuilder";

interface OperateProps {
  account: Account;
}

type Tab = "credentials" | "opcert" | "registration" | "retirement" | "metadata";

const TABS: readonly TabDef<Tab>[] = [
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
      </Card>

      <Tabs id="operate" tabs={TABS} active={tab} onSelect={setTab}>
        {(key) => renderPanel(key)}
      </Tabs>
    </div>
  );
}
