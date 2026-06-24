import { useBalance, useDelegation } from "../api/hooks";
import { Card } from "../components/Card";
import { Table } from "../components/Table";
import { StatusPill } from "../components/StatusPill";
import { formatAda } from "../format";

export function Portfolio() {
  const balance = useBalance();
  const delegation = useDelegation();

  // Show a single loading state if either hook is still loading.
  if (balance.loading || delegation.loading) {
    return <p>Loading…</p>;
  }

  // Show the first error encountered (balance errors take priority).
  if (balance.error) {
    return <p role="alert" className="error-text">{balance.error.message}</p>;
  }
  if (delegation.error) {
    return <p role="alert" className="error-text">{delegation.error.message}</p>;
  }

  const bal = balance.data;
  const del = delegation.data;

  // A fresh wallet returns zeros/empty — treat it as valid, not an error.
  const lovelace = bal?.lovelace ?? "0";
  const assets = bal?.assets ?? [];

  const tokenColumns = [
    { key: "unit", label: "Unit" },
    { key: "quantity", label: "Quantity" },
  ];
  const tokenRows = assets.map((a) => ({ unit: a.unit, quantity: a.quantity }));

  return (
    <div className="portfolio">
      <Card title="Balance">
        <p className="balance-ada">{formatAda(lovelace)} ADA</p>
      </Card>

      <Card title="Native Tokens">
        {assets.length === 0 ? (
          <p className="muted">No native tokens</p>
        ) : (
          <Table columns={tokenColumns} rows={tokenRows} />
        )}
      </Card>

      <Card title="Delegation">
        {del ? (
          <dl className="delegation-details">
            <div className="dl-row">
              <dt>Pool</dt>
              <dd>{del.pool_id ?? <span className="muted">Not delegated</span>}</dd>
            </div>

            <div className="dl-row">
              <dt>Status</dt>
              <dd>
                <StatusPill tone={del.active ? "ok" : "muted"}>
                  {del.active ? "Active" : "Inactive"}
                </StatusPill>
              </dd>
            </div>

            <div className="dl-row">
              <dt>Rewards</dt>
              <dd>{formatAda(del.rewards_sum)} ADA</dd>
            </div>

            <div className="dl-row">
              <dt>Withdrawable</dt>
              <dd>{formatAda(del.withdrawable_amount)} ADA</dd>
            </div>

            {del.provisional && (
              <div className="dl-row provisional-notice">
                <dt>
                  <StatusPill tone="warn">Provisional</StatusPill>
                </dt>
                <dd className="muted">{del.note}</dd>
              </div>
            )}
          </dl>
        ) : (
          <p className="muted">Not delegated</p>
        )}
      </Card>
    </div>
  );
}
