import { useAddresses } from "../api/hooks";
import { Card } from "../components/Card";
import { Table } from "../components/Table";
import { CopyButton } from "../components/CopyButton";

/** Truncate a long bech32 address for display: first 12 … last 8 chars. */
function truncateAddr(addr: string): string {
  if (addr.length <= 24) return addr;
  return addr.slice(0, 12) + "…" + addr.slice(-8);
}

export function Receive() {
  const addresses = useAddresses();

  if (addresses.loading) {
    return <p>Loading…</p>;
  }

  if (addresses.error) {
    return (
      <p role="alert" className="error-text">
        {addresses.error.message}
      </p>
    );
  }

  const data = addresses.data;
  const nextUnused = data?.next_unused ?? "";
  const receive = data?.receive ?? [];
  const usedSet = new Set(data?.used ?? []);

  const columns = [
    { key: "address", label: "Address" },
    { key: "status", label: "Status" },
    { key: "copy", label: "" },
  ];

  const rows = receive.map((addr) => ({
    address: truncateAddr(addr),
    status: usedSet.has(addr) ? "Used" : "Unused",
    copy: <CopyButton value={addr} />,
  }));

  return (
    <div className="receive">
      <Card title="Next Unused Address">
        <p className="mono address-full">{nextUnused}</p>
        <CopyButton value={nextUnused} />
      </Card>

      <Card title="Receive Addresses">
        {receive.length === 0 ? (
          <p className="muted">No addresses available</p>
        ) : (
          <Table columns={columns} rows={rows} />
        )}
      </Card>
    </div>
  );
}
