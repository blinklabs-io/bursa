import { useState } from "react";
import { QRCodeSVG } from "qrcode.react";
import { useAddresses } from "../api/hooks";
import { Card } from "../components/Card";
import { Table } from "../components/Table";
import { CopyButton } from "../components/CopyButton";
import { ExplorerLink } from "../components/ExplorerLink";

interface ReceiveProps {
  // Optional so existing no-prop callers/tests keep working; the app always
  // passes the active wallet's real network when routing to this screen.
  network?: string;
}

/** Truncate a long bech32 address for display: first 12 … last 8 chars. */
function truncateAddr(addr: string): string {
  if (addr.length <= 24) return addr;
  return addr.slice(0, 12) + "…" + addr.slice(-8);
}

// QR codes are rendered entirely client-side (bundled `qrcode.react`, no
// network round-trip) into an inline SVG. A high, near-white/near-black
// contrast pair is used regardless of the surrounding dark theme so the code
// stays reliably scannable by phone cameras.
const QR_BG = "#ffffff";
const QR_FG = "#0c0f15";
const QR_SIZE_HERO = 176;
const QR_SIZE_ROW = 112;

/** A QR code framed in a light chip so it stays scannable on the dark panel. */
function AddressQR({ address, size, title }: { address: string; size: number; title: string }) {
  return (
    <div className="receive-qr-frame">
      <QRCodeSVG value={address} size={size} bgColor={QR_BG} fgColor={QR_FG} level="M" marginSize={2} title={title} />
    </div>
  );
}

export function Receive({ network = "preview" }: ReceiveProps = {}) {
  const addresses = useAddresses();
  const [expandedQr, setExpandedQr] = useState<string | null>(null);

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
    { key: "qr", label: "QR" },
    { key: "copy", label: "" },
  ];

  const rows = receive.map((addr) => {
    const isExpanded = expandedQr === addr;
    return {
      address: truncateAddr(addr),
      status: usedSet.has(addr) ? "Used" : "Unused",
      qr: (
        <div className="receive-qr-cell">
          <button
            type="button"
            className="btn ghost"
            aria-expanded={isExpanded}
            aria-label={`${isExpanded ? "Hide" : "Show"} QR code for ${addr}`}
            onClick={() => setExpandedQr(isExpanded ? null : addr)}
          >
            {isExpanded ? "Hide QR" : "QR"}
          </button>
          {isExpanded && (
            <AddressQR address={addr} size={QR_SIZE_ROW} title={`QR code for ${addr}`} />
          )}
        </div>
      ),
      copy: (
        <>
          <CopyButton value={addr} />
          <ExplorerLink
            network={network}
            kind="address"
            id={addr}
            label={`View address ${truncateAddr(addr)} on block explorer`}
          />
        </>
      ),
    };
  });

  return (
    <div className="receive">
      <Card title="Next Unused Address">
        <div className="receive-next">
          {nextUnused && (
            <AddressQR address={nextUnused} size={QR_SIZE_HERO} title={`QR code for ${nextUnused}`} />
          )}
          <div className="receive-next-details">
            <p className="mono address-full">{nextUnused}</p>
            <CopyButton value={nextUnused} />
            {nextUnused && <ExplorerLink network={network} kind="address" id={nextUnused} />}
          </div>
        </div>
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
