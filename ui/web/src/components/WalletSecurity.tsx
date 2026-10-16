import type { WalletType } from "../api/types";
import { Icon } from "./Icon";

const labels: Record<WalletType, { title: string; detail: string }> = {
  full: { title: "Password protected", detail: "Your spending password unlocks signing." },
  hardware: { title: "Hardware secured", detail: "Transactions are signed on your hardware wallet." },
  read_only: { title: "Watch-only", detail: "View balances and receive funds." },
  multi_signature: { title: "Shared wallet", detail: "Spending requires your signing policy." },
};

export function WalletSecurity({ type, detail = false }: { type: WalletType; detail?: boolean }) {
  const label = labels[type];
  return <span className="wallet-security" data-custody={type}><Icon name={type === "hardware" ? "hardware" : "shield"} size={15} /><span><strong>{label.title}</strong>{detail && <small>{label.detail}</small>}</span></span>;
}
