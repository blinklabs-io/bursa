// Public block-explorer link building.
//
// This module only builds URL strings — it never performs a network request.
// The wallet's no-background-network-call boundary is preserved because the
// resulting URL is only ever used as the `href` of a plain
// `<a target="_blank" rel="noopener noreferrer">` that the user must click
// (see components/ExplorerLink.tsx); the wallet process itself never fetches
// it, and clicking opens the explorer in the user's own browser, outside the
// wallet.
//
// Explorer of choice: cardanoscan.io. It publishes a dedicated subdomain per
// Cardano network (mainnet / preprod / preview) with an identical path
// structure across all three, so the mapping below is a simple lookup.

export type ExplorerKind = "tx" | "address" | "pool" | "drep";

const HOSTS: Record<string, string> = {
  mainnet: "cardanoscan.io",
  preprod: "preprod.cardanoscan.io",
  preview: "preview.cardanoscan.io",
};

const PATHS: Record<ExplorerKind, string> = {
  tx: "transaction",
  address: "address",
  pool: "pool",
  drep: "drep",
};

/**
 * Build the public cardanoscan.io URL for a given network/kind/id.
 *
 * An unrecognized network string falls back to the mainnet host rather than
 * throwing — callers pass through whatever network string the server reports
 * for a wallet, and a broken/unknown value should still produce a usable (if
 * possibly wrong-network) link rather than crash the screen.
 */
export function explorerUrl(network: string, kind: ExplorerKind, id: string): string {
  const host = HOSTS[network] ?? HOSTS.mainnet;
  return `https://${host}/${PATHS[kind]}/${encodeURIComponent(id)}`;
}
