import type { AssetInfo } from "./api/types";

/**
 * Best-effort display metadata for a native asset, extracted from its
 * on-chain metadata (AssetInfo.onchain_metadata, from GET /wallet/assets/{unit}).
 * All fields are optional: most assets have none today (dingo does not yet
 * index on-chain asset metadata), and there is no single fixed schema even
 * when it is present (CIP-25 targets NFTs; fungible-token conventions vary).
 */
export interface AssetDisplayMeta {
  name?: string;
  ticker?: string;
  decimals?: number;
}

/**
 * Reads a handful of commonly-used on-chain-metadata keys defensively:
 * "name", "ticker" (or "symbol"), and "decimals" (number or numeric string).
 * Anything missing, null, or the wrong shape is silently ignored — a
 * malformed or absent metadata object must never break the Portfolio screen,
 * it just yields {} and callers fall back to the raw unit/quantity.
 */
export function extractAssetMeta(info: AssetInfo | undefined): AssetDisplayMeta {
  const meta = info?.onchain_metadata;
  if (!meta || typeof meta !== "object") return {};

  const result: AssetDisplayMeta = {};

  const name = meta.name;
  if (typeof name === "string" && name.trim() !== "") {
    result.name = name.trim();
  }

  for (const ticker of [meta.ticker, meta.symbol]) {
    if (typeof ticker === "string" && ticker.trim() !== "") {
      result.ticker = ticker.trim();
      break;
    }
  }

  const decimalsRaw = meta.decimals;
  if (typeof decimalsRaw === "number" && Number.isInteger(decimalsRaw) && decimalsRaw >= 0) {
    result.decimals = decimalsRaw;
  } else if (typeof decimalsRaw === "string" && /^\d+$/.test(decimalsRaw)) {
    result.decimals = parseInt(decimalsRaw, 10);
  }

  return result;
}

/** Display label for a native asset: metadata name, else ticker, else the raw unit (policy id + hex asset name). */
export function assetDisplayName(unit: string, meta: AssetDisplayMeta): string {
  return meta.name || meta.ticker || unit;
}

/**
 * Whether a native asset row matches a search query: a case-insensitive
 * substring match against its display name, ticker, and raw unit (which
 * already covers the policy ID, since unit = policy ID + hex asset name —
 * any substring match against the policy ID alone is also a substring match
 * against unit). An empty/whitespace-only query matches everything.
 */
export function assetMatchesQuery(unit: string, meta: AssetDisplayMeta, query: string): boolean {
  const q = query.trim().toLowerCase();
  if (q === "") return true;

  const haystacks = [unit, meta.name, meta.ticker].filter(
    (s): s is string => typeof s === "string" && s.length > 0,
  );
  return haystacks.some((s) => s.toLowerCase().includes(q));
}
