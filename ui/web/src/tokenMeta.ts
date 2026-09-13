import type { AssetInfo } from "./api/types";
import { MAX_TOKEN_DECIMALS } from "./format";

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
 * Reads a handful of commonly-used metadata keys defensively: "name",
 * "ticker" (or "symbol"), and "decimals" (number or numeric string).
 * Anything missing, null, or the wrong shape is silently ignored.
 */
function readDisplayKeys(meta: unknown): AssetDisplayMeta {
  if (!meta || typeof meta !== "object") return {};
  const source = meta as Record<string, unknown>;

  const result: AssetDisplayMeta = {};

  const name = source.name;
  if (typeof name === "string" && name.trim() !== "") {
    result.name = name.trim();
  }

  for (const ticker of [source.ticker, source.symbol]) {
    if (typeof ticker === "string" && ticker.trim() !== "") {
      result.ticker = ticker.trim();
      break;
    }
  }

  // Registry entries are third-party data, and the merge below lets the
  // registry win per field — so a decimals value no token could have would
  // displace a good on-chain one, and the formatter, handed a scale it cannot
  // use, falls back to the raw base-unit count. Accepting only what the
  // formatter accepts keeps a wild value from costing us a correct one.
  const decimalsRaw = source.decimals;
  const decimals =
    typeof decimalsRaw === "number"
      ? decimalsRaw
      : typeof decimalsRaw === "string" && /^\d+$/.test(decimalsRaw)
        ? Number(decimalsRaw)
        : NaN;
  if (Number.isInteger(decimals) && decimals >= 0 && decimals <= MAX_TOKEN_DECIMALS) {
    result.decimals = decimals;
  }

  return result;
}

/**
 * Display metadata for a native asset, merged from the two sources the node
 * serves for it:
 *
 *   - `onchain_metadata` — the minter's own CIP-25/68 declaration.
 *   - `metadata` — the curated CIP-26 off-chain token-registry entry.
 *
 * Merged per field, with the registry winning where both declare a value: the
 * registry is reviewed, whereas on-chain metadata is whatever the minter wrote.
 * That matters most for `decimals`, since a wrong value misstates the holder's
 * balance. Per-field (rather than whole-object) precedence means a registry
 * entry that declares only a ticker still keeps the on-chain name.
 *
 * Either source being absent, null, or malformed is normal — most assets have
 * neither, and the node's registry sync is opt-in — so this yields {} and
 * callers fall back to the raw unit/quantity.
 */
export function extractAssetMeta(info: AssetInfo | undefined): AssetDisplayMeta {
  return {
    ...readDisplayKeys(info?.onchain_metadata),
    ...readDisplayKeys(info?.metadata),
  };
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
