import { extractAssetMeta, assetDisplayName, assetMatchesQuery } from "./tokenMeta";
import type { AssetInfo } from "./api/types";
import { formatTokenQuantity } from "./format";

function makeInfo(onchainMetadata: unknown, registryMetadata: unknown = null): AssetInfo {
  return {
    asset: "policy123746f6b656e",
    policy_id: "policy123",
    asset_name: "746f6b656e",
    asset_name_ascii: "token",
    fingerprint: "asset1xyz",
    quantity: "1000000",
    onchain_metadata: onchainMetadata as AssetInfo["onchain_metadata"],
    metadata: registryMetadata as AssetInfo["metadata"],
  };
}

// --- extractAssetMeta ---

test("extractAssetMeta: reads name/ticker/decimals when present", () => {
  const info = makeInfo({ name: "Token", ticker: "TOK", decimals: 6 });
  expect(extractAssetMeta(info)).toEqual({ name: "Token", ticker: "TOK", decimals: 6 });
});

test("extractAssetMeta: falls back to symbol when ticker absent", () => {
  const info = makeInfo({ name: "Token", symbol: "TOK" });
  expect(extractAssetMeta(info)).toEqual({ name: "Token", ticker: "TOK" });
});

test("extractAssetMeta: falls back to symbol when ticker is empty", () => {
  const info = makeInfo({ ticker: "  ", symbol: "TOK" });
  expect(extractAssetMeta(info)).toEqual({ ticker: "TOK" });
});

test("extractAssetMeta: returns {} when onchain_metadata is null (dingo's current default)", () => {
  expect(extractAssetMeta(makeInfo(null))).toEqual({});
});

test("extractAssetMeta: returns {} when info is undefined (lookup not yet resolved / failed)", () => {
  expect(extractAssetMeta(undefined)).toEqual({});
});

test("extractAssetMeta: ignores malformed fields (wrong types)", () => {
  const info = makeInfo({ name: 123, ticker: [], decimals: "not-a-number" });
  expect(extractAssetMeta(info)).toEqual({});
});

test("extractAssetMeta: accepts a numeric-string decimals", () => {
  const info = makeInfo({ decimals: "6" });
  expect(extractAssetMeta(info)).toEqual({ decimals: 6 });
});

test("extractAssetMeta: trims whitespace-only name/ticker to absent", () => {
  const info = makeInfo({ name: "   ", ticker: "  " });
  expect(extractAssetMeta(info)).toEqual({});
});

test("extractAssetMeta: rejects a negative decimals value", () => {
  const info = makeInfo({ decimals: -1 });
  expect(extractAssetMeta(info)).toEqual({});
});

// --- assetDisplayName ---

test("assetDisplayName: prefers name, then ticker, then raw unit", () => {
  expect(assetDisplayName("unit1", { name: "Token" })).toBe("Token");
  expect(assetDisplayName("unit1", { ticker: "TOK" })).toBe("TOK");
  expect(assetDisplayName("unit1", {})).toBe("unit1");
});

// --- assetMatchesQuery ---

test("assetMatchesQuery: empty/whitespace query matches everything", () => {
  expect(assetMatchesQuery("unit1", {}, "")).toBe(true);
  expect(assetMatchesQuery("unit1", {}, "   ")).toBe(true);
});

test("assetMatchesQuery: matches by name (case-insensitive)", () => {
  expect(assetMatchesQuery("unit1", { name: "SpaceCoin" }, "space")).toBe(true);
  expect(assetMatchesQuery("unit1", { name: "SpaceCoin" }, "moon")).toBe(false);
});

test("assetMatchesQuery: matches by ticker", () => {
  expect(assetMatchesQuery("unit1", { ticker: "SPC" }, "spc")).toBe(true);
});

test("assetMatchesQuery: matches by policy id", () => {
  const policy = "b".repeat(56);
  const unit = policy + "746f6b656e";
  expect(assetMatchesQuery(unit, {}, policy.slice(0, 10))).toBe(true);
});

test("assetMatchesQuery: matches by raw unit substring when there is no metadata", () => {
  expect(assetMatchesQuery("lovelace_unit.TokenA", {}, "tokena")).toBe(true);
});

test("assetMatchesQuery: no match returns false", () => {
  expect(assetMatchesQuery("unit1", { name: "Token" }, "nomatch")).toBe(false);
});

// --- CIP-26 off-chain token-registry metadata (AssetInfo.metadata) ---
//
// The node serves the curated registry entry in `metadata` alongside the
// minter's self-declared `onchain_metadata`. The registry is the source of
// truth for fungible-token ticker/decimals, so it wins where both declare a
// value — getting decimals wrong misstates the holder's balance.

test("extractAssetMeta: reads name/ticker/decimals from the registry metadata", () => {
  const info = makeInfo(null, { name: "Registry Token", ticker: "RTK", decimals: 6 });
  expect(extractAssetMeta(info)).toEqual({ name: "Registry Token", ticker: "RTK", decimals: 6 });
});

test("extractAssetMeta: registry metadata wins over on-chain for name/ticker/decimals", () => {
  const info = makeInfo(
    { name: "Minter Name", ticker: "BAD", decimals: 0 },
    { name: "Curated Name", ticker: "GOOD", decimals: 6 },
  );
  expect(extractAssetMeta(info)).toEqual({ name: "Curated Name", ticker: "GOOD", decimals: 6 });
});

test("extractAssetMeta: honours a registry decimals of 0 (a real declaration)", () => {
  const info = makeInfo({ decimals: 8 }, { decimals: 0 });
  expect(extractAssetMeta(info).decimals).toBe(0);
});

test("extractAssetMeta: falls back to on-chain when registry metadata is null", () => {
  const info = makeInfo({ name: "Token", ticker: "TOK", decimals: 2 }, null);
  expect(extractAssetMeta(info)).toEqual({ name: "Token", ticker: "TOK", decimals: 2 });
});

test("extractAssetMeta: ignores a malformed registry metadata object", () => {
  const info = makeInfo({ name: "Token" }, { name: 42, ticker: {}, decimals: "six" });
  expect(extractAssetMeta(info)).toEqual({ name: "Token" });
});

// Registry entries are third-party data: the node serves whatever the registry
// published. A decimals value no token could have must not displace a good one,
// because the merge lets the registry win per field — and the formatter, seeing
// a scale it cannot use, falls back to the raw base-unit count, so a wild
// registry value turns a correctly-scaled balance into a bare integer.
test("an out-of-range registry decimals does not displace the on-chain value", () => {
  const info = makeInfo({ decimals: 6 }, { decimals: Number.MAX_SAFE_INTEGER });
  expect(extractAssetMeta(info).decimals).toBe(6);
});

test("an out-of-range decimals string does not displace the on-chain value", () => {
  const info = makeInfo({ decimals: 6 }, { decimals: "9007199254740993" });
  expect(extractAssetMeta(info).decimals).toBe(6);
});

test("decimals beyond what a quantity can be scaled by are ignored", () => {
  expect(extractAssetMeta(makeInfo({ decimals: 19 })).decimals).toBeUndefined();
  expect(extractAssetMeta(makeInfo({ decimals: 18 })).decimals).toBe(18);
});

// The scale a reader accepts has to be one the formatter can actually apply;
// otherwise the balance silently degrades to a raw count.
test("every accepted decimals value formats as a scaled quantity", () => {
  for (const decimals of [0, 1, 6, 18]) {
    const meta = extractAssetMeta(makeInfo({ decimals }));
    expect(meta.decimals).toBe(decimals);
    expect(formatTokenQuantity("1000000000000000000000", meta.decimals ?? 0)).toContain(",");
  }
});
