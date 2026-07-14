import { extractAssetMeta, assetDisplayName, assetMatchesQuery } from "./tokenMeta";
import type { AssetInfo } from "./api/types";

function makeInfo(onchainMetadata: unknown): AssetInfo {
  return {
    asset: "policy123746f6b656e",
    policy_id: "policy123",
    asset_name: "746f6b656e",
    asset_name_ascii: "token",
    fingerprint: "asset1xyz",
    quantity: "1000000",
    onchain_metadata: onchainMetadata as AssetInfo["onchain_metadata"],
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
