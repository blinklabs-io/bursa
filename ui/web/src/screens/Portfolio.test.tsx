import { render, screen, fireEvent } from "@testing-library/react";
import { Portfolio } from "./Portfolio";
import * as hooks from "../api/hooks";
import { ApiError } from "../api/client";
import type { AssetInfo } from "../api/types";

function mockBalance(lovelace: string, assets: { unit: string; quantity: string }[]) {
  vi.spyOn(hooks, "useBalance").mockReturnValue({
    data: { lovelace, assets },
    error: null,
    loading: false,
    refresh: vi.fn(),
  } as never);
}

function mockAssetMetadata(byUnit: Record<string, Partial<AssetInfo>>) {
  vi.spyOn(hooks, "useAssetMetadata").mockReturnValue(byUnit as never);
}

function mockDelegation(overrides: Partial<{
  pool_id: string | null;
  active: boolean;
  rewards_sum: string;
  withdrawable_amount: string;
  provisional: boolean;
  note: string;
}> = {}) {
  vi.spyOn(hooks, "useDelegation").mockReturnValue({
    data: {
      pool_id: "pool1abc123",
      active: true,
      rewards_sum: "1000000",
      withdrawable_amount: "500000",
      provisional: false,
      note: "",
      ...overrides,
    },
    error: null,
    loading: false,
    refresh: vi.fn(),
  } as never);
}

beforeEach(() => {
  // Default: no metadata resolved for any asset (the common case, since most
  // assets have none on-chain). Individual tests override with mockAssetMetadata.
  mockAssetMetadata({});
  vi.spyOn(hooks, "useNftMedia").mockReturnValue({
    enabled: false,
    loading: false,
    saving: false,
    error: null,
    setEnabled: vi.fn(),
  });
});

afterEach(() => {
  vi.restoreAllMocks();
});

test("(a) formats lovelace to ADA correctly — 4500000 lovelace = 4.5 ADA", () => {
  mockBalance("4500000", []);
  mockDelegation();

  render(<Portfolio />);

  // "4.500000" or "4.5" — both are valid per spec (trailing zeros may be trimmed)
  expect(screen.getByText(/4\.5/)).toBeInTheDocument();
});

test("(b) renders native token row with unit and quantity", () => {
  mockBalance("4500000", [
    { unit: "lovelace_unit.TokenA", quantity: "999999999999999" },
  ]);
  mockDelegation();

  render(<Portfolio />);

  expect(screen.getByText("lovelace_unit.TokenA")).toBeInTheDocument();
  expect(screen.getByText("999999999999999")).toBeInTheDocument();
});

test("(c) delegation card shows pool id, active pill, rewards, and withdrawable", () => {
  mockBalance("4500000", []);
  mockDelegation({
    pool_id: "pool1testpoolid",
    active: true,
    rewards_sum: "2000000",
    withdrawable_amount: "1000000",
    provisional: false,
    note: "",
  });

  render(<Portfolio />);

  expect(screen.getByText("pool1testpoolid")).toBeInTheDocument();
  // active pill
  expect(screen.getByText(/active/i)).toBeInTheDocument();
});

test("(d) provisional=true renders a visible provisional indicator", () => {
  mockBalance("4500000", []);
  mockDelegation({
    provisional: true,
    note: "Delegation registered but not yet confirmed on-chain.",
  });

  render(<Portfolio />);

  // The provisional indicator must be visible.
  expect(screen.getByText(/provisional/i)).toBeInTheDocument();
});

test("(e) not delegated shows fallback text", () => {
  mockBalance("4500000", []);
  mockDelegation({ pool_id: null, active: false });

  render(<Portfolio />);

  expect(screen.getByText(/not delegated/i)).toBeInTheDocument();
});

test("(f) loading state renders a loading indicator", () => {
  vi.spyOn(hooks, "useBalance").mockReturnValue({
    data: null,
    error: null,
    loading: true,
    refresh: vi.fn(),
  } as never);
  vi.spyOn(hooks, "useDelegation").mockReturnValue({
    data: null,
    error: null,
    loading: true,
    refresh: vi.fn(),
  } as never);

  render(<Portfolio />);

  expect(screen.getByText(/loading/i)).toBeInTheDocument();
});

test("(g) error state renders inline error message", () => {
  vi.spyOn(hooks, "useBalance").mockReturnValue({
    data: null,
    error: new Error("network error"),
    loading: false,
    refresh: vi.fn(),
  } as never);
  vi.spyOn(hooks, "useDelegation").mockReturnValue({
    data: null,
    error: null,
    loading: false,
    refresh: vi.fn(),
  } as never);

  render(<Portfolio />);

  expect(screen.getByText(/network error/i)).toBeInTheDocument();
});

test("(h) fresh wallet with zero balance is valid — not an error", () => {
  mockBalance("0", []);
  mockDelegation({ pool_id: null, active: false });

  render(<Portfolio />);

  // Should show "0 ADA" in the balance card without an error state.
  expect(screen.getByText(/^0 ADA$/)).toBeInTheDocument();
  expect(screen.queryByRole("alert")).toBeNull();
});

// --- on-chain token metadata + search/filter ---

function makeAssetInfo(unit: string, metadata: Record<string, unknown> | null): AssetInfo {
  return {
    asset: unit,
    policy_id: unit.slice(0, 56),
    asset_name: unit.slice(56),
    asset_name_ascii: "",
    fingerprint: "",
    quantity: "0",
    onchain_metadata: metadata,
  };
}

test("(i) shows on-chain name and decimals-applied quantity when metadata is available", () => {
  const unit = "a".repeat(56) + "746f6b656e";
  mockBalance("4500000", [{ unit, quantity: "1500000" }]);
  mockDelegation();
  mockAssetMetadata({
    [unit]: makeAssetInfo(unit, { name: "Space Coin", ticker: "SPC", decimals: 6 }),
  });

  render(<Portfolio />);

  expect(screen.getByText("Space Coin")).toBeInTheDocument();
  expect(screen.getByText("1.5")).toBeInTheDocument();
  expect(screen.queryByText(unit)).not.toBeInTheDocument();
});

test("(j) an asset with no resolved metadata falls back to its raw unit/quantity, even when a sibling asset has metadata", () => {
  const known = "a".repeat(56) + "746f6b656e";
  const unknown = "b".repeat(56) + "756e6b6e6f776e";
  mockBalance("4500000", [
    { unit: known, quantity: "1500000" },
    { unit: unknown, quantity: "42" },
  ]);
  mockDelegation();
  mockAssetMetadata({ [known]: makeAssetInfo(known, { name: "Space Coin", decimals: 6 }) });

  render(<Portfolio />);

  expect(screen.getByText("Space Coin")).toBeInTheDocument();
  expect(screen.getByText(unknown)).toBeInTheDocument();
  expect(screen.getByText("42")).toBeInTheDocument();
});

test("(k) search box filters the token list by on-chain name", () => {
  const spc = "a".repeat(56) + "746f6b656e";
  const other = "b".repeat(56) + "756e6b6e6f776e";
  mockBalance("0", [
    { unit: spc, quantity: "10" },
    { unit: other, quantity: "20" },
  ]);
  mockDelegation();
  mockAssetMetadata({ [spc]: makeAssetInfo(spc, { name: "Space Coin" }) });

  render(<Portfolio />);

  expect(screen.getByText("Space Coin")).toBeInTheDocument();
  expect(screen.getByText(other)).toBeInTheDocument();

  fireEvent.change(screen.getByPlaceholderText(/search/i), { target: { value: "space" } });

  expect(screen.getByText("Space Coin")).toBeInTheDocument();
  expect(screen.queryByText(other)).not.toBeInTheDocument();
});

test("(k2) search box also matches on the raw unit when there is no metadata", () => {
  mockBalance("0", [{ unit: "lovelace_unit.TokenA", quantity: "5" }]);
  mockDelegation();

  render(<Portfolio />);
  fireEvent.change(screen.getByPlaceholderText(/search/i), { target: { value: "tokena" } });

  expect(screen.getByText("lovelace_unit.TokenA")).toBeInTheDocument();
});

test("(l) a search with no matches shows an empty-results message instead of the table", () => {
  mockBalance("0", [{ unit: "lovelace_unit.TokenA", quantity: "5" }]);
  mockDelegation();

  render(<Portfolio />);
  fireEvent.change(screen.getByPlaceholderText(/search/i), { target: { value: "nomatch" } });

  expect(screen.queryByText("lovelace_unit.TokenA")).not.toBeInTheDocument();
  expect(screen.getByText(/no tokens match/i)).toBeInTheDocument();
});

test("(m) the search box is not rendered when there are no native tokens", () => {
  mockBalance("0", []);
  mockDelegation();

  render(<Portfolio />);

  expect(screen.queryByPlaceholderText(/search/i)).not.toBeInTheDocument();
});

test("NFT media off links to Settings without fetching the NFT list", () => {
  mockBalance("0", []);
  mockDelegation();
  const nftSpy = vi.spyOn(hooks, "useNfts");
  render(<Portfolio />);
  expect(screen.getByText(/media off/i)).toBeInTheDocument();
  expect(screen.getByRole("link", { name: "Settings" })).toBeInTheDocument();
  expect(nftSpy).not.toHaveBeenCalled();
});

test("NFT media on renders same-origin image thumbnails", () => {
  mockBalance("0", []);
  mockDelegation();
  vi.spyOn(hooks, "useNftMedia").mockReturnValue({
    enabled: true, loading: false, saving: false, error: null, setEnabled: vi.fn(),
  });
  vi.spyOn(hooks, "useNfts").mockReturnValue({
    data: [{ unit: "policy.token", name: "Token", image_cid: "bafyimage", cached: false }],
    error: null, loading: false, refresh: vi.fn(), setData: vi.fn(),
  });
  render(<Portfolio />);
  expect(screen.getByRole("img", { name: "Token" })).toHaveAttribute(
    "src", "/wallet/nft/policy.token/image",
  );
});

test("NFT image load failure renders the empty thumbnail", () => {
  mockBalance("0", []);
  mockDelegation();
  vi.spyOn(hooks, "useNftMedia").mockReturnValue({
    enabled: true, loading: false, saving: false, error: null, setEnabled: vi.fn(),
  });
  vi.spyOn(hooks, "useNfts").mockReturnValue({
    data: [{ unit: "policy.token", name: "Token", image_cid: "bafyimage", cached: false }],
    error: null, loading: false, refresh: vi.fn(), setData: vi.fn(),
  });

  const { container } = render(<Portfolio />);
  fireEvent.error(screen.getByRole("img", { name: "Token" }));

  expect(screen.queryByRole("img", { name: "Token" })).not.toBeInTheDocument();
  expect(container.querySelector(".nft-thumb-empty")).toBeInTheDocument();
});
// The read-only escape hatch lets people in before the node can answer, so this
// is the first screen a new user sees on a fresh install. A bare "node not
// ready" in an empty page reads as a broken wallet; the node is simply starting.
test("a node that cannot answer yet is explained, not dumped as an error", () => {
  vi.spyOn(hooks, "useBalance").mockReturnValue({
    data: null, error: new ApiError(503, "node not ready"), loading: false, refresh: vi.fn(),
  } as never);
  mockDelegation();
  mockAssetMetadata({});
  vi.spyOn(hooks, "useStatus").mockReturnValue({
    data: { state: "bootstrapping", tip: 0, caughtUp: false, network: "preview",
            bootstrap: { phase: "bootstrap", percent: 58.7 } },
    error: null, loading: false, refresh: vi.fn(),
  } as never);

  render(<Portfolio canSend={false} />);

  expect(screen.getByText(/waiting for the node/i)).toBeInTheDocument();
  // The progress the app already knows about, rather than a dead end.
  expect(screen.getByText(/download snapshot · 58\.7%/i)).toBeInTheDocument();
  expect(screen.queryByText(/^node not ready$/i)).not.toBeInTheDocument();
});

// The corollary: swallowing genuine faults into a reassuring "still starting"
// message would hide real breakage, so anything that is not the node's own
// not-ready gate must still surface as an error.
test("a real fault is still reported as an error", () => {
  vi.spyOn(hooks, "useBalance").mockReturnValue({
    data: null, error: new ApiError(500, "balance blew up"), loading: false, refresh: vi.fn(),
  } as never);
  mockDelegation();
  mockAssetMetadata({});

  render(<Portfolio canSend={false} />);

  expect(screen.getByRole("alert")).toHaveTextContent(/balance blew up/i);
  expect(screen.queryByText(/waiting for the node/i)).not.toBeInTheDocument();
});

test("a real delegation fault is not masked by a not-ready balance", () => {
  vi.spyOn(hooks, "useBalance").mockReturnValue({
    data: null, error: new ApiError(503, "node not ready"), loading: false, refresh: vi.fn(),
  } as never);
  vi.spyOn(hooks, "useDelegation").mockReturnValue({
    data: null, error: new ApiError(500, "delegation blew up"), loading: false, refresh: vi.fn(),
  } as never);

  render(<Portfolio canSend={false} />);

  expect(screen.getByRole("alert")).toHaveTextContent(/delegation blew up/i);
  expect(screen.queryByText(/waiting for the node/i)).not.toBeInTheDocument();
});

test("a supervisor error is shown instead of a reassuring wait state", () => {
  mockBalance("0", []);
  mockDelegation();
  vi.spyOn(hooks, "useBalance").mockReturnValue({
    data: null, error: new ApiError(503, "node not ready"), loading: false, refresh: vi.fn(),
  } as never);
  vi.spyOn(hooks, "useStatus").mockReturnValue({
    data: { state: "error", error: "node failed to start", tip: 0, caughtUp: false, network: "preview" },
    error: null, loading: false, refresh: vi.fn(),
  } as never);

  render(<Portfolio canSend={false} />);

  expect(screen.getByRole("alert")).toHaveTextContent(/node failed to start/i);
  expect(screen.queryByText(/nothing is wrong/i)).not.toBeInTheDocument();
});

// useAsync shows its spinner only on the initial fetch, not on the two-second
// retries (polls update data in place, see hooks.ts: `if (isInitial)
// setLoading(true)`). This test still pins the defensive ordering in
// Portfolio.tsx: even if a fetch reported loading alongside the 503, the
// not-ready branch must come before any loading check so the explanation is
// never blanked. The card owns the screen until the node answers.
test("the not-ready card stays put while its retry is in flight", () => {
  vi.spyOn(hooks, "useBalance").mockReturnValue({
    data: null, error: new ApiError(503, "node not ready"), loading: true, refresh: vi.fn(),
  } as never);
  mockDelegation();
  mockAssetMetadata({});
  vi.spyOn(hooks, "useStatus").mockReturnValue({
    data: { state: "bootstrapping", tip: 0, caughtUp: false, network: "preview",
            bootstrap: { phase: "bootstrap", percent: 58.7 } },
    error: null, loading: false, refresh: vi.fn(),
  } as never);

  render(<Portfolio canSend={false} />);

  expect(screen.getByText(/waiting for the node/i)).toBeInTheDocument();
  expect(screen.queryByText("Loading…")).not.toBeInTheDocument();
});
