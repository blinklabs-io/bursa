import { useState } from "react";
import type { DexQuote } from "../api/types";
import { computeDexQuote } from "../api/client";
import { useDexPools } from "../api/hooks";
import { Card } from "../components/Card";
import { Input } from "../components/Input";
import { Button } from "../components/Button";
import { Table } from "../components/Table";
import { CopyButton } from "../components/CopyButton";
import { errorMessage } from "../errorMessage";

// Render an asset unit compactly: ADA stays "lovelace", a long policy+name is
// truncated in the middle so the row stays scannable.
function shortUnit(unit: string): string {
  if (unit === "lovelace" || unit === "") return "ADA (lovelace)";
  if (unit.length <= 20) return unit;
  return `${unit.slice(0, 10)}…${unit.slice(-6)}`;
}

// Format a pool price to ~6 significant digits in fixed-point notation.
// Number.prototype.toPrecision falls back to scientific notation outside
// roughly [1e-6, 1e21) (e.g. "1.23457e-7"), which is hard to scan in a price
// column; native-token pools routinely produce prices in that range (assets
// with very different decimals/reserves). toLocaleString with a significant-
// digit budget never switches to exponential notation.
function formatPrice(n: number): string {
  if (!Number.isFinite(n)) return "—";
  if (n === 0) return "0";
  return n.toLocaleString("en-US", {
    maximumSignificantDigits: 6,
    useGrouping: false,
  });
}

const POOL_COLUMNS = [
  { key: "protocol", label: "DEX" },
  { key: "pair", label: "Pair" },
  { key: "price", label: "Price (Y/X)" },
  { key: "fee", label: "Fee" },
];

// PoolsPanel lists every pool the node can see, with prices. Pool data comes
// entirely from the embedded node (no external service), so it needs no consent.
function PoolsPanel() {
  const pools = useDexPools();

  if (pools.loading && !pools.data) {
    return (
      <Card title="Pools">
        <p className="muted">Reading pools from the local node…</p>
      </Card>
    );
  }
  if (pools.error && !pools.data) {
    return (
      <Card title="Pools">
        <p role="alert" className="error-text">
          {pools.error.message}
        </p>
      </Card>
    );
  }

  const rows = (pools.data?.pools ?? []).map((p) => ({
    protocol: p.protocol,
    pair: `${shortUnit(p.asset_x)} / ${shortUnit(p.asset_y)}`,
    price: formatPrice(p.price_xy),
    fee: `${(p.effective_fee * 100).toFixed(2)}%`,
  }));

  return (
    <Card title="Pools">
      <p className="helper-text">
        Live pool prices, read directly from the embedded node — no external
        price service is contacted.
      </p>
      {pools.error && (
        <p role="alert" className="error-text">
          Could not refresh pools: {pools.error.message}
        </p>
      )}
      {rows.length === 0 ? (
        <p className="muted">No pools found.</p>
      ) : (
        <Table columns={POOL_COLUMNS} rows={rows} />
      )}
    </Card>
  );
}

interface OrderPanelProps {
  quote: DexQuote;
  onBack: () => void;
}

// OrderPanel shows the prepared order parameters for a quote. This is
// QUOTES-FIRST: the wallet does NOT build or submit a swap transaction. The
// parameters are exported for the user to take to a DEX front-end / batcher.
function OrderPanel({ quote, onBack }: OrderPanelProps) {
  const orderJson = JSON.stringify(
    {
      protocol: quote.protocol,
      pool_id: quote.pool_id,
      asset_in: quote.asset_in,
      asset_out: quote.asset_out,
      amount_in: quote.amount_in,
      expected_amount_out: quote.amount_out,
      price_impact_pct: quote.price_impact_pct,
      effective_fee: quote.effective_fee,
    },
    null,
    2,
  );

  return (
    <Card title="Prepared Order">
      <div className="done-details">
        <p className="helper-text">
          This is a <strong>prepared order</strong>, not a submitted swap. Bursa
          does not build or send swap transactions. Take these parameters to the
          chosen DEX / batcher to execute the swap yourself.
        </p>

        <dl className="preview-summary">
          <div className="dl-row">
            <dt>DEX</dt>
            <dd>{quote.protocol}</dd>
          </div>
          <div className="dl-row">
            <dt>Pool</dt>
            <dd>{quote.pool_id}</dd>
          </div>
          <div className="dl-row">
            <dt>Pay</dt>
            <dd>
              {quote.amount_in} {shortUnit(quote.asset_in)}
            </dd>
          </div>
          <div className="dl-row">
            <dt>Receive (est.)</dt>
            <dd>
              {quote.amount_out} {shortUnit(quote.asset_out)}
            </dd>
          </div>
        </dl>

        <p className="field-label">Order parameters (JSON)</p>
        <div className="tx-hash-row">
          <code className="tx-hash">{orderJson}</code>
          <CopyButton value={orderJson} />
        </div>

        <Button variant="ghost" onClick={onBack}>
          Back
        </Button>
      </div>
    </Card>
  );
}

export function Swap() {
  const [assetIn, setAssetIn] = useState("lovelace");
  const [assetOut, setAssetOut] = useState("");
  const [amountIn, setAmountIn] = useState("");
  const [quote, setQuote] = useState<DexQuote | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);
  const [prepared, setPrepared] = useState<DexQuote | null>(null);

  function clearResult() {
    setQuote(null);
    setError(null);
  }

  async function handleQuote() {
    setError(null);
    setQuote(null);

    const amount = amountIn.trim();
    // amount_in is a base-unit (e.g. lovelace) uint64; validate as a whole
    // positive integer with BigInt so large values aren't capped at 2^53.
    if (!/^\d+$/.test(amount) || BigInt(amount) <= 0n) {
      setError("Amount must be a positive whole number (base units, e.g. lovelace)");
      return;
    }
    if (!assetOut.trim()) {
      setError("Choose an asset to receive");
      return;
    }

    setLoading(true);
    try {
      const q = await computeDexQuote({
        asset_in: assetIn.trim() || "lovelace",
        asset_out: assetOut.trim(),
        amount_in: amount,
      });
      setQuote(q);
    } catch (e) {
      setError(errorMessage(e));
    } finally {
      setLoading(false);
    }
  }

  if (prepared) {
    return <OrderPanel quote={prepared} onBack={() => setPrepared(null)} />;
  }

  return (
    <div className="send-form">
      <Card title="Swap Quote">
        <div className="sign-form">
          <p className="helper-text">
            Get the best on-chain swap quote across DEX pools, computed entirely
            from your embedded node. Units are <code>lovelace</code> for ADA or a
            policy-id + hex asset-name string for native tokens; amounts are in
            base units.
          </p>

          <label htmlFor="swap-in">Pay (asset in)</label>
          <Input
            id="swap-in"
            type="text"
            placeholder="lovelace"
            value={assetIn}
            onChange={(e) => {
              setAssetIn(e.target.value);
              clearResult();
            }}
            disabled={loading}
          />

          <label htmlFor="swap-out">Receive (asset out)</label>
          <Input
            id="swap-out"
            type="text"
            placeholder="policy id + hex name"
            value={assetOut}
            onChange={(e) => {
              setAssetOut(e.target.value);
              clearResult();
            }}
            disabled={loading}
          />

          <label htmlFor="swap-amount">Amount in (base units)</label>
          <Input
            id="swap-amount"
            type="text"
            placeholder="1000000"
            value={amountIn}
            onChange={(e) => {
              setAmountIn(e.target.value);
              clearResult();
            }}
            disabled={loading}
          />

          {error && (
            <p role="alert" className="error-text">
              {error}
            </p>
          )}

          <Button
            onClick={handleQuote}
            disabled={loading || !amountIn.trim() || !assetOut.trim()}
          >
            {loading ? "Quoting…" : "Get quote"}
          </Button>

          {quote && (
            <div className="sign-result">
              <p className="field-label">Best quote</p>
              <dl className="preview-summary">
                <div className="dl-row">
                  <dt>Route</dt>
                  <dd>{quote.route}</dd>
                </div>
                <div className="dl-row">
                  <dt>Amount out</dt>
                  <dd>{quote.amount_out}</dd>
                </div>
                <div className="dl-row">
                  <dt>Price impact</dt>
                  <dd>{quote.price_impact_pct.toFixed(4)}%</dd>
                </div>
                <div className="dl-row">
                  <dt>Effective fee</dt>
                  <dd>{(quote.effective_fee * 100).toFixed(2)}%</dd>
                </div>
              </dl>
              <Button onClick={() => setPrepared(quote)}>Prepare order</Button>
            </div>
          )}
        </div>
      </Card>

      <PoolsPanel />
    </div>
  );
}
