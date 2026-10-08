import { useEffect, useMemo, useRef, useState } from "react";
import type { AssetInfo, DexQuote } from "../api/types";
import { computeDexQuote } from "../api/client";
import { useAssetMetadata, useBalance, useDexPools } from "../api/hooks";
import { Card } from "../components/Card";
import { Input } from "../components/Input";
import { Button } from "../components/Button";
import { Table } from "../components/Table";
import { CopyButton } from "../components/CopyButton";
import { AssetIcon } from "../components/AssetIcon";
import { Icon } from "../components/Icon";
import { errorMessage } from "../errorMessage";
import { extractAssetMeta, assetDisplayName } from "../tokenMeta";
import { formatTokenQuantity, parseTokenQuantity, shortId } from "../format";

type Metadata = Record<string, AssetInfo | undefined>;

function assetName(unit: string, metadata: Metadata): string {
  return unit === "lovelace" ? "ADA" : assetDisplayName(unit, extractAssetMeta(metadata[unit]));
}
function assetDecimals(unit: string, metadata: Metadata): number | undefined {
  return unit === "lovelace" ? 6 : extractAssetMeta(metadata[unit]).decimals;
}
function displayAmount(amount: string, unit: string, metadata: Metadata): string {
  const decimals = assetDecimals(unit, metadata);
  return decimals === undefined ? `${amount} base units` : formatTokenQuantity(amount, decimals);
}
function formatPrice(value: number): string {
  return Number.isFinite(value) ? value.toLocaleString("en-US", { maximumSignificantDigits: 6, useGrouping: false }) : "—";
}

function OrderPanel({ quote, metadata, onBack }: { quote: DexQuote; metadata: Metadata; onBack: () => void }) {
  const orderJson = JSON.stringify({
    protocol: quote.protocol, pool_id: quote.pool_id, asset_in: quote.asset_in, asset_out: quote.asset_out,
    amount_in: quote.amount_in, expected_amount_out: quote.amount_out,
    price_impact_pct: quote.price_impact_pct, effective_fee: quote.effective_fee,
  }, null, 2);
  return <div className="swap-order"><Card title="Prepared Order">
    <p className="helper-text">Take these parameters to your chosen DEX to execute the swap. Bursa does not build or send swap transactions.</p>
    <dl className="preview-summary">
      <div className="dl-row"><dt>DEX</dt><dd>{quote.protocol}</dd></div>
      <div className="dl-row"><dt>Pool</dt><dd className="mono">{quote.pool_id}</dd></div>
      <div className="dl-row"><dt>Pay</dt><dd>{displayAmount(quote.amount_in, quote.asset_in, metadata)} {shortId(assetName(quote.asset_in, metadata))}</dd></div>
      <div className="dl-row"><dt>Receive (est.)</dt><dd>{displayAmount(quote.amount_out, quote.asset_out, metadata)} {shortId(assetName(quote.asset_out, metadata))}</dd></div>
    </dl>
    <details className="order-parameters" open><summary>Order parameters (JSON)</summary><pre>{orderJson}</pre><CopyButton value={orderJson} ariaLabel="Copy order JSON" /></details>
    <Button variant="ghost" onClick={onBack}>Back</Button>
  </Card></div>;
}

export function Swap() {
  const pools = useDexPools();
  const balance = useBalance();
  const [assetIn, setAssetIn] = useState("lovelace");
  const [assetOut, setAssetOut] = useState("");
  const [customIn, setCustomIn] = useState("");
  const [customOut, setCustomOut] = useState("");
  const [amountIn, setAmountIn] = useState("");
  const [quote, setQuote] = useState<DexQuote | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);
  const [prepared, setPrepared] = useState<DexQuote | null>(null);
  const requestVersion = useRef(0);
  const unitIn = assetIn === "custom" ? customIn.trim() : assetIn;
  const unitOut = assetOut === "custom" ? customOut.trim() : assetOut;
  const units = useMemo(() => Array.from(new Set([
    ...(balance.data?.assets ?? []).map((a) => a.unit),
    ...(pools.data?.pools ?? []).flatMap((p) => [p.asset_x, p.asset_y]),
    unitIn, unitOut,
  ])).filter((u) => u && u !== "lovelace"), [balance.data, pools.data, unitIn, unitOut]);
  const metadata = useAssetMetadata(units);
  const choices = useMemo(() => ["lovelace", ...Array.from(new Set([
    ...(balance.data?.assets ?? []).map((a) => a.unit),
    ...(pools.data?.pools ?? []).flatMap((p) => [p.asset_x, p.asset_y]),
  ])).filter((u) => u && u !== "lovelace")], [balance.data, pools.data]);
  const decimals = assetDecimals(unitIn, metadata);
  const ownedAmount = unitIn === "lovelace" ? balance.data?.lovelace : balance.data?.assets.find((a) => a.unit === unitIn)?.quantity;

  useEffect(() => {
    // An amount entered as base units must never become whole tokens on metadata arrival.
    setAmountIn("");
    setQuote(null);
    setError(null);
    requestVersion.current += 1;
  }, [unitIn, decimals]);

  function clearResult() { requestVersion.current += 1; setQuote(null); setError(null); }
  async function handleQuote() {
    clearResult();
    const version = requestVersion.current;
    let amount: string;
    try {
      amount = parseTokenQuantity(amountIn, decimals ?? 0);
      if (!unitIn || !unitOut) throw new Error("Choose an asset to pay and receive");
      if (unitIn === unitOut) throw new Error("Choose two different assets");
    } catch (e) { setError(errorMessage(e)); return; }
    setLoading(true);
    try {
      const result = await computeDexQuote({ asset_in: unitIn, asset_out: unitOut, amount_in: amount });
      if (requestVersion.current === version) setQuote(result);
    } catch (e) { if (requestVersion.current === version) setError(errorMessage(e)); }
    finally { setLoading(false); }
  }

  if (prepared) return <OrderPanel quote={prepared} metadata={metadata} onBack={() => setPrepared(null)} />;

  const poolRows = (pools.data?.pools ?? []).map((p) => ({
    protocol: p.protocol,
    pair: <span className="pool-pair" title={`${p.asset_x} / ${p.asset_y}`}>{shortId(assetName(p.asset_x, metadata))} / {shortId(assetName(p.asset_y, metadata))}</span>,
    price: formatPrice(p.price_xy),
    fee: `${(p.effective_fee * 100).toFixed(2)}%`,
    action: <Button variant="ghost" disabled={loading} onClick={() => { setAssetIn(p.asset_x); setAssetOut(p.asset_y); setAmountIn(""); clearResult(); }}>Use pair</Button>,
  }));

  function picker(side: "in" | "out") {
    const incoming = side === "in";
    const value = incoming ? assetIn : assetOut;
    const unit = incoming ? unitIn : unitOut;
    return <>
      <label htmlFor={`swap-${side}`}>{incoming ? "Pay (asset in)" : "Receive (asset out)"}</label>
      <div className="swap-token-select"><AssetIcon unit={unit} name={assetName(unit, metadata) || "?"} info={metadata[unit]} />
        <select id={`swap-${side}`} className="field" value={value} disabled={loading} onChange={(e) => {
          (incoming ? setAssetIn : setAssetOut)(e.target.value);
          if (incoming) setAmountIn("");
          clearResult();
        }}>
          {!incoming && <option value="">Choose a token</option>}
          {choices.map((choice) => <option key={choice} value={choice}>{shortId(assetName(choice, metadata))}{choice !== "lovelace" ? ` · ${shortId(choice)}` : " · Cardano"}</option>)}
          <option value="custom">Custom token…</option>
        </select>
      </div>
      {value === "custom" && <div className="swap-custom"><label htmlFor={`custom-${side}`}>{incoming ? "Custom pay asset" : "Custom receive asset"}</label><Input id={`custom-${side}`} value={incoming ? customIn : customOut} placeholder="Policy ID + hex asset name" disabled={loading} onChange={(e) => { (incoming ? setCustomIn : setCustomOut)(e.target.value); if (incoming) setAmountIn(""); clearResult(); }} /></div>}
    </>;
  }

  return <div className="swap-screen">
    <header className="page-heading"><h1>Swap</h1><p>Find a quote across the pools on your node.</p></header>
    <div className="swap-layout">
      <section className="swap-composer" aria-label="Swap quote">
        <div className="swap-composer-heading"><h2>Swap Quote</h2><span className="quote-badge">Quote only</span></div>
        <div className="swap-input-panel">
          {picker("in")}
          <label htmlFor="swap-amount">Amount in ({decimals === undefined ? "base units" : shortId(assetName(unitIn, metadata))})</label>
          <Input id="swap-amount" type="text" inputMode="decimal" placeholder="0.00" value={amountIn} disabled={loading} onChange={(e) => { setAmountIn(e.target.value); clearResult(); }} />
          {ownedAmount !== undefined && <p className="helper-text">Balance: {displayAmount(ownedAmount, unitIn, metadata)}</p>}
          {decimals === undefined && <p className="helper-text">Token decimals are unavailable. Enter a whole number of base units.</p>}
        </div>
        <div className="swap-direction"><Icon name="receive" size={18} /></div>
        <div className="swap-input-panel">{picker("out")}</div>
        {error && <p role="alert" className="error-text">{error}</p>}
        <Button onClick={handleQuote} disabled={loading || !amountIn.trim() || !unitOut || !unitIn}>{loading ? "Quoting…" : "Get quote"}</Button>
        <p className="swap-disclosure">Review a quote here, then execute it with your chosen DEX.</p>
      </section>
      <aside className="swap-review" aria-live="polite">
        {quote ? <>
          <h2>Best quote</h2><div className="swap-output"><span>Estimated receive</span><strong>{displayAmount(quote.amount_out, quote.asset_out, metadata)}</strong><span>{shortId(assetName(quote.asset_out, metadata))}</span></div>
          <dl className="preview-summary">
            <div className="dl-row"><dt>DEX</dt><dd>{quote.protocol}</dd></div>
            <div className="dl-row"><dt>Price impact</dt><dd>{quote.price_impact_pct.toFixed(4)}%</dd></div>
            <div className="dl-row"><dt>Pool fee</dt><dd>{(quote.effective_fee * 100).toFixed(2)}%</dd></div>
          </dl>
          <details className="quote-route"><summary>Route details</summary><code>{quote.route}</code></details>
          <p className="helper-text">The estimate can change. Network and DEX execution fees are additional.</p>
          <Button onClick={() => setPrepared(quote)}>Prepare order</Button>
        </> : <><Icon name="swap" size={26} /><h2>Your quote appears here</h2><p>Choose two assets and an amount. Bursa compares the available pools and shows the highest estimated output.</p><dl className="quote-facts"><div><dt>Source</dt><dd>Your local node</dd></div><div><dt>Network</dt><dd>Cardano mainnet</dd></div><div><dt>Execution</dt><dd>On your chosen DEX</dd></div></dl></>}
      </aside>
    </div>
    <section className="dex-pools"><h2>Liquidity pools</h2><p className="helper-text">Indexed by your node. Prices below are ratios of base units (Y/X).</p>
      {pools.loading && !pools.data && <p className="muted">Reading pools from the local node…</p>}
      {pools.error && <p role="alert" className="error-text">Could not refresh pools: {pools.error.message}</p>}
      {!pools.loading && !pools.error && poolRows.length === 0 && <p className="muted">No pools found.</p>}
      {poolRows.length > 0 && <Table columns={[{ key: "protocol", label: "DEX" }, { key: "pair", label: "Pair" }, { key: "price", label: "Base-unit price" }, { key: "fee", label: "Pool fee" }, { key: "action", label: "" }]} rows={poolRows} />}
    </section>
  </div>;
}
