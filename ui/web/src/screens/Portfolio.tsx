import { useCallback, useMemo, useState } from "react";
import { useBalance, useDelegation, useAssetMetadata, useNfts, useNftMedia } from "../api/hooks";
import { Icon } from "../components/Icon";
import { AssetIcon } from "../components/AssetIcon";
import { CopyButton } from "../components/CopyButton";
import { Button } from "../components/Button";
import { Card } from "../components/Card";
import { Table } from "../components/Table";
import { StatusPill } from "../components/StatusPill";
import { Input } from "../components/Input";
import { formatAda, formatTokenQuantity } from "../format";
import { extractAssetMeta, assetDisplayName, assetMatchesQuery } from "../tokenMeta";
import { nftImageUrl } from "../api/client";
import { navigate } from "../router";
import { NodeNotReady } from "../components/NodeNotReady";
import { ApiError } from "../api/client";

function NftList() {
  const nfts = useNfts();
  if (nfts.loading) return <p className="muted">Loading…</p>;
  if (nfts.error) return <p role="alert" className="error-text">{nfts.error.message}</p>;
  if (!nfts.data?.length) return <p className="muted">No NFTs</p>;
  return (
    <div className="nft-grid">
      {nfts.data.map((n) => (
        <figure className="nft-item" key={n.unit}>
          <NftThumbnail unit={n.unit} name={n.name} hasImage={Boolean(n.image_cid)} />
          <figcaption className="nft-name">{n.name || n.unit}</figcaption>
          <details className="nft-details">
            <summary>Asset details</summary>
            {n.description && <p>{n.description}</p>}
            <code>{n.unit}</code>
            <CopyButton value={n.unit} ariaLabel={`Copy asset ID for ${n.name || n.unit}`} />
          </details>
        </figure>
      ))}
    </div>
  );
}

function NftThumbnail({ unit, name, hasImage }: { unit: string; name: string; hasImage: boolean }) {
  const [failed, setFailed] = useState(false);
  const [attempt, setAttempt] = useState(0);
  if (!hasImage || failed) {
    return <div className="nft-thumb nft-thumb-empty">
      <Icon name="image" size={28} />
      <span>{failed ? "Image unavailable" : "No supported image"}</span>
      {failed && <button type="button" onClick={() => { setAttempt((n) => n + 1); setFailed(false); }}>Retry image</button>}
    </div>;
  }
  return (
    <img
      className="nft-thumb"
      src={`${nftImageUrl(unit)}${attempt ? `?retry=${attempt}` : ""}`}
      alt={name || unit}
      loading="lazy"
      onError={() => setFailed(true)}
    />
  );
}

function NftGallery() {
  const media = useNftMedia();
  if (media.loading) return <p className="muted">Loading…</p>;
  if (media.error) return <p role="alert" className="error-text">{media.error.message}</p>;
  if (media.available === false) {
    return <div className="collection-empty"><Icon name="image" size={28} /><h3>Images need media support</h3><p className="muted">This build can show token balances, but NFT images require a Bursa build with NFT media support.</p></div>;
  }
  if (!media.enabled) {
    return (
      <div className="collection-empty"><Icon name="image" size={28} /><h3>Your collection, in view</h3><p className="muted">
        Media off. Enabling images connects to IPFS peers through your local client. You can change this in{" "}
        <a href="#/settings" onClick={(e) => { e.preventDefault(); navigate("settings"); }}>
          Settings
        </a>{" "}
        at any time.
      </p><Button disabled={media.saving} onClick={() => void media.setEnabled(true)}>{media.saving ? "Enabling…" : "Enable images"}</Button></div>
    );
  }
  return <NftList />;
}

interface PortfolioProps {
  // Set when this wallet's stored multi-signature policy could not be read. It
  // still receives and reports a balance; it just cannot spend, and saying so
  // beats a Send button that leads nowhere.
  multiSigError?: string;
  // Whether this wallet on this node can build a spend. Receive needs nothing,
  // so it is always offered.
  canSend?: boolean;
  // Why Send is off, when it is. A greyed button with no reason leaves someone
  // guessing whether the wallet is broken or just waiting; the command palette
  // has always said why, and this is the same string.
  sendDisabledReason?: string;
}

export function Portfolio({ canSend = false, sendDisabledReason, multiSigError }: PortfolioProps = {}) {
  const balance = useBalance();
  const delegation = useDelegation();
  const [query, setQuery] = useState("");

  // Metadata is looked up per-asset through the node (node-only; see
  // tokenMeta.ts) and applied on a best-effort basis below — a missing or
  // failed lookup for one asset never blocks the rest of the portfolio.
  const units = useMemo(() => (balance.data?.assets ?? []).map((a) => a.unit), [balance.data]);
  // Stable identity: NodeNotReady keys its retry interval on this callback, and a
  // fresh closure every render would clear and restart the interval each time,
  // so the retry could be starved by unrelated re-renders.
  const refreshBalance = balance.refresh;
  const refreshDelegation = delegation.refresh;
  const retryNodeQueries = useCallback(() => {
    refreshBalance();
    refreshDelegation();
  }, [refreshBalance, refreshDelegation]);
  const metadataByUnit = useAssetMetadata(units);
  const assets = balance.data?.assets ?? [];

  // A node that cannot answer yet is an expected, self-resolving state, not a
  // fault: say so instead of dropping a bare server error into a blank screen.
  // Real faults still surface as errors.
  const notReady = (e: Error | null) => e instanceof ApiError && e.status === 503;
  const balanceNotReady = notReady(balance.error);
  const delegationNotReady = notReady(delegation.error);
  if (balance.error && !balanceNotReady) {
    return <p role="alert" className="error-text">{balance.error.message}</p>;
  }
  if (delegation.error && !delegationNotReady) {
    return <p role="alert" className="error-text">{delegation.error.message}</p>;
  }
  // Ahead of the loading branch on purpose. Each retry from the card re-enters
  // loading (useAsync shows the spinner for a refresh), so checking loading
  // first would replace the labeled explanation with "Loading…" every two
  // seconds. The 503 is still set while the retry is in flight, so the card
  // stays put until the node actually answers.
  if (balanceNotReady || delegationNotReady) {
    return <NodeNotReady what="Your balance and delegation" verb="come" refresh={retryNodeQueries} />;
  }

  // Show a single loading state if either hook is still loading.
  if (balance.loading || delegation.loading) {
    return <p>Loading…</p>;
  }

  const del = delegation.data;

  // A fresh wallet returns zeros/empty — treat it as valid, not an error.
  const lovelace = balance.data?.lovelace ?? "0";

  const visibleAssets = assets.filter((a) =>
    assetMatchesQuery(a.unit, extractAssetMeta(metadataByUnit[a.unit]), query),
  );

  const tokenColumns = [
    { key: "unit", label: "Asset" },
    { key: "quantity", label: "Quantity" },
  ];
  const tokenRows = visibleAssets.map((a) => {
    const meta = extractAssetMeta(metadataByUnit[a.unit]);
    const name = assetDisplayName(a.unit, meta);
    const identifier = meta.ticker && meta.ticker !== name
      ? meta.ticker
      : `${a.unit.slice(0, 8)}…${a.unit.slice(-6)}`;
    return {
      unit: (
        <span className="asset-identity">
          <AssetIcon unit={a.unit} name={name} info={metadataByUnit[a.unit]} />
          <span>
            <span className="asset-name">{name}</span>
            <span className="asset-kind" title={a.unit}>{identifier}</span>
          </span>
        </span>
      ),
      quantity: <span className="asset-quantity">{meta.decimals !== undefined ? formatTokenQuantity(a.quantity, meta.decimals) : a.quantity}{meta.decimals === undefined && <small>Base units</small>}</span>,
    };
  });

  return (
    <div className="portfolio">
      <header className="portfolio-heading"><div><h1>Portfolio</h1><p>Your assets, in one place.</p></div></header>
      <section className="balance-panel" aria-label="Balance">
        <div className="balance-copy"><div className="wallet-card-heading"><h2>Balance</h2><span className="card-chain"><span className="cardano-mark" aria-hidden="true">₳</span>Cardano</span></div>
        <p className="balance-ada">{formatAda(lovelace)} <span>ADA</span></p>
        <p className="balance-source">ADA in your selected account</p>
        {/* Send and Receive are actions, not places. They sit on the balance
            they act on — where you already are when you decide to move funds —
            rather than costing two entries in a nav you have to scan. */}
        {multiSigError && (
          <p role="alert" className="error-text">
            {multiSigError}
          </p>
        )}
        <div className="portfolio-actions">
          <Button onClick={() => navigate("send")} disabled={!canSend}>
            <Icon name="send" size={18} />Send
          </Button>
          <Button variant="ghost" onClick={() => navigate("receive")}>
            <Icon name="receive" size={18} />Receive
          </Button>
        </div>
        {/* Suppressed when multiSigError is already on screen: that alert names the
            actual reason this wallet cannot spend, and the generic line under the
            buttons would only restate it in weaker words. */}
        {!canSend && !multiSigError && sendDisabledReason && (
          <p className="helper-text">Send is unavailable — {sendDisabledReason.toLowerCase()}.</p>
        )}
        </div>
      </section>

      <div className="portfolio-assets"><Card>
        <div className="asset-toolbar">
          <h2>Native Tokens <span className="asset-count" aria-label={`${assets.length} native tokens`}>{assets.length}</span></h2>
          {assets.length > 0 && <div className="asset-search"><Icon name="search" size={16} /><Input
            type="text"
            className="token-search"
            placeholder="Search tokens"
            aria-label="Search native tokens"
            value={query}
            onChange={(e) => setQuery(e.target.value)}
          /></div>}
        </div>
        {assets.length === 0 ? (
          <p className="muted">No native tokens</p>
        ) : (
          <>
            {visibleAssets.length === 0 ? (
              <p className="muted">No tokens match &ldquo;{query}&rdquo;</p>
            ) : (
              <Table columns={tokenColumns} rows={tokenRows} />
            )}
          </>
        )}
      </Card></div>
      <aside className="portfolio-staking"><Card title="Delegation">
        {del ? (
          <dl className="delegation-details">
            <div className="dl-row staking-rewards">
              <dt>Rewards</dt>
              <dd>{formatAda(del.rewards_sum)} ADA</dd>
            </div>

            <div className="dl-row">
              <dt>Pool</dt>
              <dd>{del.pool_id ?? <span className="muted">Not delegated</span>}</dd>
            </div>

            <div className="dl-row">
              <dt>Status</dt>
              <dd>
                <StatusPill tone={del.active ? "ok" : "muted"}>
                  {del.active ? "Active" : "Inactive"}
                </StatusPill>
              </dd>
            </div>


            <div className="dl-row">
              <dt>Withdrawable</dt>
              <dd>{formatAda(del.withdrawable_amount)} ADA</dd>
            </div>

            {del.provisional && (
              <div className="dl-row provisional-notice">
                <dt>
                  <StatusPill tone="warn">Provisional</StatusPill>
                </dt>
                <dd className="muted">{del.note}</dd>
              </div>
            )}
          </dl>
        ) : (
          <p className="muted">Not delegated</p>
        )}
        <button className="staking-link" onClick={() => navigate("stake")}>Manage staking<Icon name="arrow" size={18} /></button>
      </Card></aside>
      <aside className="portfolio-collectibles"><Card title="NFTs">
        <div className="collection-content"><NftGallery /></div>
      </Card></aside>
    </div>
  );
}
