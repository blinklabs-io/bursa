import { useMemo, useState } from "react";
import { useBalance, useDelegation, useAssetMetadata, useNfts, useNftMedia } from "../api/hooks";
import { Card } from "../components/Card";
import { Table } from "../components/Table";
import { StatusPill } from "../components/StatusPill";
import { Input } from "../components/Input";
import { formatAda, formatTokenQuantity } from "../format";
import { extractAssetMeta, assetDisplayName, assetMatchesQuery } from "../tokenMeta";
import { nftImageUrl } from "../api/client";
import { navigate } from "../router";

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
        </figure>
      ))}
    </div>
  );
}

function NftThumbnail({ unit, name, hasImage }: { unit: string; name: string; hasImage: boolean }) {
  const [failed, setFailed] = useState(false);
  if (!hasImage || failed) {
    return <div className="nft-thumb nft-thumb-empty" aria-hidden="true" />;
  }
  return (
    <img
      className="nft-thumb"
      src={nftImageUrl(unit)}
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
  if (!media.enabled) {
    return (
      <p className="muted">
        Media off — enable NFT media in{" "}
        <a href="#/settings" onClick={(e) => { e.preventDefault(); navigate("settings"); }}>
          Settings
        </a>{" "}
        to fetch images.
      </p>
    );
  }
  return <NftList />;
}

export function Portfolio() {
  const balance = useBalance();
  const delegation = useDelegation();
  const [query, setQuery] = useState("");

  // Metadata is looked up per-asset through the node (node-only; see
  // tokenMeta.ts) and applied on a best-effort basis below — a missing or
  // failed lookup for one asset never blocks the rest of the portfolio.
  const units = useMemo(() => (balance.data?.assets ?? []).map((a) => a.unit), [balance.data]);
  const metadataByUnit = useAssetMetadata(units);
  const assets = balance.data?.assets ?? [];

  // Show a single loading state if either hook is still loading.
  if (balance.loading || delegation.loading) {
    return <p>Loading…</p>;
  }

  // Show the first error encountered (balance errors take priority).
  if (balance.error) {
    return <p role="alert" className="error-text">{balance.error.message}</p>;
  }
  if (delegation.error) {
    return <p role="alert" className="error-text">{delegation.error.message}</p>;
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
    return {
      unit: assetDisplayName(a.unit, meta),
      quantity: meta.decimals !== undefined ? formatTokenQuantity(a.quantity, meta.decimals) : a.quantity,
    };
  });

  return (
    <div className="portfolio">
      <Card title="Balance">
        <p className="balance-ada">{formatAda(lovelace)} ADA</p>
      </Card>

      <Card title="Native Tokens">
        {assets.length === 0 ? (
          <p className="muted">No native tokens</p>
        ) : (
          <>
            <Input
              type="text"
              className="token-search"
              placeholder="Search by name, ticker, policy, or unit…"
              aria-label="Search native tokens"
              value={query}
              onChange={(e) => setQuery(e.target.value)}
            />
            {visibleAssets.length === 0 ? (
              <p className="muted">No tokens match &ldquo;{query}&rdquo;</p>
            ) : (
              <Table columns={tokenColumns} rows={tokenRows} />
            )}
          </>
        )}
      </Card>

      <Card title="NFTs">
        <NftGallery />
      </Card>

      <Card title="Delegation">
        {del ? (
          <dl className="delegation-details">
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
              <dt>Rewards</dt>
              <dd>{formatAda(del.rewards_sum)} ADA</dd>
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
      </Card>
    </div>
  );
}
