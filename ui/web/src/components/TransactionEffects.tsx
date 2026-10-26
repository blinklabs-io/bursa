import type { TxSummary } from "../api/types";
import { formatAda } from "../format";

export function TransactionEffects({
  summary,
  showSigningState = false,
}: {
  summary: TxSummary;
  showSigningState?: boolean;
}) {
  return (
    <section aria-label="Transaction effects">
      <dl className="preview-summary">
        <div className="dl-row">
          <dt>Fee</dt>
          <dd>{formatAda(summary.fee)} ADA</dd>
        </div>
        {summary.ttl !== undefined ? (
          <div className="dl-row">
            <dt>TTL (slot)</dt>
            <dd>{summary.ttl}</dd>
          </div>
        ) : null}
        {summary.certificates?.length ? (
          <div className="dl-row">
            <dt>Certificates</dt>
            <dd>{summary.certificates.join(", ")}</dd>
          </div>
        ) : null}
        {summary.network_id !== undefined ? (
          <div className="dl-row">
            <dt>Network</dt>
            <dd>{summary.network_id === 1 ? "mainnet (1)" : `testnet (${summary.network_id})`}</dd>
          </div>
        ) : null}
        {showSigningState ? (
          <>
            <div className="dl-row">
              <dt>Existing signatures</dt>
              <dd>{summary.existing_signatures.length}</dd>
            </div>
            <div className="dl-row">
              <dt>Wallet signatures available</dt>
              <dd>{summary.wallet_can_add.length}</dd>
            </div>
            <div className="dl-row">
              <dt>Complete</dt>
              <dd>{summary.is_complete ? "Yes" : "No"}</dd>
            </div>
          </>
        ) : null}
      </dl>

      <p className="field-label">Outputs</p>
      {summary.outputs.length ? (
        <ul className="signer-list">
          {summary.outputs.map((output, outputIndex) => (
            <li key={`${output.address}-${outputIndex}`}>
              <code className="tx-hash">{output.address}</code> — {formatAda(output.lovelace)} ADA
              {output.assets?.length ? (
                <div style={{ marginTop: "0.25rem" }}>
                  {output.assets.map((asset, assetIndex) => (
                    <div key={`${asset.unit}-${assetIndex}`}>
                      <code className="tx-hash">{asset.unit}</code> — {asset.quantity}
                    </div>
                  ))}
                </div>
              ) : null}
            </li>
          ))}
        </ul>
      ) : (
        <p className="helper-text">No outputs</p>
      )}

      {summary.withdrawals?.length ? (
        <>
          <p className="field-label">Reward withdrawals</p>
          <ul className="signer-list">
            {summary.withdrawals.map((withdrawal, index) => (
              <li key={`${withdrawal.address}-${index}`}>
                <code className="tx-hash">{withdrawal.address}</code> —{" "}
                {formatAda(withdrawal.lovelace)} ADA
              </li>
            ))}
          </ul>
        </>
      ) : null}
    </section>
  );
}
