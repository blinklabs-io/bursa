import type { TxSummary, TxSummaryInput, TxSummaryOutput } from "../api/types";
import { formatAda } from "../format";

function AssetList({ assets }: { assets?: { unit: string; quantity: string }[] }) {
  return assets?.length ? (
    <div style={{ marginTop: "0.25rem" }}>
      {assets.map((asset, index) => (
        <div key={`${asset.unit}-${index}`}>
          <code className="tx-hash">{asset.unit}</code> — {asset.quantity}
        </div>
      ))}
    </div>
  ) : null;
}

function OutputEffect({ output }: { output: TxSummaryOutput }) {
  return (
    <>
      <code className="tx-hash">{output.address}</code> — {formatAda(output.lovelace)} ADA
      <AssetList assets={output.assets} />
    </>
  );
}

function InputEffects({ inputs }: { inputs: TxSummaryInput[] }) {
  return (
    <ul className="signer-list">
      {inputs.map((input) => (
        <li key={`${input.tx_hash}-${input.index}`}>
          <code className="tx-hash">{input.tx_hash}#{input.index}</code>
          {input.resolved && input.address && input.lovelace !== undefined ? (
            <>
              <div><code className="tx-hash">{input.address}</code></div>
              <div>{formatAda(input.lovelace)} ADA</div>
              <AssetList assets={input.assets} />
            </>
          ) : (
            <div className="helper-text">Unresolved — address and value unavailable</div>
          )}
        </li>
      ))}
    </ul>
  );
}

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
		{summary.validity_start !== undefined ? (
		  <div className="dl-row">
			<dt>Valid from (slot)</dt>
			<dd>{summary.validity_start}</dd>
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
		{summary.voting_count ? <div className="dl-row"><dt>Governance votes</dt><dd>{summary.voting_count}</dd></div> : null}
		{summary.proposal_count ? <div className="dl-row"><dt>Governance proposals</dt><dd>{summary.proposal_count}</dd></div> : null}
		{summary.current_treasury_value !== undefined ? <div className="dl-row"><dt>Current treasury value</dt><dd>{formatAda(summary.current_treasury_value)} ADA</dd></div> : null}
		{summary.treasury_donation !== undefined ? <div className="dl-row"><dt>Treasury donation</dt><dd>{formatAda(summary.treasury_donation)} ADA</dd></div> : null}
		{summary.required_signers?.length ? <div className="dl-row"><dt>Required signers</dt><dd>{summary.required_signers.length}</dd></div> : null}
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

	  {summary.inputs?.length ? <><p className="field-label">Inputs spent</p><InputEffects inputs={summary.inputs} /></> : null}

      <p className="field-label">Outputs</p>
      {summary.outputs.length ? (
        <ul className="signer-list">
          {summary.outputs.map((output, outputIndex) => (
            <li key={`${output.address}-${outputIndex}`}>
			  <OutputEffect output={output} />
            </li>
          ))}
        </ul>
      ) : (
        <p className="helper-text">No outputs</p>
      )}

	  {summary.mint?.length ? (
		<><p className="field-label">Mint and burn</p><AssetList assets={summary.mint} /></>
	  ) : null}

	  {summary.collateral_inputs?.length || summary.collateral_return || summary.total_collateral !== undefined ? (
		<section aria-label="Collateral effects">
		  <p className="field-label">Collateral if script validation fails</p>
		  {summary.collateral_inputs?.length ? <InputEffects inputs={summary.collateral_inputs} /> : null}
		  <dl className="preview-summary">
			{summary.total_collateral !== undefined ? <div className="dl-row"><dt>Total collateral</dt><dd>{formatAda(summary.total_collateral)} ADA</dd></div> : null}
			{summary.collateral_return ? <div className="dl-row"><dt>Collateral return</dt><dd><OutputEffect output={summary.collateral_return} /></dd></div> : null}
		  </dl>
		</section>
	  ) : null}

	  {summary.reference_inputs?.length ? <><p className="field-label">Reference inputs</p><InputEffects inputs={summary.reference_inputs} /></> : null}

	  {summary.auxiliary_data_hash ? <p>Metadata hash: <code className="tx-hash">{summary.auxiliary_data_hash}</code></p> : null}
	  {summary.script_data_hash ? <p>Script data hash: <code className="tx-hash">{summary.script_data_hash}</code></p> : null}
	  {summary.required_signers?.length ? <><p className="field-label">Required signer key hashes</p><ul className="signer-list">{summary.required_signers.map((keyHash) => <li key={keyHash}><code className="tx-hash">{keyHash}</code></li>)}</ul></> : null}
	  {summary.unsupported_effects?.length ? <p role="alert">Full details unavailable for: {summary.unsupported_effects.join(", ")}</p> : null}

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
