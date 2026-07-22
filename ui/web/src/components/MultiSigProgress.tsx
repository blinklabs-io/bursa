interface MultiSigParticipant {
  key_hash: string;
  label?: string;
  signed: boolean;
}

interface MultiSigProgressProps {
  threshold: number;
  total: number;
  signedCount: number;
  participants?: MultiSigParticipant[];
}

// MultiSigProgress renders the shared N-of-M signing-progress display used by
// multi-sig spend flows: a "K of N signed" line (with the M-of-N policy and a
// threshold-met indicator once signedCount reaches threshold) and, when a
// participants list is supplied, a signer-list marking each key as signed or
// pending.
export function MultiSigProgress({ threshold, total, signedCount, participants }: MultiSigProgressProps) {
  const met = signedCount >= threshold;
  return (
    <div className="ms-progress-block">
      <p className="ms-progress">
        {signedCount} of {threshold} signed
        {total > 0 && ` (policy ${threshold}-of-${total})`}
        {met ? " · threshold met" : ""}
      </p>
      {participants && participants.length > 0 && (
        <ul className="signer-list">
          {participants.map((p) => (
            <li key={p.key_hash} className="ms-participant">
              <span aria-label={p.signed ? "signed" : "pending"}>{p.signed ? "✓" : "○"}</span>{" "}
              <code className="tx-hash">
                {p.label ? `${p.label}: ` : ""}
                {p.key_hash}
              </code>
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}
