import { useState } from "react";

interface CopyButtonProps {
  value: string;
  ariaLabel?: string;
  "aria-label"?: string;
}

export function CopyButton({
  value,
  ariaLabel,
  "aria-label": ariaLabelAttribute,
}: CopyButtonProps) {
  const [copied, setCopied] = useState(false);
  const label = ariaLabel ?? ariaLabelAttribute;

  function handleClick() {
    navigator.clipboard
      .writeText(value)
      .then(() => {
        setCopied(true);
        setTimeout(() => setCopied(false), 1000);
      })
      .catch(() => {
        // Copy can fail (denied permission / insecure context); leave the
        // label unchanged rather than falsely reporting success.
      });
  }

  return (
    <button type="button" className="btn ghost" onClick={handleClick} aria-label={label}>
      {copied ? "Copied" : "Copy"}
    </button>
  );
}
