import { useState } from "react";

interface CopyButtonProps {
  value: string;
}

export function CopyButton({ value }: CopyButtonProps) {
  const [copied, setCopied] = useState(false);

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
    <button type="button" className="btn ghost" onClick={handleClick}>
      {copied ? "Copied" : "Copy"}
    </button>
  );
}
