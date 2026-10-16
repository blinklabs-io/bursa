import { useState } from "react";
import type { AssetInfo } from "../api/types";
import { tokenIconUrl } from "../tokenMeta";

export function AssetIcon({ unit, name, info }: { unit: string; name: string; info?: AssetInfo }) {
  const url = tokenIconUrl(info);
  const [failedUrl, setFailedUrl] = useState<string>();
  if (url && failedUrl !== url) {
    return <img className="asset-icon" src={url} alt="" loading="lazy" onError={() => setFailedUrl(url)} />;
  }
  const tone = Array.from(unit).reduce((hash, char) => (hash * 31 + char.charCodeAt(0)) >>> 0, 0) % 4;
  return <span className="asset-monogram" data-tone={tone} aria-hidden="true">{unit === "lovelace" ? "₳" : name.slice(0, 2).toUpperCase()}</span>;
}
