interface DownloadButtonProps {
  // The text content to download (e.g. CBOR hex). Mutually exclusive with
  // getValue — use this form when the value is already computed and cheap.
  value?: string;
  // Lazily produces the text content on click. Use this form when computing
  // the value eagerly on every render would be wasteful or unsafe (e.g. it
  // reads fields that may be absent until the export is actually requested).
  getValue?: () => string;
  // Suggested file name for the download.
  filename: string;
  label?: string;
}

// DownloadButton offers a string payload as a downloadable text file. It is used
// to carry air-gap artifacts (unsigned tx / witness CBOR) to a separate machine
// where copy/paste across an air gap is impractical.
export function DownloadButton({ value, getValue, filename, label = "Download" }: DownloadButtonProps) {
  function handleClick() {
    const content = getValue ? getValue() : (value ?? "");
    const blob = new Blob([content], { type: "text/plain" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    setTimeout(() => URL.revokeObjectURL(url), 100);
  }

  return (
    <button type="button" className="btn ghost" onClick={handleClick} disabled={!getValue && !value}>
      {label}
    </button>
  );
}
