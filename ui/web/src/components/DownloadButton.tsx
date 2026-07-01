interface DownloadButtonProps {
  // The text content to download (e.g. CBOR hex).
  value: string;
  // Suggested file name for the download.
  filename: string;
  label?: string;
}

// DownloadButton offers a string payload as a downloadable text file. It is used
// to carry air-gap artifacts (unsigned tx / witness CBOR) to a separate machine
// where copy/paste across an air gap is impractical.
export function DownloadButton({ value, filename, label = "Download" }: DownloadButtonProps) {
  function handleClick() {
    const blob = new Blob([value], { type: "text/plain" });
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
    <button type="button" className="btn ghost" onClick={handleClick} disabled={!value}>
      {label}
    </button>
  );
}
