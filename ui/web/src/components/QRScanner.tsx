import { useEffect, useRef, useState } from "react";
import type { KeystoneScannedUR } from "../hw/types";

interface QRScannerProps {
  /** Called once a complete Uniform Resource has been decoded from the camera. */
  onResult: (ur: KeystoneScannedUR) => void;
  /** Called if the camera cannot be opened or a fatal decode error occurs. */
  onError?: (message: string) => void;
}

// A ZXing control handle we can stop; typed loosely so we don't pull the SDK's
// types into the initial bundle (the SDK itself is dynamically imported below).
interface ScannerControls {
  stop: () => void;
}

// Lazily install a global `Buffer`, which @ngraveio/bc-ur relies on but browsers
// do not provide. Kept local so the `buffer` shim rides this code-split chunk.
async function ensureBuffer(): Promise<void> {
  const g = globalThis as unknown as { Buffer?: unknown };
  if (typeof g.Buffer === "undefined") {
    const mod = await import("buffer");
    g.Buffer = mod.Buffer;
  }
}

function toHex(bytes: Uint8Array): string {
  let out = "";
  for (const b of bytes) out += b.toString(16).padStart(2, "0");
  return out;
}

/**
 * Webcam QR scanner that assembles a (possibly animated / multi-part) Uniform
 * Resource and resolves it as {type, cborHex}. Both the ZXing camera reader and
 * the bc-ur decoder are dynamically imported so they stay OUT of the initial
 * bundle — this component is only ever mounted inside a Keystone QR flow.
 *
 * Camera access is local (getUserMedia); nothing is sent over the network.
 */
export function QRScanner({ onResult, onError }: QRScannerProps) {
  const videoRef = useRef<HTMLVideoElement>(null);
  const [progress, setProgress] = useState<number>(0);

  useEffect(() => {
    let controls: ScannerControls | null = null;
    let cancelled = false;
    let done = false;

    (async () => {
      try {
        await ensureBuffer();
        const [{ BrowserQRCodeReader }, { URDecoder }] = await Promise.all([
          import("@zxing/browser"),
          import("@ngraveio/bc-ur"),
        ]);
        if (cancelled) return;

        const decoder = new URDecoder();
        const reader = new BrowserQRCodeReader();

        controls = await reader.decodeFromVideoDevice(
          undefined,
          videoRef.current ?? undefined,
          (result) => {
            if (done || !result) return;
            const text = result.getText().trim();
            if (!text.toLowerCase().startsWith("ur:")) return;
            try {
              decoder.receivePart(text);
            } catch {
              // A stray/foreign QR that isn't a valid UR part — ignore and keep
              // scanning rather than aborting the whole session.
              return;
            }
            setProgress(Math.round(decoder.getProgress() * 100));
            if (decoder.isComplete()) {
              done = true;
              controls?.stop();
              if (!decoder.isSuccess()) {
                onError?.(decoder.resultError() || "Failed to decode the scanned QR.");
                return;
              }
              const ur = decoder.resultUR();
              onResult({ type: ur.type, cborHex: toHex(new Uint8Array(ur.cbor)) });
            }
          },
        );
        if (cancelled) controls?.stop();
      } catch (err) {
        if (cancelled) return;
        const message =
          err instanceof Error
            ? err.name === "NotAllowedError"
              ? "Camera access was denied. Allow camera access to scan the Keystone reply."
              : err.message
            : "Could not open the camera.";
        onError?.(message);
      }
    })();

    return () => {
      cancelled = true;
      controls?.stop();
    };
    // onResult/onError are stable for the modal's lifetime; deliberately run once.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  return (
    <div className="qr-scanner">
      {/* muted + playsInline so mobile browsers autoplay the preview inline. */}
      <video ref={videoRef} className="qr-scanner-video" muted playsInline aria-label="Camera preview" />
      <p className="helper-text" role="status" aria-live="polite">
        Point the camera at the Keystone&apos;s QR. {progress > 0 ? `Reading… ${progress}%` : "Scanning…"}
      </p>
    </div>
  );
}
