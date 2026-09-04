import { useEffect, useRef, useState } from "react";
import type { ScannedUR } from "./types";
import { createURAssembler, DEFAULT_UR_LIMITS } from "./ur";

interface QRScannerProps {
  /** Called once a complete Uniform Resource has been decoded from the camera. */
  onResult: (ur: ScannedUR) => void;
  /** Called if the camera cannot be opened or a fatal decode error occurs. */
  onError?: (message: string) => void;
  /** Device name used in the on-screen copy (e.g. "Keystone"). */
  deviceLabel?: string;
}

// A ZXing control handle we can stop; typed loosely so we don't pull the SDK's
// types into the initial bundle (the SDK itself is dynamically imported below).
interface ScannerControls {
  stop: () => void;
}

/**
 * Webcam QR scanner that assembles a (possibly animated / multi-part) Uniform
 * Resource and resolves it as {type, cborHex}. Both the ZXing camera reader and
 * the bc-ur decoder (via the shared UR transport) are dynamically imported so
 * they stay OUT of the initial bundle — this component is only ever mounted
 * inside an air-gapped QR flow.
 *
 * Camera access is local (getUserMedia); nothing is sent over the network.
 */
export function QRScanner({ onResult, onError, deviceLabel = "device" }: QRScannerProps) {
  const videoRef = useRef<HTMLVideoElement>(null);
  const [progress, setProgress] = useState<number>(0);

  useEffect(() => {
    let controls: ScannerControls | null = null;
    let cancelled = false;
    let done = false;
    let timeout: ReturnType<typeof setTimeout> | null = null;

    const fail = (message: string) => {
      if (done) return;
      done = true;
      if (timeout !== null) clearTimeout(timeout);
      controls?.stop();
      onError?.(message);
    };

    (async () => {
      try {
        const [{ BrowserQRCodeReader }, assembler] = await Promise.all([
          import("@zxing/browser"),
          createURAssembler(),
        ]);
        if (cancelled) return;

        timeout = setTimeout(() => {
          fail("The scanned QR stream took too long to complete.");
        }, DEFAULT_UR_LIMITS.maxDurationMs);

        const reader = new BrowserQRCodeReader();

        controls = await reader.decodeFromVideoDevice(
          undefined,
          videoRef.current ?? undefined,
          (result) => {
            if (done || !result) return;
            const text = result.getText().trim();
            if (!text.toLowerCase().startsWith("ur:")) return;
            try {
              assembler.receivePart(text);
            } catch {
              if (assembler.isError()) {
                fail(assembler.error() || "The scanned QR could not be decoded.");
              }
              // A stray/foreign QR that isn't a valid UR part — ignore and keep
              // scanning rather than aborting the whole session.
              return;
            }
            setProgress(assembler.progressPercent());
            // A structurally valid but corrupt multipart stream (e.g. mismatched
            // fragment checksums) puts the decoder into a permanent error state
            // WITHOUT ever reaching isComplete(). Detect that and surface it, or
            // the UI would sit on "Scanning…" forever with no way to recover.
            if (assembler.isError()) {
              fail(
                assembler.error() ||
                  "The scanned QR could not be decoded. Restart the exchange on the device and rescan.",
              );
              return;
            }
            if (assembler.isComplete()) {
              if (!assembler.isSuccess()) {
                fail(assembler.error() || "Failed to decode the scanned QR.");
                return;
              }
              done = true;
              if (timeout !== null) clearTimeout(timeout);
              controls?.stop();
              onResult(assembler.result());
            }
          },
        );
        if (cancelled || done) controls?.stop();
      } catch (err) {
        if (cancelled || done) return;
        const message =
          err instanceof Error
            ? err.name === "NotAllowedError"
              ? `Camera access was denied. Allow camera access to scan the ${deviceLabel} reply.`
              : err.message
            : "Could not open the camera.";
        fail(message);
      }
    })();

    return () => {
      cancelled = true;
      if (timeout !== null) clearTimeout(timeout);
      controls?.stop();
    };
    // onResult/onError/deviceLabel are stable for the modal's lifetime; run once.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  return (
    <div className="qr-scanner">
      {/* muted + playsInline so mobile browsers autoplay the preview inline. */}
      <video ref={videoRef} className="qr-scanner-video" muted playsInline aria-label="Camera preview" />
      <p className="helper-text" role="status" aria-live="polite">
        Point the camera at the {deviceLabel}&apos;s QR.{" "}
        {progress > 0 ? `Reading… ${progress}%` : "Scanning…"}
      </p>
    </div>
  );
}
