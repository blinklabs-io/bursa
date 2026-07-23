import { useEffect, useState } from "react";
import { QRCodeSVG } from "qrcode.react";

// The QR chip uses a fixed high-contrast pair regardless of theme so it stays
// scannable by a device camera on the dark panel (mirrors Receive.tsx).
const QR_BG = "#ffffff";
const QR_FG = "#0c0f15";
const DEFAULT_SIZE = 240;

// How long each frame is shown, in milliseconds. Slow enough that a Keystone
// camera reliably captures each frame, fast enough that a multi-part animation
// completes in a few seconds.
const DEFAULT_INTERVAL_MS = 300;

interface AnimatedQRProps {
  /** UR fragment strings to cycle through as QR frames. */
  fragments: string[];
  size?: number;
  intervalMs?: number;
  title?: string;
}

/**
 * Render an animated ("fountain") QR from a list of UR fragment strings, cycling
 * one frame at a time. A single-fragment payload renders as a static QR. Purely
 * client-side (bundled `qrcode.react`) — no network round-trip.
 */
export function AnimatedQR({
  fragments,
  size = DEFAULT_SIZE,
  intervalMs = DEFAULT_INTERVAL_MS,
  title = "Transaction request QR",
}: AnimatedQRProps) {
  const [frame, setFrame] = useState(0);

  useEffect(() => {
    setFrame(0);
    if (fragments.length <= 1) return;
    const timer = setInterval(() => {
      setFrame((f) => (f + 1) % fragments.length);
    }, intervalMs);
    return () => clearInterval(timer);
  }, [fragments, intervalMs]);

  if (fragments.length === 0) return null;
  const value = fragments[Math.min(frame, fragments.length - 1)];

  return (
    <div className="qr-animated">
      <div className="receive-qr-frame">
        <QRCodeSVG
          value={value}
          size={size}
          bgColor={QR_BG}
          fgColor={QR_FG}
          level="M"
          marginSize={2}
          title={title}
        />
      </div>
      {fragments.length > 1 && (
        <p className="helper-text" aria-live="off">
          Frame {frame + 1} of {fragments.length} — hold the animation steady in front of the device.
        </p>
      )}
    </div>
  );
}
