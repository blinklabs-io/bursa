import { useMemo, useRef, useState } from "react";
import type { ReactNode } from "react";
import type { KeystoneQRBridge, KeystoneScannedUR } from "../hw/types";
import { Button } from "./Button";
import { AnimatedQR } from "./AnimatedQR";
import { QRScanner } from "./QRScanner";

type Phase = "idle" | "display" | "display-armed" | "scan";

interface KeystoneQRBridgeHandle {
  /** The bridge to hand to connectKeystone/connectDevice("keystone", …). */
  bridge: KeystoneQRBridge;
  /** The modal to render in the screen; `null` when no flow is active. */
  element: ReactNode;
}

/**
 * Bridge the Keystone signer's imperative QR exchange to a React modal.
 *
 * The signer calls `displayRequest(fragments)` (animated request QR) and then
 * awaits `scanResponse()` (webcam reply). This hook renders those two steps as a
 * modal and resolves the promise when a complete UR is scanned. Everything is
 * LOCAL — the animated QR is paper/screen and the scanner is the local camera;
 * no network is contacted, so there is deliberately no consent gate here.
 */
export function useKeystoneQRBridge(): KeystoneQRBridgeHandle {
  const [phase, setPhase] = useState<Phase>("idle");
  const [fragments, setFragments] = useState<string[]>([]);
  const [error, setError] = useState<string | null>(null);

  const phaseRef = useRef<Phase>("idle");
  const resolverRef = useRef<{
    resolve: (ur: KeystoneScannedUR) => void;
    reject: (err: Error) => void;
  } | null>(null);

  function goto(next: Phase) {
    phaseRef.current = next;
    setPhase(next);
  }

  const bridge = useMemo<KeystoneQRBridge>(
    () => ({
      displayRequest(frags: string[]) {
        setError(null);
        setFragments(frags);
        goto("display");
      },
      scanResponse() {
        return new Promise<KeystoneScannedUR>((resolve, reject) => {
          resolverRef.current = { resolve, reject };
          // If a request QR is already showing, keep it up and let the user
          // advance to the camera when they've scanned it into the device;
          // otherwise (account-sync) go straight to the camera.
          goto(phaseRef.current === "display" ? "display-armed" : "scan");
        });
      },
      close() {
        resolverRef.current = null;
        setFragments([]);
        setError(null);
        goto("idle");
      },
    }),
    [],
  );

  function cancel() {
    resolverRef.current?.reject(new Error("Keystone QR flow cancelled"));
    bridge.close();
  }

  let body: ReactNode = null;
  if (phase === "display" || phase === "display-armed") {
    body = (
      <>
        <p className="helper-text">
          Scan this animated code with your Keystone, review and approve the transaction on the
          device, then continue to capture its signature.
        </p>
        <AnimatedQR fragments={fragments} />
        {phase === "display-armed" && (
          <Button onClick={() => goto("scan")}>Scan Keystone&apos;s signature</Button>
        )}
      </>
    );
  } else if (phase === "scan") {
    body = (
      <>
        <QRScanner
          onResult={(ur) => resolverRef.current?.resolve(ur)}
          onError={(message) => setError(message)}
        />
      </>
    );
  }

  const element =
    phase === "idle" ? null : (
      <div className="drawer-overlay" onClick={cancel}>
        <div
          className="qr-modal"
          role="dialog"
          aria-modal="true"
          aria-label="Keystone QR"
          onClick={(e) => e.stopPropagation()}
        >
          {body}
          {error && (
            <p role="alert" className="error-text">
              {error}
            </p>
          )}
          <Button variant="ghost" onClick={cancel}>
            Cancel
          </Button>
        </div>
      </div>
    );

  return { bridge, element };
}
