import { Component } from "react";
import type { ErrorInfo, ReactNode } from "react";

interface Props {
  children: ReactNode;
  // Identifies the region that failed, so the message can say what broke
  // rather than implying the whole wallet is gone.
  label?: string;
  // Bumping this remounts the boundary's subtree, clearing a caught error.
  // The app passes the current route so navigating away recovers.
  resetKey?: string;
}

interface State {
  // Normalised to a string: a child may throw a non-Error (a string, null,
  // even undefined), and reading .message off that in the fallback would throw
  // again — restoring exactly the blank page this exists to prevent.
  message: string | null;
  // The resetKey in force when the error was captured, so navigation clears
  // only errors that predate it.
  capturedAt: string | undefined;
}

/**
 * Catches a render-time throw and shows a recoverable panel instead of an
 * empty document.
 *
 * Without this, one bad field in one API response unmounts the entire React
 * tree and the wallet becomes a blank white page with no way back except a
 * reload — with the vault still unlocked and no indication of what happened.
 * That is a poor failure mode for any app and an alarming one for a wallet.
 *
 * The node is the source of truth here and its responses are not part of this
 * codebase, so a field arriving absent or in an unexpected shape is a case to
 * survive, not to assume away.
 */
export class ErrorBoundary extends Component<Props, State> {
  state: State = { message: null, capturedAt: undefined };

  static getDerivedStateFromError(error: unknown): State {
    const message =
      error instanceof Error
        ? error.message
        : typeof error === "string" && error !== ""
          ? error
          : "An unexpected error occurred.";
    // capturedAt is filled in by componentDidCatch, which has access to props.
    return { message: message || "An unexpected error occurred.", capturedAt: undefined };
  }

  componentDidUpdate(prev: Props) {
    if (this.state.message === null) return;
    if (prev.resetKey === this.props.resetKey) return;
    // A new resetKey means the user navigated; give the subtree a clean try
    // rather than pinning them to the failed screen. Only clear an error
    // captured under an EARLIER key though: if the destination throws during
    // the same commit, its fresh error arrives with the new key and clearing it
    // would remount, throw again, and log twice before settling.
    if (this.state.capturedAt !== this.props.resetKey) {
      this.setState({ message: null, capturedAt: undefined });
    }
  }

  componentDidCatch(error: unknown, info: ErrorInfo) {
    this.setState({ capturedAt: this.props.resetKey });
    console.error("Unhandled error in", this.props.label ?? "the wallet UI", error, info.componentStack);
  }

  render() {
    const { message } = this.state;
    if (message === null) return this.props.children;

    return (
      <div className="card error-boundary" role="alert">
        <h2>Something went wrong</h2>
        <p>
          {this.props.label
            ? `The ${this.props.label} screen could not be displayed.`
            : "This screen could not be displayed."}{" "}
          Your keys are safe — this is a display fault, not a change to your
          wallet.
        </p>
        <p className="helper-text">
          If you had just submitted something, this does not tell you whether it
          went through: check Activity before trying again, so you do not send
          twice. Otherwise, move to another screen to carry on, or reload.
        </p>
        <pre className="error-detail">{message}</pre>
        <div className="preview-actions">
          <button
            type="button"
            className="btn primary"
            onClick={() => this.setState({ message: null, capturedAt: undefined })}
          >
            Try again
          </button>
          <button
            type="button"
            className="btn ghost"
            onClick={() => window.location.reload()}
          >
            Reload
          </button>
        </div>
      </div>
    );
  }
}
