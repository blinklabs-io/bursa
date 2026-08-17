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
  error: Error | null;
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
  state: State = { error: null };

  static getDerivedStateFromError(error: Error): State {
    return { error };
  }

  componentDidUpdate(prev: Props) {
    // A new resetKey means the user navigated; give the subtree a clean try
    // rather than pinning them to the failed screen.
    if (this.state.error !== null && prev.resetKey !== this.props.resetKey) {
      this.setState({ error: null });
    }
  }

  componentDidCatch(error: Error, info: ErrorInfo) {
    console.error("Unhandled error in", this.props.label ?? "the wallet UI", error, info.componentStack);
  }

  render() {
    const { error } = this.state;
    if (error === null) return this.props.children;

    return (
      <div className="card error-boundary" role="alert">
        <h2>Something went wrong</h2>
        <p>
          {this.props.label
            ? `The ${this.props.label} screen could not be displayed.`
            : "This screen could not be displayed."}{" "}
          Your wallet and funds are unaffected — nothing was submitted.
        </p>
        <p className="helper-text">
          Move to another screen to carry on, or reload to start fresh. If it
          keeps happening, the details below help us fix it.
        </p>
        <pre className="error-detail">{error.message}</pre>
        <div className="preview-actions">
          <button
            type="button"
            className="btn primary"
            onClick={() => this.setState({ error: null })}
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
