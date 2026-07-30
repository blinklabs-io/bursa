import { Card } from "../components/Card";
import { Table } from "../components/Table";
import { StatusPill, type Tone } from "../components/StatusPill";
import { CopyButton } from "../components/CopyButton";
import { useDiagnostics } from "../api/hooks";
import { diagnosticsLogsUrl } from "../api/client";
import type { DiagnosticsSync, NodeState } from "../api/types";

// Node diagnostics: a live, node-local view of the embedded node and this
// wallet process. Everything shown comes from the node/supervisor/process — no
// external calls — so there is no consent gate. Live-polls via useDiagnostics.

const STATE_TONE: Record<NodeState, Tone> = {
  ready: "ok",
  syncing: "warn",
  bootstrapping: "warn",
  starting: "warn",
  stopped: "muted",
  error: "error",
};

function fmtUptime(seconds: number): string {
  if (!isFinite(seconds) || seconds < 0) return "—";
  const d = Math.floor(seconds / 86400);
  const h = Math.floor((seconds % 86400) / 3600);
  const m = Math.floor((seconds % 3600) / 60);
  const s = Math.floor(seconds % 60);
  const parts: string[] = [];
  if (d) parts.push(`${d}d`);
  if (h) parts.push(`${h}h`);
  if (m) parts.push(`${m}m`);
  if (!d && !h) parts.push(`${s}s`);
  return parts.join(" ");
}

function fmtBehind(sync: DiagnosticsSync): string {
  if (sync.caughtUp) return "at the chain tip";
  if (sync.secondsBehind == null) return "—";
  return `${fmtUptime(sync.secondsBehind)} behind`;
}

function fmtInt(n?: number): string {
  return n == null ? "—" : n.toLocaleString();
}

// Build a correctly percent-encoded file:// URL for an absolute filesystem
// path so spaces and other special characters survive the JS→Go bridge and a
// POSIX path yields the canonical file:///… (not file:////…). The Go side
// (resolveOpenTarget) percent-decodes it and normalizes Windows drive paths.
export function pathToFileUrl(path: string): string {
  // Normalize Windows separators, then ensure a single leading slash so both
  // "/var/log" and "C:/Users/…" become file:///…
  const normalized = path.replace(/\\/g, "/").replace(/^\/+/, "");
  const encoded = normalized.split("/").map(encodeURIComponent).join("/");
  return `file:///${encoded}`;
}

// A definition-list row grid, reusing the sync-stats styling used elsewhere.
function Stats({ items }: { items: [string, React.ReactNode][] }) {
  return (
    <dl className="sync-stats">
      {items.map(([label, value]) => (
        <div key={label}>
          <dt>{label}</dt>
          <dd>{value}</dd>
        </div>
      ))}
    </dl>
  );
}

export function Diagnostics() {
  const { data, error, loading } = useDiagnostics();

  if (loading && !data) {
    return (
      <Card title="Diagnostics">
        <p className="helper-text">Loading node diagnostics…</p>
      </Card>
    );
  }
  if (!data) {
    return (
      <Card title="Diagnostics">
        <p className="error-text" role="alert">
          {error?.message || "Could not load diagnostics"}
        </p>
      </Card>
    );
  }

  const { node, sync, peers, listen, uptime, log } = data;
  const canOpenFolder =
    typeof window.bursaOpenExternal === "function" && log.available && !!log.dir;

  return (
    <div className="diagnostics">
      <header className="sync-head">
        <h1 className="sync-title">Diagnostics</h1>
        <p className="helper-text">
          Live status of your embedded node and this wallet. All data is local
          to your machine.
        </p>
      </header>

      <Card title="Sync">
        <p>
          <StatusPill tone={STATE_TONE[sync.state] ?? "muted"}>{sync.state}</StatusPill>
        </p>
        {sync.state === "bootstrapping" && sync.bootstrapPercent != null && (
          <p className="helper-text">
            Bootstrap {sync.bootstrapPhase ? `(${sync.bootstrapPhase}) ` : ""}
            {sync.bootstrapPercent.toFixed(1)}%
          </p>
        )}
        {sync.error && (
          <p className="error-text" role="alert">
            {sync.error}
          </p>
        )}
        <Stats
          items={[
            ["Block slot", sync.tip > 0 ? fmtInt(sync.tip) : "—"],
            ["Epoch", fmtInt(sync.epoch)],
            ["Block height", fmtInt(sync.blockHeight)],
            [
              "Latest block",
              sync.latestBlockTime
                ? new Date(sync.latestBlockTime).toLocaleString()
                : "—",
            ],
            ["Chain lag", fmtBehind(sync)],
          ]}
        />
      </Card>

      <Card title="Network & Node">
        <Stats
          items={[
            ["Network", node.network || "—"],
            ["Dingo", node.dingoVersion || "unknown"],
            ["gouroboros", node.gouroborosVersion || "unknown"],
            ["Go runtime", node.goVersion || "unknown"],
          ]}
        />
      </Card>

      <Card title="Peers">
        {peers.available ? (
          <Stats
            items={[
              ["Connections", fmtInt(peers.total)],
              ["Inbound", fmtInt(peers.inbound)],
              ["Outbound", fmtInt(peers.outbound)],
              ["Duplex", fmtInt(peers.duplex)],
              ["Full duplex", fmtInt(peers.fullDuplex)],
              ["Unidirectional", fmtInt(peers.unidirectional)],
            ]}
          />
        ) : (
          <p className="helper-text">
            Live connection counts are unavailable until the node is running.
          </p>
        )}
        <h3>Configured peers</h3>
        <p className="helper-text">
          Outbound peers your node is configured to dial (from its topology).
          This is the configured set, not a live-connection list — the embedded
          node does not expose per-peer connection detail.
        </p>
        {peers.configured.length > 0 ? (
          <Table
            columns={[
              { key: "address", label: "Address" },
              { key: "port", label: "Port" },
              { key: "source", label: "Source" },
            ]}
            rows={peers.configured.map((p) => ({
              address: p.address,
              port: p.port,
              source: p.source,
            }))}
          />
        ) : (
          <p className="helper-text">No configured peers reported yet.</p>
        )}
      </Card>

      <Card title="Ports & Uptime">
        <Stats
          items={[
            ["Control surface", listen.controlSurface || "—"],
            ["Blockfrost port", listen.blockfrostPort || "—"],
            ["UTxO-RPC port", listen.utxorpcPort || "—"],
            [
              "Node socket",
              listen.nodeSocket ? (
                <span className="mono">{listen.nodeSocket}</span>
              ) : (
                "—"
              ),
            ],
            [
              "Started",
              uptime.startedAt ? new Date(uptime.startedAt).toLocaleString() : "—",
            ],
            ["Uptime", fmtUptime(uptime.seconds)],
          ]}
        />
      </Card>

      <Card title="Logs">
        {log.available ? (
          <>
            <p className="helper-text">
              Log file: <span className="mono">{log.path}</span>
              {log.path && (
                <>
                  {" "}
                  <CopyButton value={log.path} aria-label="Copy log path" />
                </>
              )}
            </p>
            <div className="preview-actions">
              {/* Direct download of the zipped log(s). A plain download anchor
                  works in the browser build; the webview build offers "Open log
                  folder" below instead (its downloads are not surfaced). */}
              <a className="btn ghost" href={diagnosticsLogsUrl()} download>
                Export logs (.zip)
              </a>
              {canOpenFolder && (
                <button
                  type="button"
                  className="btn ghost"
                  onClick={() =>
                    log.dir && window.bursaOpenExternal?.(pathToFileUrl(log.dir))
                  }
                >
                  Open log folder
                </button>
              )}
            </div>
          </>
        ) : (
          <p className="helper-text">
            Log export is unavailable (this build is not writing logs to a file).
          </p>
        )}
      </Card>
    </div>
  );
}
