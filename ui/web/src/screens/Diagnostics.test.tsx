import { render, screen, fireEvent } from "@testing-library/react";
import { Diagnostics } from "./Diagnostics";
import * as hooks from "../api/hooks";
import type { AsyncState } from "../api/hooks";
import type { Diagnostics as DiagnosticsData } from "../api/types";

function baseData(): DiagnosticsData {
  return {
    node: {
      network: "preview",
      dingoVersion: "v0.66.2",
      gouroborosVersion: "v0.188.0",
      goVersion: "go1.25.8",
    },
    sync: {
      state: "syncing",
      tip: 123456,
      epoch: 812,
      blockHeight: 99000,
      latestBlockTime: "2026-07-28T11:59:30Z",
      caughtUp: false,
      secondsBehind: 45,
    },
    peers: {
      available: true,
      total: 7,
      inbound: 2,
      outbound: 5,
      duplex: 1,
      fullDuplex: 1,
      unidirectional: 4,
      configured: [{ address: "relay.example", port: 3001, source: "bootstrap" }],
    },
    listen: {
      controlSurface: "127.0.0.1:8090",
      blockfrostPort: 5556,
      utxorpcPort: 5555,
      nodeSocket: "/home/u/.bursa-wallet/preview/node.socket",
    },
    uptime: { startedAt: "2026-07-28T11:50:00Z", seconds: 630 },
    log: {
      available: true,
      path: "/home/u/.bursa-wallet/preview/logs/bursa-wallet.log",
      dir: "/home/u/.bursa-wallet/preview/logs",
    },
  };
}

function mockDiagnostics(data: DiagnosticsData | null, opts: Partial<AsyncState<DiagnosticsData>> = {}) {
  vi.spyOn(hooks, "useDiagnostics").mockReturnValue({
    data,
    error: opts.error ?? null,
    loading: opts.loading ?? false,
    refresh: vi.fn(),
    setData: vi.fn(),
  });
}

afterEach(() => {
  vi.restoreAllMocks();
  delete (window as { bursaOpenExternal?: unknown }).bursaOpenExternal;
});

test("renders sync, network, peers, ports and logs from the report", () => {
  mockDiagnostics(baseData());
  render(<Diagnostics />);

  // Sync
  expect(screen.getByText("syncing")).toBeInTheDocument();
  expect(screen.getByText("123,456")).toBeInTheDocument(); // tip slot
  expect(screen.getByText("812")).toBeInTheDocument(); // epoch
  // Network & node versions
  expect(screen.getByText("v0.66.2")).toBeInTheDocument();
  expect(screen.getByText("v0.188.0")).toBeInTheDocument();
  // Peers counts + configured table
  expect(screen.getByText("relay.example")).toBeInTheDocument();
  expect(screen.getByText("bootstrap")).toBeInTheDocument();
  // Ports
  expect(screen.getByText("127.0.0.1:8090")).toBeInTheDocument();
  expect(screen.getByText("5556")).toBeInTheDocument();
});

test("log export link points at the logs endpoint", () => {
  mockDiagnostics(baseData());
  render(<Diagnostics />);
  const link = screen.getByText(/Export logs/i).closest("a");
  expect(link).not.toBeNull();
  expect(link).toHaveAttribute("href", "/diagnostics/logs");
});

test("shows 'Open log folder' only when the webview bridge is present and calls it with a file URL", () => {
  const bridge = vi.fn();
  (window as { bursaOpenExternal?: (url: string) => void }).bursaOpenExternal = bridge;
  mockDiagnostics(baseData());
  render(<Diagnostics />);

  const btn = screen.getByRole("button", { name: /Open log folder/i });
  fireEvent.click(btn);
  expect(bridge).toHaveBeenCalledWith("file:///home/u/.bursa-wallet/preview/logs");
});

test("'Open log folder' percent-encodes spaces/special chars in the file URL", () => {
  const bridge = vi.fn();
  (window as { bursaOpenExternal?: (url: string) => void }).bursaOpenExternal = bridge;
  const data = baseData();
  data.log = {
    available: true,
    path: "/home/My Logs/bursa#1/bursa-wallet.log",
    dir: "/home/My Logs/bursa#1",
  };
  mockDiagnostics(data);
  render(<Diagnostics />);

  fireEvent.click(screen.getByRole("button", { name: /Open log folder/i }));
  expect(bridge).toHaveBeenCalledWith("file:///home/My%20Logs/bursa%231");
});

test("hides 'Open log folder' when no webview bridge is present", () => {
  mockDiagnostics(baseData());
  render(<Diagnostics />);
  expect(screen.queryByRole("button", { name: /Open log folder/i })).toBeNull();
});

test("peers panel notes when live counts are unavailable", () => {
  const data = baseData();
  data.peers.available = false;
  mockDiagnostics(data);
  render(<Diagnostics />);
  expect(screen.getByText(/Live connection counts are unavailable/i)).toBeInTheDocument();
});

test("log export is hidden when no log file is available", () => {
  const data = baseData();
  data.log = { available: false };
  mockDiagnostics(data);
  render(<Diagnostics />);
  expect(screen.queryByText(/Export logs/i)).toBeNull();
  expect(screen.getByText(/Log export is unavailable/i)).toBeInTheDocument();
});

test("shows a loading state before the first report arrives", () => {
  mockDiagnostics(null, { loading: true });
  render(<Diagnostics />);
  expect(screen.getByText(/Loading node diagnostics/i)).toBeInTheDocument();
});
