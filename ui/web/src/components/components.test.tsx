import { act, render, screen, fireEvent, waitFor, within, createEvent } from "@testing-library/react";
import type { WalletView } from "../api/types";
import { Button } from "./Button";
import { StatusPill } from "./StatusPill";
import { CopyButton } from "./CopyButton";
import { SyncBanner } from "./SyncBanner";
import { MobileNav } from "./MobileNav";
import { ExplorerLink } from "./ExplorerLink";
import { MultiSigProgress } from "./MultiSigProgress";

type MobileNavProps = Parameters<typeof MobileNav>[0];

const mobileWallet: WalletView = {
  id: "w1",
  name: "Main",
  network: "preview",
  stake_address: "stake_test1abc",
  addresses: ["addr_test1abc"],
  active: true,
  type: "full",
};

function renderMobileNav(overrides: Partial<MobileNavProps> = {}) {
  const props: MobileNavProps = {
    status: { state: "ready", tip: 0, caughtUp: true },
    activeWallet: mobileWallet,
    wallets: [mobileWallet],
    activeId: mobileWallet.id,
    lockError: null,
    navItems: [
      { key: "portfolio", label: "Portfolio", active: true },
      { key: "receive", label: "Receive" },
    ],
    onActivated: vi.fn(),
    onAddWallet: vi.fn(),
    onLock: vi.fn(),
    onNavigate: vi.fn(),
    ...overrides,
  };

  return { ...render(<MobileNav {...props} />), props };
}

const originalClipboard = navigator.clipboard;
const originalMatchMedia = window.matchMedia;
afterEach(() => {
  // Restore the global clipboard the CopyButton test stubs, to avoid leakage.
  Object.assign(navigator, { clipboard: originalClipboard });
  Object.defineProperty(window, "matchMedia", {
    configurable: true,
    writable: true,
    value: originalMatchMedia,
  });
  document.body.style.overflow = "";
  // The real build never has this bridge in a browser/test environment; undo
  // whatever an ExplorerLink test above stubbed in, to avoid leakage.
  delete (window as { bursaOpenExternal?: unknown }).bursaOpenExternal;
});

test("Button fires onClick", () => {
  let clicked = false;
  render(<Button onClick={() => (clicked = true)}>Go</Button>);
  fireEvent.click(screen.getByText("Go"));
  expect(clicked).toBe(true);
});

test("StatusPill shows its tone + label", () => {
  render(<StatusPill tone="ok">ready</StatusPill>);
  expect(screen.getByText("ready")).toBeInTheDocument();
});

test("CopyButton copies its value and shows feedback on success", async () => {
  const writeText = vi.fn().mockResolvedValue(undefined);
  Object.assign(navigator, { clipboard: { writeText } });
  render(<CopyButton value="addr_test1abc" />);
  fireEvent.click(screen.getByRole("button"));
  expect(writeText).toHaveBeenCalledWith("addr_test1abc");
  // "Copied" appears only after the async write resolves.
  expect(await screen.findByText("Copied")).toBeInTheDocument();
});

test("SyncBanner shows error detail ahead of retained bootstrap diagnostics", () => {
  render(
    <SyncBanner
      status={{
        state: "error",
        tip: 0,
        caughtUp: false,
        error: "mithril bootstrap: download failed",
        bootstrap: { phase: "bootstrap", percent: 40 },
      }}
    />,
  );
  expect(screen.getByText("error")).toBeInTheDocument();
  expect(screen.getByText("mithril bootstrap: download failed")).toBeInTheDocument();
  expect(screen.queryByText("bootstrap 40.0%")).not.toBeInTheDocument();
});

test("MobileNav locks page scroll and restores focus when dismissed", async () => {
  document.body.style.overflow = "auto";
  renderMobileNav();
  const menuButton = screen.getByRole("button", { name: /open menu/i });

  menuButton.focus();
  fireEvent.click(menuButton);

  expect(document.body.style.overflow).toBe("hidden");
  expect(screen.getByRole("button", { name: /close menu/i })).toHaveFocus();

  fireEvent.keyDown(document, { key: "Escape" });

  await waitFor(() => expect(menuButton).toHaveFocus());
  expect(document.body.style.overflow).toBe("auto");
});

test("MobileNav closes from the drawer close button", async () => {
  renderMobileNav();
  const menuButton = screen.getByRole("button", { name: /open menu/i });

  menuButton.focus();
  fireEvent.click(menuButton);

  const drawer = screen.getByRole("navigation", { name: /wallet and navigation/i });
  const closeButton = within(drawer).getByRole("button", { name: /close menu/i });

  expect(closeButton).toHaveFocus();
  fireEvent.click(closeButton);

  await waitFor(() => expect(menuButton).toHaveFocus());
  expect(screen.getByRole("button", { name: /open menu/i })).toHaveAttribute(
    "aria-expanded",
    "false",
  );
});

test("MobileNav returns focus after navigation closes the drawer", async () => {
  const onNavigate = vi.fn();
  renderMobileNav({ onNavigate });
  const menuButton = screen.getByRole("button", { name: /open menu/i });

  menuButton.focus();
  fireEvent.click(menuButton);
  fireEvent.click(screen.getByRole("button", { name: "Receive" }));

  expect(onNavigate).toHaveBeenCalledWith("receive");
  await waitFor(() => expect(menuButton).toHaveFocus());
});

test("MobileNav closes when the drawer overlay is tapped", async () => {
  const { container } = renderMobileNav();
  const menuButton = screen.getByRole("button", { name: /open menu/i });

  fireEvent.click(menuButton);
  const overlay = container.querySelector<HTMLElement>(".mobile-drawer-overlay");
  expect(overlay).not.toBeNull();
  fireEvent.click(overlay as HTMLElement);

  await waitFor(() => expect(screen.getByRole("button", { name: /open menu/i })).toBeEnabled());
});

test("MobileNav closes the drawer when the viewport switches to desktop", async () => {
  let handleMediaChange: ((event: MediaQueryListEvent) => void) | null = null;
  const desktopQuery = {
    matches: false,
    media: "(min-width: 768px)",
    onchange: null,
    addEventListener: vi.fn((type: string, callback: EventListenerOrEventListenerObject) => {
      if (type === "change" && typeof callback === "function") {
        handleMediaChange = callback as (event: MediaQueryListEvent) => void;
      }
    }),
    removeEventListener: vi.fn(),
    addListener: vi.fn(),
    removeListener: vi.fn(),
    dispatchEvent: vi.fn(),
  } as unknown as MediaQueryList;
  Object.defineProperty(window, "matchMedia", {
    configurable: true,
    writable: true,
    value: vi.fn(() => desktopQuery),
  });

  document.body.style.overflow = "auto";
  renderMobileNav();
  const menuButton = screen.getByRole("button", { name: /open menu/i });

  fireEvent.click(menuButton);

  expect(menuButton).toHaveAttribute("aria-expanded", "true");
  expect(screen.getByRole("button", { name: /close menu/i })).toBeEnabled();
  expect(document.body.style.overflow).toBe("hidden");

  act(() => {
    handleMediaChange?.({ matches: true } as MediaQueryListEvent);
  });

  await waitFor(() =>
    expect(screen.getByRole("button", { name: /open menu/i })).toHaveAttribute(
      "aria-expanded",
      "false",
    ),
  );
  expect(document.body.style.overflow).toBe("auto");
});

test("MobileNav keeps lock failures visible in the open drawer", () => {
  const onLock = vi.fn();
  const { props, rerender } = renderMobileNav({ onLock });

  fireEvent.click(screen.getByRole("button", { name: /open menu/i }));
  fireEvent.click(screen.getByRole("button", { name: /lock vault/i }));

  expect(onLock).toHaveBeenCalledTimes(1);
  expect(screen.getByRole("button", { name: /close menu/i })).toBeEnabled();

  rerender(<MobileNav {...props} lockError="network error" />);

  expect(screen.getByRole("alert")).toHaveTextContent("network error");
});

// --- ExplorerLink ---
// The wallet must never call out to a block explorer itself — this link only
// ever fires from a user click, and must open in a new, unlinked tab.

test("ExplorerLink renders an <a> with the correct href, target, and rel", () => {
  render(<ExplorerLink network="preview" kind="tx" id="deadbeef" />);
  const link = screen.getByRole("link");
  expect(link).toHaveAttribute("href", "https://preview.cardanoscan.io/transaction/deadbeef");
  expect(link).toHaveAttribute("target", "_blank");
  expect(link).toHaveAttribute("rel", expect.stringContaining("noopener"));
  expect(link).toHaveAttribute("rel", expect.stringContaining("noreferrer"));
});

test("ExplorerLink maps network + kind to the right host and path", () => {
  render(<ExplorerLink network="mainnet" kind="pool" id="pool1abc" />);
  expect(screen.getByRole("link")).toHaveAttribute(
    "href",
    "https://cardanoscan.io/pool/pool1abc",
  );
});

test("ExplorerLink has an accessible label that signals it leaves the wallet", () => {
  render(<ExplorerLink network="preprod" kind="drep" id="drep1abc" />);
  const link = screen.getByRole("link");
  expect(link.getAttribute("aria-label")?.toLowerCase()).toContain("explorer");
  expect(link).toHaveAttribute("title");
});

// The desktop build embeds a webview with no tab-strip: a plain
// `target="_blank"` click would navigate the wallet window itself. The click
// handler must always prevent the anchor's own navigation and instead open
// externally — via the webview-injected `window.bursaOpenExternal` bridge
// when present, or `window.open` otherwise (see ui_webview.go / ui_headless.go).

test("ExplorerLink opens via window.open and prevents default navigation when no webview bridge is present", () => {
  const openSpy = vi.spyOn(window, "open").mockImplementation(() => null);

  render(<ExplorerLink network="preview" kind="tx" id="deadbeef" />);
  const link = screen.getByRole("link");
  const event = createEvent.click(link);
  const preventDefault = vi.spyOn(event, "preventDefault");
  fireEvent(link, event);

  expect(preventDefault).toHaveBeenCalled();
  expect(openSpy).toHaveBeenCalledWith(
    "https://preview.cardanoscan.io/transaction/deadbeef",
    "_blank",
    "noopener,noreferrer",
  );
});

test("ExplorerLink calls the webview bursaOpenExternal bridge instead of window.open when present", () => {
  const bridge = vi.fn();
  (window as { bursaOpenExternal?: (url: string) => void }).bursaOpenExternal = bridge;
  const openSpy = vi.spyOn(window, "open").mockImplementation(() => null);

  render(<ExplorerLink network="mainnet" kind="pool" id="pool1abc" />);
  const link = screen.getByRole("link");
  const event = createEvent.click(link);
  const preventDefault = vi.spyOn(event, "preventDefault");
  fireEvent(link, event);

  expect(preventDefault).toHaveBeenCalled();
  expect(bridge).toHaveBeenCalledWith("https://cardanoscan.io/pool/pool1abc");
  expect(openSpy).not.toHaveBeenCalled();
});

test("MultiSigProgress shows K of N signed and marks signed participants", () => {
  render(
    <MultiSigProgress
      threshold={2}
      total={3}
      signedCount={1}
      participants={[
        { key_hash: "aa".repeat(28), label: "alice", signed: true },
        { key_hash: "bb".repeat(28), signed: false },
        { key_hash: "cc".repeat(28), signed: false },
      ]}
    />,
  );

  expect(screen.getByText(/1 of 2/)).toBeInTheDocument();
  expect(screen.getByText(/alice/)).toBeInTheDocument();
});

test("MultiSigProgress shows threshold-met indicator once signedCount reaches threshold", () => {
  render(<MultiSigProgress threshold={2} total={2} signedCount={2} />);

  expect(screen.getByText(/2 of 2/)).toBeInTheDocument();
  expect(screen.getByText(/threshold met/i)).toBeInTheDocument();
});
