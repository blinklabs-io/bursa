import { act, render, screen, fireEvent, waitFor } from "@testing-library/react";
import type { WalletView } from "../api/types";
import { Button } from "./Button";
import { StatusPill } from "./StatusPill";
import { CopyButton } from "./CopyButton";
import { SyncBanner } from "./SyncBanner";
import { MobileNav } from "./MobileNav";

type MobileNavProps = Parameters<typeof MobileNav>[0];

const mobileWallet: WalletView = {
  id: "w1",
  name: "Main",
  network: "preview",
  stake_address: "stake_test1abc",
  addresses: ["addr_test1abc"],
  active: true,
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
  expect(screen.getByRole("button", { name: /Main/i })).toHaveFocus();

  fireEvent.keyDown(document, { key: "Escape" });

  await waitFor(() => expect(menuButton).toHaveFocus());
  expect(document.body.style.overflow).toBe("auto");
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

  expect(screen.getByRole("button", { name: /close menu/i })).toHaveAttribute(
    "aria-expanded",
    "true",
  );
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
  expect(screen.getByRole("button", { name: /close menu/i })).toHaveAttribute(
    "aria-expanded",
    "true",
  );

  rerender(<MobileNav {...props} lockError="network error" />);

  expect(screen.getByRole("alert")).toHaveTextContent("network error");
});
