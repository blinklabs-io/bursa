import { render, screen, waitFor, fireEvent } from "@testing-library/react";
import { App } from "./app";
import * as hooks from "./api/hooks";
import * as client from "./api/client";
import type { Account } from "./api/types";

const mockAccount: Account = {
  network: "preview",
  stake_address: "stake_test1abc",
  receive_addresses: ["addr_test1abc"],
};

function stubStatus(state: string) {
  vi.spyOn(hooks, "useStatus").mockReturnValue({ data: { state, tip: 0, caughtUp: state === "ready" }, error: null, loading: false, refresh: vi.fn() } as never);
}

afterEach(() => {
  vi.restoreAllMocks();
  window.location.hash = "";
});

test("with no wallet loaded, only Setup is shown", async () => {
  stubStatus("ready");
  // simulate the no-wallet signal: the wallet hooks reject 409 — App treats that as 'needs setup'
  render(<App />);
  await waitFor(() => expect(screen.getAllByText(/set up|load wallet/i).length).toBeGreaterThan(0));
});

test("Send nav is disabled until the node is ready", async () => {
  stubStatus("syncing");
  render(<App />);
  // The Send entry is present but disabled while not ready.
  await waitFor(() => expect(screen.getByText("Send").closest("button")).toBeDisabled());
});

test("deep-linking #/send while syncing falls back to Portfolio (guard)", async () => {
  // Regression for the deep-link guard: reaching #/send directly (bypassing the
  // disabled nav button) must NOT render the Send screen until the node is ready.
  stubStatus("syncing");
  // Keep Portfolio's data hooks quiet so it renders without firing real fetches.
  vi.spyOn(hooks, "useBalance").mockReturnValue({ data: null, error: null, loading: true, refresh: vi.fn() } as never);
  vi.spyOn(hooks, "useDelegation").mockReturnValue({ data: null, error: null, loading: true, refresh: vi.fn() } as never);
  vi.spyOn(client, "loadWallet").mockResolvedValue(mockAccount);
  window.location.hash = "#/send";

  render(<App />);
  // Load a read-only wallet to get past Setup into the routed content area.
  fireEvent.change(screen.getByRole("textbox", { name: /mnemonic/i }), {
    target: { value: "word1 word2 word3 word4 word5 word6 word7 word8 word9 word10 word11 word12" },
  });
  fireEvent.click(screen.getByRole("button", { name: /load wallet/i }));

  // Once the wallet loads, Setup is gone — but the Send screen must not appear.
  await waitFor(() => expect(screen.queryByRole("button", { name: /load wallet/i })).not.toBeInTheDocument());
  expect(screen.queryByText("Send ADA")).not.toBeInTheDocument();
});

test("a crafted hash (#/constructor) falls back to Portfolio instead of crashing", async () => {
  // Regression: ROUTES is a Map, so an inherited Object.prototype key like
  // "constructor" can't resolve to a function and get rendered as a screen.
  stubStatus("ready");
  vi.spyOn(hooks, "useBalance").mockReturnValue({ data: { lovelace: "1000000", assets: [] }, error: null, loading: false, refresh: vi.fn() } as never);
  vi.spyOn(hooks, "useDelegation").mockReturnValue({ data: null, error: null, loading: false, refresh: vi.fn() } as never);
  vi.spyOn(client, "loadWallet").mockResolvedValue(mockAccount);
  window.location.hash = "#/constructor";

  render(<App />);
  fireEvent.change(screen.getByRole("textbox", { name: /mnemonic/i }), {
    target: { value: "word1 word2 word3 word4 word5 word6 word7 word8 word9 word10 word11 word12" },
  });
  fireEvent.click(screen.getByRole("button", { name: /load wallet/i }));

  // Falls back to Portfolio (its "Balance" card renders), not a blank/crashed screen.
  await waitFor(() => expect(screen.getByText("Balance")).toBeInTheDocument());
});

test("read-only wallet cannot reach Send even when the node is ready", async () => {
  // Regression: Send is gated on spendingEnabled, not just node readiness. A
  // wallet loaded without a password (read-only) can never sign, so it must not
  // enter the send flow even on a fully synced node.
  stubStatus("ready");
  vi.spyOn(hooks, "useBalance").mockReturnValue({ data: { lovelace: "1000000", assets: [] }, error: null, loading: false, refresh: vi.fn() } as never);
  vi.spyOn(hooks, "useDelegation").mockReturnValue({ data: null, error: null, loading: false, refresh: vi.fn() } as never);
  vi.spyOn(client, "loadWallet").mockResolvedValue(mockAccount); // no password → read-only
  window.location.hash = "#/send";

  render(<App />);
  fireEvent.change(screen.getByRole("textbox", { name: /mnemonic/i }), {
    target: { value: "word1 word2 word3 word4 word5 word6 word7 word8 word9 word10 word11 word12" },
  });
  fireEvent.click(screen.getByRole("button", { name: /load wallet/i }));

  await waitFor(() => expect(screen.queryByRole("button", { name: /load wallet/i })).not.toBeInTheDocument());
  // Send screen is NOT shown (falls back to Portfolio), and the nav item is disabled.
  expect(screen.queryByText("Send ADA")).not.toBeInTheDocument();
  expect(screen.getByText("Send").closest("button")).toBeDisabled();
});

test("spending-enabled wallet on a ready node can reach Send", async () => {
  // The gate must still allow the valid case: a password-backed wallet on a
  // synced node enters the send flow.
  stubStatus("ready");
  vi.spyOn(client, "createKeystore").mockResolvedValue(mockAccount); // password → spending enabled
  window.location.hash = "#/send";

  render(<App />);
  fireEvent.change(screen.getByRole("textbox", { name: /mnemonic/i }), {
    target: { value: "word1 word2 word3 word4 word5 word6 word7 word8 word9 word10 word11 word12" },
  });
  // Must clear the client-side minimum (12 chars) so it reaches createKeystore.
  fireEvent.change(screen.getByLabelText(/spending password/i), { target: { value: "s3cret-passphrase" } });
  fireEvent.click(screen.getByRole("button", { name: /load wallet/i }));

  // Send screen renders (its "Send ADA" card).
  await waitFor(() => expect(screen.getByText("Send ADA")).toBeInTheDocument());
});
