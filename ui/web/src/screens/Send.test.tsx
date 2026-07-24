import { render, screen, fireEvent, waitFor } from "@testing-library/react";
import { Send } from "./Send";
import * as client from "../api/client";
import { mockContacts } from "../test/mockContacts";
import type { Preview, TxResult, HandleInfo, Contact, HardwareSignResponse } from "../api/types";
import type { HardwareSigner } from "../hw";

// Mock the hardware factory so tests don't try to open WebHID / a Trezor popup.
vi.mock("../hw", () => ({
  connectHardware: vi.fn(),
  connectDevice: vi.fn(),
}));

// Send-parity capabilities shared by the mock signers below.
const HW_CAPS = { send: true, staking: false, governance: false, multisig: false, poolReg: false };

const MOCK_PREVIEW: Preview = {
  pending_id: "pending-abc-123",
  inputs: ["utxo1#0", "utxo2#1"],
  outputs: [
    { address: "addr_test1abc", lovelace: "5000000", assets: [] },
    { address: "addr_test1xyz", lovelace: "3000000", assets: [] },
  ],
  fee: "170000",
  change: "1830000",
};

const MOCK_TX_RESULT: TxResult = {
  tx_hash: "deadbeef1234567890abcdef1234567890abcdef1234567890abcdef1234567890",
};

beforeEach(() => {
  mockContacts([]);
});

afterEach(() => {
  vi.restoreAllMocks();
});

// --- compose → preview ---

test("(a) compose→preview: buildSend called with correct lovelace and preview rendered", async () => {
  const buildSend = vi.spyOn(client, "buildSend").mockResolvedValue(MOCK_PREVIEW);

  render(<Send />);

  // Fill recipient
  const inputs = screen.getAllByRole("textbox");
  fireEvent.change(inputs[0], { target: { value: "addr_test1recipient" } });

  // Fill ADA amount
  fireEvent.change(inputs[1], { target: { value: "5" } });

  // Click Review
  fireEvent.click(screen.getByRole("button", { name: /review/i }));

  await waitFor(() => {
    expect(buildSend).toHaveBeenCalledWith({
      to: "addr_test1recipient",
      lovelace: "5000000",
    });
  });

  // Preview phase: shows inputs count
  await waitFor(() => {
    expect(screen.getByText(/2 inputs/i)).toBeInTheDocument();
  });

  // Preview shows fee and change in ADA
  expect(screen.getByText(/0.17/)).toBeInTheDocument();   // fee: 170000 lovelace = 0.17 ADA
  expect(screen.getByText(/1.83/)).toBeInTheDocument();   // change: 1830000 lovelace = 1.83 ADA
});

// --- preview → confirm (success) ---

test("(b) preview→confirm: confirmSend called with pending_id and password; tx_hash shown on success", async () => {
  vi.spyOn(client, "buildSend").mockResolvedValue(MOCK_PREVIEW);
  const confirmSend = vi.spyOn(client, "confirmSend").mockResolvedValue(MOCK_TX_RESULT);

  render(<Send />);

  // Go to preview
  const inputs = screen.getAllByRole("textbox");
  fireEvent.change(inputs[0], { target: { value: "addr_test1recipient" } });
  fireEvent.change(inputs[1], { target: { value: "5" } });
  fireEvent.click(screen.getByRole("button", { name: /review/i }));

  // Wait for preview phase
  await waitFor(() => {
    expect(screen.getByText(/2 inputs/i)).toBeInTheDocument();
  });

  // Enter password
  const passwordInput = screen.getByPlaceholderText(/spending password/i);
  fireEvent.change(passwordInput, { target: { value: "s3cr3t" } });

  // Click confirm
  fireEvent.click(screen.getByRole("button", { name: /confirm/i }));

  await waitFor(() => {
    expect(confirmSend).toHaveBeenCalledWith("pending-abc-123", "s3cr3t");
  });

  // Done phase: tx_hash shown
  await waitFor(() => {
    expect(screen.getByText(new RegExp(MOCK_TX_RESULT.tx_hash))).toBeInTheDocument();
  });

  // Done phase: "Send another" button present
  expect(screen.getByRole("button", { name: /send another/i })).toBeInTheDocument();
});

// --- error path: confirm error keeps preview ---

test("(c) confirmSend error keeps preview phase so user can retry", async () => {
  vi.spyOn(client, "buildSend").mockResolvedValue(MOCK_PREVIEW);
  const confirmSend = vi
    .spyOn(client, "confirmSend")
    .mockRejectedValue(new client.ApiError(401, "incorrect spending password"));

  render(<Send />);

  // Go to preview
  const inputs = screen.getAllByRole("textbox");
  fireEvent.change(inputs[0], { target: { value: "addr_test1recipient" } });
  fireEvent.change(inputs[1], { target: { value: "5" } });
  fireEvent.click(screen.getByRole("button", { name: /review/i }));

  await waitFor(() => {
    expect(screen.getByText(/2 inputs/i)).toBeInTheDocument();
  });

  // Enter wrong password and confirm
  const passwordInput = screen.getByPlaceholderText(/spending password/i);
  fireEvent.change(passwordInput, { target: { value: "wrong" } });
  fireEvent.click(screen.getByRole("button", { name: /confirm/i }));

  await waitFor(() => {
    expect(confirmSend).toHaveBeenCalled();
  });

  // Error shown inline
  await waitFor(() => {
    expect(screen.getByText(/incorrect spending password/i)).toBeInTheDocument();
  });

  // Still on preview phase (password input still present, not done)
  expect(screen.getByPlaceholderText(/spending password/i)).toBeInTheDocument();

  // NOT showing tx_hash
  expect(screen.queryByText(new RegExp(MOCK_TX_RESULT.tx_hash))).not.toBeInTheDocument();
});

// --- "Back" button returns to compose ---

test("(d) Back button in preview returns to compose phase", async () => {
  vi.spyOn(client, "buildSend").mockResolvedValue(MOCK_PREVIEW);

  render(<Send />);

  const inputs = screen.getAllByRole("textbox");
  fireEvent.change(inputs[0], { target: { value: "addr_test1recipient" } });
  fireEvent.change(inputs[1], { target: { value: "5" } });
  fireEvent.click(screen.getByRole("button", { name: /review/i }));

  await waitFor(() => {
    expect(screen.getByText(/2 inputs/i)).toBeInTheDocument();
  });

  fireEvent.click(screen.getByRole("button", { name: /back/i }));

  // Back on compose — Review button visible again
  expect(screen.getByRole("button", { name: /review/i })).toBeInTheDocument();
});

// --- "Send another" resets to compose ---

test("(e) 'Send another' resets to compose phase", async () => {
  vi.spyOn(client, "buildSend").mockResolvedValue(MOCK_PREVIEW);
  vi.spyOn(client, "confirmSend").mockResolvedValue(MOCK_TX_RESULT);

  render(<Send />);

  // Compose → preview → done
  const inputs = screen.getAllByRole("textbox");
  fireEvent.change(inputs[0], { target: { value: "addr_test1recipient" } });
  fireEvent.change(inputs[1], { target: { value: "5" } });
  fireEvent.click(screen.getByRole("button", { name: /review/i }));

  await waitFor(() => {
    expect(screen.getByText(/2 inputs/i)).toBeInTheDocument();
  });

  const passwordInput = screen.getByPlaceholderText(/spending password/i);
  fireEvent.change(passwordInput, { target: { value: "s3cr3t" } });
  fireEvent.click(screen.getByRole("button", { name: /confirm/i }));

  await waitFor(() => {
    expect(screen.getByRole("button", { name: /send another/i })).toBeInTheDocument();
  });

  fireEvent.click(screen.getByRole("button", { name: /send another/i }));

  // Back to compose
  expect(screen.getByRole("button", { name: /review/i })).toBeInTheDocument();

  // "Send another" clears the draft for a fresh send.
  const fresh = screen.getAllByRole("textbox");
  expect(fresh[0]).toHaveValue("");
  expect(fresh[1]).toHaveValue("");
});

// --- Back preserves the compose draft ---

test("(h) Back from preview preserves the entered recipient and amount", async () => {
  vi.spyOn(client, "buildSend").mockResolvedValue(MOCK_PREVIEW);

  render(<Send />);

  const inputs = screen.getAllByRole("textbox");
  fireEvent.change(inputs[0], { target: { value: "addr_test1recipient" } });
  fireEvent.change(inputs[1], { target: { value: "5" } });
  fireEvent.click(screen.getByRole("button", { name: /review/i }));

  await waitFor(() => {
    expect(screen.getByText(/2 inputs/i)).toBeInTheDocument();
  });

  fireEvent.click(screen.getByRole("button", { name: /back/i }));

  // Draft intact — no re-entry required.
  const back = screen.getAllByRole("textbox");
  expect(back[0]).toHaveValue("addr_test1recipient");
  expect(back[1]).toHaveValue("5");
});

// --- compose inputs locked during in-flight build ---

test("(i) compose inputs are disabled while the preview build is in flight", async () => {
  let resolveBuild: (p: Preview) => void = () => {};
  vi.spyOn(client, "buildSend").mockReturnValue(
    new Promise<Preview>((resolve) => {
      resolveBuild = resolve;
    })
  );

  render(<Send />);

  const inputs = screen.getAllByRole("textbox");
  fireEvent.change(inputs[0], { target: { value: "addr_test1recipient" } });
  fireEvent.change(inputs[1], { target: { value: "5" } });
  fireEvent.click(screen.getByRole("button", { name: /review/i }));

  // While building, recipient + amount must be locked so they can't drift from
  // the values the preview is being built for.
  await waitFor(() => {
    expect(screen.getByRole("button", { name: /building/i })).toBeDisabled();
  });
  expect(inputs[0]).toBeDisabled();
  expect(inputs[1]).toBeDisabled();

  // Resolve so the component settles into the preview phase.
  resolveBuild(MOCK_PREVIEW);
  await waitFor(() => {
    expect(screen.getByText(/2 inputs/i)).toBeInTheDocument();
  });
});

// --- export for offline signing ---

test("(j) Export for offline signing shows the unsigned tx CBOR and required signers", async () => {
  vi.spyOn(client, "buildSend").mockResolvedValue(MOCK_PREVIEW);
  const exportUnsigned = vi.spyOn(client, "exportUnsigned").mockResolvedValue({
    unsigned_tx_cbor: "84a400deadbeef",
    required_signers: ["aabbccdd"],
  });

  render(<Send />);

  const inputs = screen.getAllByRole("textbox");
  fireEvent.change(inputs[0], { target: { value: "addr_test1recipient" } });
  fireEvent.change(inputs[1], { target: { value: "5" } });
  fireEvent.click(screen.getByRole("button", { name: /review/i }));

  await waitFor(() => {
    expect(screen.getByText(/2 inputs/i)).toBeInTheDocument();
  });

  fireEvent.click(screen.getByRole("button", { name: /export for offline signing/i }));

  await waitFor(() => {
    expect(exportUnsigned).toHaveBeenCalledWith("pending-abc-123");
  });
  expect(await screen.findByText("84a400deadbeef")).toBeInTheDocument();
  expect(screen.getByText("aabbccdd")).toBeInTheDocument();
});

test("(j2) failed export retry clears a previous unsigned tx", async () => {
  vi.spyOn(client, "buildSend").mockResolvedValue(MOCK_PREVIEW);
  vi.spyOn(client, "exportUnsigned")
    .mockResolvedValueOnce({
      unsigned_tx_cbor: "84a400deadbeef",
      required_signers: ["aabbccdd"],
    })
    .mockRejectedValueOnce(new client.ApiError(400, "invalid transaction"));

  render(<Send />);

  const inputs = screen.getAllByRole("textbox");
  fireEvent.change(inputs[0], { target: { value: "addr_test1recipient" } });
  fireEvent.change(inputs[1], { target: { value: "5" } });
  fireEvent.click(screen.getByRole("button", { name: /review/i }));

  await waitFor(() => {
    expect(screen.getByText(/2 inputs/i)).toBeInTheDocument();
  });

  fireEvent.click(screen.getByRole("button", { name: /export for offline signing/i }));
  expect(await screen.findByText("84a400deadbeef")).toBeInTheDocument();

  fireEvent.click(screen.getByRole("button", { name: /export for offline signing/i }));
  expect(await screen.findByRole("alert")).toHaveTextContent(/invalid transaction/i);
  expect(screen.queryByText("84a400deadbeef")).not.toBeInTheDocument();
});

// --- invalid ADA shows error, buildSend NOT called ---

test("(f) invalid ADA amount shows error without calling buildSend", async () => {
  const buildSend = vi.spyOn(client, "buildSend");

  render(<Send />);

  const inputs = screen.getAllByRole("textbox");
  fireEvent.change(inputs[0], { target: { value: "addr_test1recipient" } });
  fireEvent.change(inputs[1], { target: { value: "abc" } });

  fireEvent.click(screen.getByRole("button", { name: /review/i }));

  // Error shown, buildSend not called
  await waitFor(() => {
    expect(screen.getByRole("alert")).toBeInTheDocument();
  });
  expect(buildSend).not.toHaveBeenCalled();
});

// --- buildSend error stays on compose ---

test("(g) buildSend error shown inline on compose phase", async () => {
  vi.spyOn(client, "buildSend").mockRejectedValue(
    new client.ApiError(400, "insufficient funds")
  );

  render(<Send />);

  const inputs = screen.getAllByRole("textbox");
  fireEvent.change(inputs[0], { target: { value: "addr_test1recipient" } });
  fireEvent.change(inputs[1], { target: { value: "1000" } });
  fireEvent.click(screen.getByRole("button", { name: /review/i }));

  await waitFor(() => {
    expect(screen.getByText(/insufficient funds/i)).toBeInTheDocument();
  });

  // Still on compose
  expect(screen.getByRole("button", { name: /review/i })).toBeInTheDocument();
});

// --- ADA Handle resolution ---

const MOCK_HANDLE: HandleInfo = { handle: "chris", address: "addr1resolvedhandle" };
const MOCK_HW_SIGN_RESP: HardwareSignResponse = {
  network: "preview",
  network_id: 0,
  include_network_id: true,
  protocol_magic: 2,
  inputs: [{ tx_hash_hex: "deadbeef", output_index: 0, path: "1852'/1815'/0'/0/0" }],
  outputs: [
    { address_hex: "60aabb", address_bech32: "addr_test1recipient", lovelace: "1000000" },
    {
      address_hex: "60ccdd",
      address_bech32: "addr_test1change",
      lovelace: "3800000",
      payment_path: "1852'/1815'/0'/0/0",
      stake_path: "1852'/1815'/0'/2/0",
    },
  ],
  fee: "170000",
  required_signers: ["aabbccdd"],
  unsigned_tx_cbor: "84a4deadbeef",
};

test("(k) $handle recipient resolves and buildSend uses the resolved address", async () => {
  const resolveHandle = vi.spyOn(client, "resolveHandle").mockResolvedValue(MOCK_HANDLE);
  const buildSend = vi.spyOn(client, "buildSend").mockResolvedValue(MOCK_PREVIEW);

  render(<Send />);

  const inputs = screen.getAllByRole("textbox");
  fireEvent.change(inputs[0], { target: { value: "$chris" } });
  fireEvent.change(inputs[1], { target: { value: "5" } });

  await waitFor(() => {
    expect(resolveHandle).toHaveBeenCalledWith("$chris");
  });

  await waitFor(() => {
    expect(screen.getByText(/resolved by your node/i)).toBeInTheDocument();
  });
  expect(screen.getByText(/addr1resolvedhandle/)).toBeInTheDocument();

  fireEvent.click(screen.getByRole("button", { name: /review/i }));

  await waitFor(() => {
    expect(buildSend).toHaveBeenCalledWith({
      to: "addr1resolvedhandle",
      lovelace: "5000000",
    });
  });
});

test("(l) unresolved $handle shows 'Handle not found' and disables Review", async () => {
  vi.spyOn(client, "resolveHandle").mockRejectedValue(new client.ApiError(404, "not found by your node"));
  const buildSend = vi.spyOn(client, "buildSend");

  render(<Send />);

  const inputs = screen.getAllByRole("textbox");
  fireEvent.change(inputs[0], { target: { value: "$nosuchhandle" } });
  fireEvent.change(inputs[1], { target: { value: "5" } });

  await waitFor(() => {
    expect(screen.getByText(/handle not found/i)).toBeInTheDocument();
  });

  expect(screen.getByRole("button", { name: /review/i })).toBeDisabled();

  fireEvent.click(screen.getByRole("button", { name: /review/i }));
  expect(buildSend).not.toHaveBeenCalled();
});

test("(m) Review is disabled while a $handle is still resolving", async () => {
  let resolveLookup: (info: HandleInfo) => void = () => {};
  vi.spyOn(client, "resolveHandle").mockReturnValue(
    new Promise<HandleInfo>((resolve) => {
      resolveLookup = resolve;
    })
  );

  render(<Send />);

  const inputs = screen.getAllByRole("textbox");
  fireEvent.change(inputs[0], { target: { value: "$chris" } });
  fireEvent.change(inputs[1], { target: { value: "5" } });

  await waitFor(() => {
    expect(screen.getByText(/resolving handle/i)).toBeInTheDocument();
  });
  expect(screen.getByRole("button", { name: /review/i })).toBeDisabled();

  resolveLookup(MOCK_HANDLE);
  await waitFor(() => {
    expect(screen.getByRole("button", { name: /review/i })).toBeEnabled();
  });
});

test("(n) a plain address recipient never calls resolveHandle", async () => {
  const resolveHandle = vi.spyOn(client, "resolveHandle");
  vi.spyOn(client, "buildSend").mockResolvedValue(MOCK_PREVIEW);

  render(<Send />);

  const inputs = screen.getAllByRole("textbox");
  fireEvent.change(inputs[0], { target: { value: "addr_test1recipient" } });
  fireEvent.change(inputs[1], { target: { value: "5" } });
  fireEvent.click(screen.getByRole("button", { name: /review/i }));

  await waitFor(() => {
    expect(screen.getByText(/2 inputs/i)).toBeInTheDocument();
  });
  expect(resolveHandle).not.toHaveBeenCalled();
});

// --- address-book picker on the recipient field ---

const ALICE: Contact = { id: "c1", name: "Alice", address: "addr_test1alice" };
const BOB: Contact = { id: "c2", name: "Bob", address: "addr_test1bob" };

test("(o) no saved contacts: the Address book toggle is not rendered", () => {
  mockContacts([]);
  render(<Send />);
  expect(screen.queryByRole("button", { name: /address book/i })).not.toBeInTheDocument();
  // And the textbox indices other tests rely on stay exactly recipient/amount.
  expect(screen.getAllByRole("textbox")).toHaveLength(2);
});

test("(p) saved contacts: clicking Address book lists them, and picking one fills the recipient", () => {
  mockContacts([ALICE, BOB]);
  render(<Send />);

  const toggle = screen.getByRole("button", { name: /address book/i });
  expect(toggle).toHaveAttribute("aria-controls", "send-contact-picker-list");
  fireEvent.click(toggle);
  expect(screen.getByRole("list", { name: /saved contacts/i })).toHaveAttribute(
    "id",
    "send-contact-picker-list"
  );
  expect(screen.getByText("Alice")).toBeInTheDocument();
  expect(screen.getByText("addr_test1alice")).toBeInTheDocument();
  expect(screen.getByText("Bob")).toBeInTheDocument();

  fireEvent.click(screen.getByText("Alice"));

  const inputs = screen.getAllByRole("textbox");
  expect(inputs[0]).toHaveValue("addr_test1alice");
  // The picker list closes after a selection.
  expect(screen.queryByText("Bob")).not.toBeInTheDocument();
});

test("(q) the Address book picker closes on a second click of the toggle", () => {
  mockContacts([ALICE]);
  render(<Send />);

  const toggle = screen.getByRole("button", { name: /address book/i });
  fireEvent.click(toggle);
  expect(screen.getByText("Alice")).toBeInTheDocument();

  fireEvent.click(toggle);
  expect(screen.queryByText("Alice")).not.toBeInTheDocument();
});

// --- Hardware wallet tests ---

test("(r) hardware account: preview shows 'Confirm on your Ledger' with no password input", async () => {
  vi.spyOn(client, "buildSend").mockResolvedValue(MOCK_PREVIEW);

  render(<Send isHardware />);

  const inputs = screen.getAllByRole("textbox");
  fireEvent.change(inputs[0], { target: { value: "addr_test1recipient" } });
  fireEvent.change(inputs[1], { target: { value: "5" } });
  fireEvent.click(screen.getByRole("button", { name: /review/i }));

  await waitFor(() => {
    expect(screen.getByText(/2 inputs/i)).toBeInTheDocument();
  });

  // With no stored device-kind hint, the wallet's device is unknown, so the
  // preview prompts for it rather than silently defaulting to Ledger.
  expect(screen.getByText(/which device backs this wallet/i)).toBeInTheDocument();
  expect(screen.getByRole("button", { name: /choose a device/i })).toBeDisabled();

  // Choosing Ledger reveals the Ledger confirm flow.
  fireEvent.click(screen.getByRole("radio", { name: /ledger/i }));

  // Hardware: no password field, shows Ledger button.
  expect(screen.queryByPlaceholderText(/spending password/i)).not.toBeInTheDocument();
  expect(screen.getByRole("button", { name: /confirm on.*ledger/i })).toBeInTheDocument();
});

test("(r2) hardware account with unknown kind: choosing Trezor gates confirm on consent", async () => {
  vi.spyOn(client, "buildSend").mockResolvedValue(MOCK_PREVIEW);

  render(<Send isHardware />);

  const inputs = screen.getAllByRole("textbox");
  fireEvent.change(inputs[0], { target: { value: "addr_test1recipient" } });
  fireEvent.change(inputs[1], { target: { value: "5" } });
  fireEvent.click(screen.getByRole("button", { name: /review/i }));

  await waitFor(() => {
    expect(screen.getByText(/2 inputs/i)).toBeInTheDocument();
  });

  // Pick Trezor: the confirm button appears but stays disabled until the
  // connect.trezor.io consent box is ticked (consent-law gate).
  fireEvent.click(screen.getByRole("radio", { name: /trezor/i }));
  const confirm = screen.getByRole("button", { name: /confirm on.*trezor/i });
  expect(confirm).toBeDisabled();

  fireEvent.click(screen.getByRole("checkbox", { name: /connect\.trezor\.io/i }));
  expect(confirm).not.toBeDisabled();
});

test("(s) hardware account: confirm flow connects device, fetches sign request, signs, submits", async () => {
  vi.spyOn(client, "buildSend").mockResolvedValue(MOCK_PREVIEW);
  vi.spyOn(client, "getHardwareSignRequest").mockResolvedValue(MOCK_HW_SIGN_RESP);
  vi.spyOn(client, "submitHardware").mockResolvedValue(MOCK_TX_RESULT);

  const mockSignTx = vi.fn<HardwareSigner["signTx"]>().mockResolvedValue("81825820aabb");
  const mockClose = vi.fn().mockResolvedValue(undefined);
  const { connectHardware } = await import("../hw");
  vi.mocked(connectHardware).mockResolvedValue({
    kind: "ledger",
    capabilities: HW_CAPS,
    getAccountXpub: vi.fn(),
    signTx: mockSignTx,
    close: mockClose,
  });

  render(<Send isHardware />);

  const inputs = screen.getAllByRole("textbox");
  fireEvent.change(inputs[0], { target: { value: "addr_test1recipient" } });
  fireEvent.change(inputs[1], { target: { value: "5" } });
  fireEvent.click(screen.getByRole("button", { name: /review/i }));

  await waitFor(() => {
    expect(screen.getByText(/2 inputs/i)).toBeInTheDocument();
  });

  // No stored hint → choose the device, then confirm on it.
  fireEvent.click(screen.getByRole("radio", { name: /ledger/i }));
  fireEvent.click(screen.getByRole("button", { name: /confirm on.*ledger/i }));

  await waitFor(() => {
    expect(client.getHardwareSignRequest).toHaveBeenCalledWith("pending-abc-123");
    // Send passes the NEUTRAL backend request straight to the signer; the
    // device-specific mapping now lives inside the signer (see ledger.test.ts).
    expect(mockSignTx).toHaveBeenCalledWith(MOCK_HW_SIGN_RESP);
    expect(client.submitHardware).toHaveBeenCalledWith("pending-abc-123", "81825820aabb");
  });

  // The user chose Ledger above, so that is the device we connect.
  expect(vi.mocked(connectHardware).mock.calls[0][0]).toBe("ledger");

  // The device connect must begin directly from the confirm click, before
  // yielding to the backend signing-request fetch (preserves user activation).
  expect(vi.mocked(connectHardware).mock.invocationCallOrder[0]).toBeLessThan(
    vi.mocked(client.getHardwareSignRequest).mock.invocationCallOrder[0],
  );

  await waitFor(() => {
    expect(screen.getByText(new RegExp(MOCK_TX_RESULT.tx_hash))).toBeInTheDocument();
    expect(mockClose).toHaveBeenCalledOnce();
  });
});

test("(t) hardware account: unsupported tx closes the connected device without signing", async () => {
  vi.spyOn(client, "buildSend").mockResolvedValue(MOCK_PREVIEW);
  vi.spyOn(client, "getHardwareSignRequest").mockResolvedValue({
    ...MOCK_HW_SIGN_RESP,
    unsupported: "certificates are not supported on hardware yet",
  });

  const { connectHardware } = await import("../hw");
  const mockConnectDevice = vi.mocked(connectHardware);
  const mockSignTx = vi.fn();
  const mockClose = vi.fn().mockResolvedValue(undefined);
  mockConnectDevice.mockClear();
  mockConnectDevice.mockResolvedValue({
    kind: "ledger",
    capabilities: HW_CAPS,
    getAccountXpub: vi.fn(),
    signTx: mockSignTx,
    close: mockClose,
  });

  render(<Send isHardware />);

  const inputs = screen.getAllByRole("textbox");
  fireEvent.change(inputs[0], { target: { value: "addr_test1recipient" } });
  fireEvent.change(inputs[1], { target: { value: "5" } });
  fireEvent.click(screen.getByRole("button", { name: /review/i }));

  await waitFor(() => {
    expect(screen.getByText(/2 inputs/i)).toBeInTheDocument();
  });

  fireEvent.click(screen.getByRole("radio", { name: /ledger/i }));
  fireEvent.click(screen.getByRole("button", { name: /confirm on.*ledger/i }));

  await waitFor(() => {
    expect(screen.getByText(/cannot be signed on hardware/i)).toBeInTheDocument();
  });

  expect(mockConnectDevice).toHaveBeenCalledOnce();
  expect(mockSignTx).not.toHaveBeenCalled();
  expect(mockClose).toHaveBeenCalledOnce();
});

test("(u) hardware account with a stored Trezor hint: no device prompt, gates on consent", async () => {
  vi.spyOn(client, "buildSend").mockResolvedValue(MOCK_PREVIEW);
  localStorage.clear();
  localStorage.setItem("bursa.hw.deviceKind", JSON.stringify({ "hw-trez": "trezor" }));

  render(<Send isHardware walletId="hw-trez" />);

  const inputs = screen.getAllByRole("textbox");
  fireEvent.change(inputs[0], { target: { value: "addr_test1recipient" } });
  fireEvent.change(inputs[1], { target: { value: "5" } });
  fireEvent.click(screen.getByRole("button", { name: /review/i }));

  await waitFor(() => {
    expect(screen.getByText(/2 inputs/i)).toBeInTheDocument();
  });

  // The stored hint means the device is known — no picker is shown, and the
  // Trezor confirm is gated straight on the consent box.
  expect(screen.queryByText(/which device backs this wallet/i)).not.toBeInTheDocument();
  const confirm = screen.getByRole("button", { name: /confirm on.*trezor/i });
  expect(confirm).toBeDisabled();
  fireEvent.click(screen.getByRole("checkbox", { name: /connect\.trezor\.io/i }));
  expect(confirm).not.toBeDisabled();

  localStorage.clear();
});

test("(v) a failed hardware attempt keeps the picker and does NOT persist the pick", async () => {
  vi.spyOn(client, "buildSend").mockResolvedValue(MOCK_PREVIEW);
  localStorage.clear();

  const { connectHardware } = await import("../hw");
  const mockConnect = vi.mocked(connectHardware);
  mockConnect.mockReset();
  // Simulate picking the wrong device: the connection attempt fails.
  mockConnect.mockRejectedValue(new Error("no matching device found"));

  render(<Send isHardware walletId="hw-recover" />);

  const inputs = screen.getAllByRole("textbox");
  fireEvent.change(inputs[0], { target: { value: "addr_test1recipient" } });
  fireEvent.change(inputs[1], { target: { value: "5" } });
  fireEvent.click(screen.getByRole("button", { name: /review/i }));

  await waitFor(() => {
    expect(screen.getByText(/2 inputs/i)).toBeInTheDocument();
  });

  // Pick the (wrong) device and try to confirm — the attempt fails.
  fireEvent.click(screen.getByRole("radio", { name: /ledger/i }));
  fireEvent.click(screen.getByRole("button", { name: /confirm on.*ledger/i }));

  await waitFor(() => {
    expect(screen.getByRole("alert")).toHaveTextContent(/no matching device/i);
  });

  // The picker is STILL reachable so the user can change the device.
  expect(screen.getByText(/which device backs this wallet/i)).toBeInTheDocument();
  expect(screen.getByRole("radio", { name: /trezor/i })).toBeInTheDocument();

  // The mistaken pick was NOT persisted — only a successful send persists.
  const { getStoredDeviceKind } = await import("../hw/deviceKind");
  expect(getStoredDeviceKind("hw-recover")).toBeUndefined();

  // Switching to the other device and retrying connects THAT device.
  fireEvent.click(screen.getByRole("radio", { name: /trezor/i }));
  fireEvent.click(screen.getByRole("checkbox", { name: /connect\.trezor\.io/i }));
  fireEvent.click(screen.getByRole("button", { name: /confirm on.*trezor/i }));

  await waitFor(() => {
    const kinds = mockConnect.mock.calls.map((c) => c[0]);
    expect(kinds[kinds.length - 1]).toBe("trezor");
  });

  localStorage.clear();
});

test("(w) a successful hardware send persists the chosen device kind", async () => {
  vi.spyOn(client, "buildSend").mockResolvedValue(MOCK_PREVIEW);
  vi.spyOn(client, "getHardwareSignRequest").mockResolvedValue(MOCK_HW_SIGN_RESP);
  vi.spyOn(client, "submitHardware").mockResolvedValue(MOCK_TX_RESULT);
  localStorage.clear();

  const { connectHardware } = await import("../hw");
  const mockConnect = vi.mocked(connectHardware);
  mockConnect.mockReset();
  mockConnect.mockResolvedValue({
    kind: "ledger",
    capabilities: HW_CAPS,
    getAccountXpub: vi.fn(),
    signTx: vi.fn<HardwareSigner["signTx"]>().mockResolvedValue("81825820aabb"),
    close: vi.fn().mockResolvedValue(undefined),
  });

  render(<Send isHardware walletId="hw-persist" />);

  const inputs = screen.getAllByRole("textbox");
  fireEvent.change(inputs[0], { target: { value: "addr_test1recipient" } });
  fireEvent.change(inputs[1], { target: { value: "5" } });
  fireEvent.click(screen.getByRole("button", { name: /review/i }));

  await waitFor(() => {
    expect(screen.getByText(/2 inputs/i)).toBeInTheDocument();
  });

  const { getStoredDeviceKind } = await import("../hw/deviceKind");

  // Merely SELECTING a device must not persist it.
  fireEvent.click(screen.getByRole("radio", { name: /ledger/i }));
  expect(getStoredDeviceKind("hw-persist")).toBeUndefined();

  // A successful send persists the hint so the next send skips the picker.
  fireEvent.click(screen.getByRole("button", { name: /confirm on.*ledger/i }));
  await waitFor(() => {
    expect(screen.getByText(new RegExp(MOCK_TX_RESULT.tx_hash))).toBeInTheDocument();
  });
  expect(getStoredDeviceKind("hw-persist")).toBe("ledger");

  localStorage.clear();
});

test("(x) Keystone QR with a missing fingerprint blocks signing and prompts a re-scan", async () => {
  vi.spyOn(client, "buildSend").mockResolvedValue(MOCK_PREVIEW);
  localStorage.clear();
  // Known to be a Keystone, but its fingerprint hint is absent (e.g. a
  // browser-data wipe) — QR signing must not proceed with a zero fingerprint.
  localStorage.setItem("bursa.hw.deviceKind", JSON.stringify({ "hw-ks": "keystone" }));

  const { connectDevice } = await import("../hw");
  const mockConnect = vi.mocked(connectDevice);
  mockConnect.mockReset();

  render(<Send isHardware walletId="hw-ks" />);

  const inputs = screen.getAllByRole("textbox");
  fireEvent.change(inputs[0], { target: { value: "addr_test1recipient" } });
  fireEvent.change(inputs[1], { target: { value: "5" } });
  fireEvent.click(screen.getByRole("button", { name: /review/i }));

  await waitFor(() => {
    expect(screen.getByText(/2 inputs/i)).toBeInTheDocument();
  });

  // The recovery prompt is shown and the confirm button is blocked (never a
  // silent zero-fingerprint sign).
  expect(screen.getByText(/reconnect this keystone/i)).toBeInTheDocument();
  expect(screen.getByRole("button", { name: /scan account-sync qr/i })).toBeInTheDocument();
  const confirm = screen.getByRole("button", { name: /reconnect keystone/i });
  expect(confirm).toBeDisabled();

  // Clicking the disabled confirm does nothing; no device connection is started.
  fireEvent.click(confirm);
  expect(mockConnect).not.toHaveBeenCalled();

  localStorage.clear();
});

test("(y) Keystone QR with a stored fingerprint enables the confirm button", async () => {
  vi.spyOn(client, "buildSend").mockResolvedValue(MOCK_PREVIEW);
  localStorage.clear();
  localStorage.setItem("bursa.hw.deviceKind", JSON.stringify({ "hw-ks2": "keystone" }));
  localStorage.setItem("bursa.hw.keystoneXfp", JSON.stringify({ "hw-ks2": "52744703" }));

  render(<Send isHardware walletId="hw-ks2" />);

  const inputs = screen.getAllByRole("textbox");
  fireEvent.change(inputs[0], { target: { value: "addr_test1recipient" } });
  fireEvent.change(inputs[1], { target: { value: "5" } });
  fireEvent.click(screen.getByRole("button", { name: /review/i }));

  await waitFor(() => {
    expect(screen.getByText(/2 inputs/i)).toBeInTheDocument();
  });

  // A valid fingerprint means no recovery prompt and a ready confirm button.
  expect(screen.queryByText(/reconnect this keystone/i)).not.toBeInTheDocument();
  expect(screen.getByRole("button", { name: /confirm on.*keystone/i })).not.toBeDisabled();

  localStorage.clear();
});
