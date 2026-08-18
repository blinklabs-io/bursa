import { render, screen, fireEvent, waitFor } from "@testing-library/react";
import { SignMessage } from "./SignMessage";
import * as client from "../api/client";
import type { Account } from "../api/types";
import { connectHardware } from "../hw";
import type { HardwareSigner } from "../hw";
import { setDeviceKind } from "../hw/deviceKind";

// Mock the hardware factory so the HW tests don't open WebHID / a Trezor popup.
vi.mock("../hw", () => ({ connectHardware: vi.fn() }));

const account: Account = {
  network: "preview",
  stake_address: "stake_test1x",
  receive_addresses: ["addr_test1aaa", "addr_test1bbb"],
};

// A backend hardware-sign-data resolver response for the default address.
const HW_SIGN_DATA_REQ = {
  address_bech32: "addr_test1aaa",
  address_hex: "0011",
  signing_path: "1852'/1815'/0'/0/0",
  stake_path: "1852'/1815'/0'/2/0",
  network_id: 0,
  protocol_magic: 2,
};

// A mock HardwareSigner with the given signMessage capability + behaviour.
function mockSigner(
  signMessage: HardwareSigner["signMessage"],
  supports = true,
): HardwareSigner {
  return {
    kind: "ledger",
    capabilities: {
      send: true,
      staking: false,
      governance: false,
      multisig: false,
      poolReg: false,
      signMessage: supports,
    },
    getAccountXpub: vi.fn(),
    signTx: vi.fn(),
    signMessage,
    close: vi.fn().mockResolvedValue(undefined),
  };
}

afterEach(() => {
  vi.restoreAllMocks();
  vi.mocked(connectHardware).mockReset();
  localStorage.clear();
});

test("signs a message and shows the COSE signature + key", async () => {
  const signData = vi
    .spyOn(client, "signData")
    .mockResolvedValue({ signature: "84a1cose5ign1", key: "a401coseKey" });

  render(<SignMessage account={account} />);

  fireEvent.change(screen.getByRole("textbox", { name: /message/i }), {
    target: { value: "prove it" },
  });
  fireEvent.change(screen.getByLabelText(/spending password/i), {
    target: { value: "pw" },
  });
  fireEvent.click(screen.getByRole("button", { name: /sign message/i }));

  // Signs the default (first) address with the entered message + password.
  await waitFor(() =>
    expect(signData).toHaveBeenCalledWith({
      address: "addr_test1aaa",
      message: "prove it",
      password: "pw",
    }),
  );
  expect(await screen.findByText("84a1cose5ign1")).toBeInTheDocument();
  expect(screen.getByText("a401coseKey")).toBeInTheDocument();
});

test("shows the API error message when signing fails", async () => {
  vi.spyOn(client, "signData").mockRejectedValue(
    new client.ApiError(401, "incorrect spending password"),
  );

  render(<SignMessage account={account} />);
  fireEvent.change(screen.getByRole("textbox", { name: /message/i }), {
    target: { value: "hi" },
  });
  fireEvent.change(screen.getByLabelText(/spending password/i), {
    target: { value: "wrong" },
  });
  fireEvent.click(screen.getByRole("button", { name: /sign message/i }));

  await waitFor(() =>
    expect(screen.getByText(/incorrect spending password/i)).toBeInTheDocument(),
  );
});

test("the Sign button is disabled until a message and password are entered", () => {
  render(<SignMessage account={account} />);
  expect(screen.getByRole("button", { name: /sign message/i })).toBeDisabled();
});

// ── Hardware wallet routing ──────────────────────────────────────────────────

test("hardware wallet signs on-device via the HardwareSigner, no password field", async () => {
  const signMessage = vi
    .fn<HardwareSigner["signMessage"]>()
    .mockResolvedValue({ signature: "84hwcose", key: "a4hwkey" });
  vi.mocked(connectHardware).mockResolvedValue(mockSigner(signMessage));
  const hwReq = vi
    .spyOn(client, "getHardwareSignDataRequest")
    .mockResolvedValue(HW_SIGN_DATA_REQ);

  render(<SignMessage account={account} isHardware walletId="hw-1" />);

  // No spending password prompt on the hardware path.
  expect(screen.queryByLabelText(/spending password/i)).not.toBeInTheDocument();

  // No stored device hint → pick the device, then sign.
  fireEvent.click(screen.getByRole("radio", { name: /ledger/i }));
  fireEvent.change(screen.getByRole("textbox", { name: /message/i }), {
    target: { value: "prove it" },
  });
  fireEvent.click(screen.getByRole("button", { name: /sign on ledger/i }));

  await waitFor(() => expect(connectHardware).toHaveBeenCalled());
  // Resolves the signing paths for the selected address, then signs the
  // hex-encoded UTF-8 message on-device with those paths.
  expect(hwReq).toHaveBeenCalledWith("addr_test1aaa");
  await waitFor(() =>
    expect(signMessage).toHaveBeenCalledWith({
      messageHex: "70726f7665206974", // "prove it"
      signingPath: "1852'/1815'/0'/0/0",
      stakePath: "1852'/1815'/0'/2/0",
      networkId: 0,
      protocolMagic: 2,
    }),
  );
  expect(await screen.findByText("84hwcose")).toBeInTheDocument();
  expect(screen.getByText("a4hwkey")).toBeInTheDocument();
});

test("a stored Ledger hint skips the device picker", async () => {
  setDeviceKind("hw-led", "ledger");
  const signMessage = vi
    .fn<HardwareSigner["signMessage"]>()
    .mockResolvedValue({ signature: "84x", key: "a4y" });
  vi.mocked(connectHardware).mockResolvedValue(mockSigner(signMessage));
  vi.spyOn(client, "getHardwareSignDataRequest").mockResolvedValue(HW_SIGN_DATA_REQ);

  render(<SignMessage account={account} isHardware walletId="hw-led" />);

  // The picker is not shown; the sign button targets the stored device directly.
  expect(screen.queryByRole("radio", { name: /ledger/i })).not.toBeInTheDocument();
  expect(screen.getByRole("button", { name: /sign on ledger/i })).toBeInTheDocument();
});

test("a device that cannot sign messages shows a clear unsupported error", async () => {
  const signMessage = vi.fn<HardwareSigner["signMessage"]>();
  vi.mocked(connectHardware).mockResolvedValue(mockSigner(signMessage, /* supports */ false));
  vi.spyOn(client, "getHardwareSignDataRequest").mockResolvedValue(HW_SIGN_DATA_REQ);

  render(<SignMessage account={account} isHardware walletId="hw-x" />);
  fireEvent.click(screen.getByRole("radio", { name: /ledger/i }));
  fireEvent.change(screen.getByRole("textbox", { name: /message/i }), {
    target: { value: "hi" },
  });
  fireEvent.click(screen.getByRole("button", { name: /sign on ledger/i }));

  await waitFor(() =>
    expect(screen.getByText(/message signing is not supported/i)).toBeInTheDocument(),
  );
  // It never attempted to sign on the incapable device.
  expect(signMessage).not.toHaveBeenCalled();
});

test("a Keystone-backed wallet shows the message-signing-unsupported state", () => {
  setDeviceKind("hw-ks", "keystone");
  render(<SignMessage account={account} isHardware walletId="hw-ks" />);

  expect(screen.getByText(/not supported on Keystone/i)).toBeInTheDocument();
  // No message field or sign button in the unsupported state.
  expect(screen.queryByRole("textbox", { name: /message/i })).not.toBeInTheDocument();
  expect(screen.queryByRole("button", { name: /sign/i })).not.toBeInTheDocument();
});
