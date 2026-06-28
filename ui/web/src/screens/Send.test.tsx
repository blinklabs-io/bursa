import { render, screen, fireEvent, waitFor } from "@testing-library/react";
import { Send } from "./Send";
import * as client from "../api/client";
import type { Preview, TxResult } from "../api/types";

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
