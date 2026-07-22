import { render, screen, fireEvent, waitFor } from "@testing-library/react";
import { ImportTransaction } from "./ImportTransaction";
import * as client from "../api/client";
import type { TxSummary } from "../api/types";

afterEach(() => {
  vi.restoreAllMocks();
});

const vkeySummary: TxSummary = {
  kind: "vkey",
  outputs: [{ address: "addr_test1xyz", lovelace: "2000000" }],
  fee: "170000",
  existing_signatures: [],
  wallet_can_add: [{ key_hash: "aa".repeat(28), role: "payment" }],
  is_complete: false,
};

test("decodes a pasted tx and shows the preview", async () => {
  vi.spyOn(client, "decodeTx").mockResolvedValue(vkeySummary);

  render(<ImportTransaction canSubmit={true} />);

  fireEvent.change(screen.getByLabelText(/transaction cbor/i), {
    target: { value: "84a4" },
  });
  fireEvent.click(screen.getByRole("button", { name: /decode/i }));

  await waitFor(() => expect(screen.getByText(/170000|0.17/)).toBeInTheDocument());
  expect(screen.getByText(/add my signature/i)).toBeInTheDocument();
});

test("adds a signature and reveals export + submit", async () => {
  vi.spyOn(client, "decodeTx").mockResolvedValue(vkeySummary);
  vi.spyOn(client, "cosignTx").mockResolvedValue({
    tx_cbor: "84beef",
    added: [{ key_hash: "aa".repeat(28) }],
    summary: {
      ...vkeySummary,
      existing_signatures: [{ key_hash: "aa".repeat(28) }],
      wallet_can_add: [],
      is_complete: true,
    },
  });

  render(<ImportTransaction canSubmit={true} />);

  fireEvent.change(screen.getByLabelText(/transaction cbor/i), {
    target: { value: "84a4" },
  });
  fireEvent.click(screen.getByRole("button", { name: /decode/i }));
  await screen.findByText(/add my signature/i);

  fireEvent.change(screen.getByLabelText(/spending password/i), {
    target: { value: "pw" },
  });
  fireEvent.click(screen.getByRole("button", { name: /add my signature/i }));

  await waitFor(() =>
    expect(screen.getByRole("button", { name: /submit to network/i })).toBeEnabled(),
  );
  expect(screen.getByText(/84beef/)).toBeInTheDocument();
});

test("disables submit when the node is not ready", async () => {
  vi.spyOn(client, "decodeTx").mockResolvedValue({
    ...vkeySummary,
    is_complete: true,
    wallet_can_add: [],
  });

  render(<ImportTransaction canSubmit={false} />);

  fireEvent.change(screen.getByLabelText(/transaction cbor/i), {
    target: { value: "84a4" },
  });
  fireEvent.click(screen.getByRole("button", { name: /decode/i }));

  await waitFor(() =>
    expect(screen.getByRole("button", { name: /submit to network/i })).toBeDisabled(),
  );
});

test("renders multisig progress for a native_multisig tx", async () => {
  vi.spyOn(client, "decodeTx").mockResolvedValue({
    ...vkeySummary,
    kind: "native_multisig",
    multisig: {
      is_multisig: true,
      threshold: 2,
      signed_count: 1,
      script_embedded: true,
      participants: [
        { key_hash: "aa".repeat(28), signed: true },
        { key_hash: "bb".repeat(28), signed: false },
      ],
    },
  });

  render(<ImportTransaction canSubmit={true} />);

  fireEvent.change(screen.getByLabelText(/transaction cbor/i), {
    target: { value: "84a4" },
  });
  fireEvent.click(screen.getByRole("button", { name: /decode/i }));

  await waitFor(() => expect(screen.getByText(/1 of 2 signed/i)).toBeInTheDocument());
});
