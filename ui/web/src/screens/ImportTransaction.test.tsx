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

// Real backend behavior for native_multisig: the multisig builder never
// registers participant key-hashes as tx-level required signers, so
// spend.DecodeTx (which derives wallet_can_add/is_complete from
// required-signers/cert credentials) always reports wallet_can_add: [] and
// is_complete: true — regardless of how many cosigners have actually signed.
// The screen must fall back to summary.multisig for both the "add my
// signature" affordance and the submit-readiness gate.
const multisigBelowThreshold: TxSummary = {
  ...vkeySummary,
  kind: "native_multisig",
  wallet_can_add: [],
  is_complete: true,
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
};

test("multisig: cosign affordance shows and submit stays gated on threshold, then unlocks once met", async () => {
  const decodeSpy = vi.spyOn(client, "decodeTx").mockResolvedValue(multisigBelowThreshold);
  const cosignSpy = vi.spyOn(client, "cosignTx").mockResolvedValue({
    tx_cbor: "84beef",
    added: true,
    signed_count: 2,
    threshold: 2,
  });

  render(<ImportTransaction canSubmit={true} />);

  fireEvent.change(screen.getByLabelText(/transaction cbor/i), {
    target: { value: "84a4" },
  });
  fireEvent.click(screen.getByRole("button", { name: /decode/i }));

  // (a) Bug 1: despite wallet_can_add being empty, the multisig-aware
  // fallback must still surface the password field + "Add my signature".
  await screen.findByLabelText(/spending password/i);
  expect(screen.getByRole("button", { name: /add my signature/i })).toBeInTheDocument();

  // (b) Bug 2: despite is_complete: true, submit must stay disabled while
  // signed_count (1) < threshold (2), with a label saying so.
  const submitBtn = screen.getByRole("button", { name: /submit to network/i });
  expect(submitBtn).toBeDisabled();
  expect(submitBtn).toHaveTextContent(/need 1 more signature/i);

  // Cosign, then the handleCosign multisig path re-decodes for a fresh
  // summary — mock that follow-up call to report the threshold now met.
  decodeSpy.mockResolvedValueOnce({
    ...multisigBelowThreshold,
    multisig: { ...multisigBelowThreshold.multisig!, signed_count: 2 },
  });

  fireEvent.change(screen.getByLabelText(/spending password/i), {
    target: { value: "pw" },
  });
  fireEvent.click(screen.getByRole("button", { name: /add my signature/i }));

  await waitFor(() =>
    expect(screen.getByRole("button", { name: /submit to network/i })).toBeEnabled(),
  );
  expect(cosignSpy).toHaveBeenCalledWith({ tx_cbor: "84a4", password: "pw" });
  expect(screen.getByRole("button", { name: /submit to network/i })).not.toHaveTextContent(
    /need|incomplete|syncing/i,
  );
});
