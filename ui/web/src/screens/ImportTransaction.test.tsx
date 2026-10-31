import { render, screen, fireEvent, waitFor } from "@testing-library/react";
import { ImportTransaction } from "./ImportTransaction";
import * as client from "../api/client";
import type { TxSummary } from "../api/types";

afterEach(() => {
  vi.restoreAllMocks();
});

const vkeySummary: TxSummary = {
  kind: "vkey",
  outputs: [{
    address: "addr_test1xyz",
    lovelace: "2000000",
    assets: [{ unit: "policyasset", quantity: "42" }],
  }],
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
  expect(screen.getByText("policyasset")).toBeInTheDocument();
  expect(screen.getByText(/42/)).toBeInTheDocument();
  expect(screen.getByText(/add my signature/i)).toBeInTheDocument();
});

test("shows unresolved consumed and collateral references for offline review", async () => {
  vi.spyOn(client, "decodeTx").mockResolvedValue({
    ...vkeySummary,
    inputs: [{ tx_hash: "aa".repeat(32), index: 0, resolved: false }],
    collateral_inputs: [{ tx_hash: "bb".repeat(32), index: 1, resolved: false }],
    total_collateral: "1000000",
  });

  render(<ImportTransaction canSubmit={true} />);
  fireEvent.change(screen.getByLabelText(/transaction cbor/i), {
    target: { value: "84a4" },
  });
  fireEvent.click(screen.getByRole("button", { name: /decode/i }));

  await screen.findByText(`${"aa".repeat(32)}#0`);
  expect(screen.getByText(`${"bb".repeat(32)}#1`)).toBeInTheDocument();
  expect(screen.getAllByText(/unresolved.*value unavailable/i)).toHaveLength(2);
  expect(screen.getByText(/collateral if script validation fails/i)).toBeInTheDocument();
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

test("multisig: submit stays disabled for an unrecognized native-script tx (threshold 0)", async () => {
  vi.spyOn(client, "decodeTx").mockResolvedValue({
    ...vkeySummary,
    kind: "native_multisig",
    wallet_can_add: [],
    is_complete: true,
    multisig: {
      is_multisig: true,
      threshold: 0,
      signed_count: 0,
      script_embedded: true,
    },
  });

  render(<ImportTransaction canSubmit={true} />);

  fireEvent.change(screen.getByLabelText(/transaction cbor/i), {
    target: { value: "84a4" },
  });
  fireEvent.click(screen.getByRole("button", { name: /decode/i }));

  const submitBtn = await screen.findByRole("button", { name: /submit to network/i });
  expect(submitBtn).toBeDisabled();
  expect(submitBtn).not.toHaveTextContent(/need 0 more/i);
});

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

test("renders imported certificate details", async () => {
  vi.spyOn(client, "decodeTx").mockResolvedValue({
    ...vkeySummary,
    certificates: [
      {
        kind: "stake_registration",
        stake_credential: { type: "key_hash", hash: "11".repeat(28) },
        deposit_implicit: true,
      },
      {
        kind: "stake_deregistration",
        stake_credential: { type: "script_hash", hash: "22".repeat(28) },
        refund_implicit: true,
      },
      {
        kind: "stake_vote_registration_delegation",
        stake_credential: { type: "key_hash", hash: "11".repeat(28) },
        pool_id: "33".repeat(28),
        drep: { type: "abstain" },
        deposit_lovelace: "2000000",
      },
      {
        kind: "pool_registration",
        pool_id: "33".repeat(28),
        reward_account: { type: "script_hash", hash: "44".repeat(28) },
        pool_owners: ["55".repeat(28), "66".repeat(28)],
      },
      { kind: "pool_retirement", pool_id: "33".repeat(28), retirement_epoch: 0 },
      {
        kind: "deregistration_drep",
        drep_credential: { type: "key_hash", hash: "88".repeat(28) },
        refund_lovelace: "500000000",
      },
      {
        kind: "auth_committee_hot",
        committee_cold_credential: { type: "key_hash", hash: "99".repeat(28) },
        committee_hot_credential: { type: "script_hash", hash: "aa".repeat(28) },
      },
    ],
  });

  render(<ImportTransaction canSubmit={true} />);

  fireEvent.change(screen.getByLabelText(/transaction cbor/i), {
    target: { value: "84a4" },
  });
  fireEvent.click(screen.getByRole("button", { name: /decode/i }));

  const legacyReg = (await screen.findByText("stake_registration")).closest("li")!;
  expect(legacyReg).toHaveTextContent(`stake key hash ${"11".repeat(28)}`);
  expect(legacyReg).toHaveTextContent(/protocol key deposit \(amount not in certificate\)/);

  const legacyDereg = screen.getByText("stake_deregistration").closest("li")!;
  expect(legacyDereg).toHaveTextContent(`stake script hash ${"22".repeat(28)}`);
  expect(legacyDereg).toHaveTextContent(/protocol key deposit refund/);

  const combined = screen.getByText("stake_vote_registration_delegation").closest("li")!;
  expect(combined).toHaveTextContent(`pool ${"33".repeat(28)}`);
  expect(combined).toHaveTextContent("DRep abstain");
  expect(combined).toHaveTextContent("2 ADA deposit");

  const poolReg = screen.getByText("pool_registration").closest("li")!;
  expect(poolReg).toHaveTextContent(`rewards to script hash ${"44".repeat(28)}`);
  expect(poolReg).toHaveTextContent(`owners ${"55".repeat(28)}, ${"66".repeat(28)}`);

  expect(screen.getByText("pool_retirement").closest("li")!).toHaveTextContent("retires at epoch 0");

  const drepDereg = screen.getByText("deregistration_drep").closest("li")!;
  expect(drepDereg).toHaveTextContent(`DRep key hash ${"88".repeat(28)}`);
  expect(drepDereg).toHaveTextContent("500 ADA refund");

  const committee = screen.getByText("auth_committee_hot").closest("li")!;
  expect(committee).toHaveTextContent(`committee cold key hash ${"99".repeat(28)}`);
  expect(committee).toHaveTextContent(`committee hot script hash ${"aa".repeat(28)}`);
});
