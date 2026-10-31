import { render, screen, fireEvent, waitFor } from "@testing-library/react";
import { Offline } from "./Offline";
import * as client from "../api/client";
import type { TxSummary } from "../api/types";

afterEach(() => {
  vi.restoreAllMocks();
});

const txSummary: TxSummary = {
  kind: "vkey",
  outputs: [{
    address: "addr_test1offline",
    lovelace: "2000000",
    assets: [{ unit: "policyasset", quantity: "42" }],
  }],
  fee: "170000",
  treasury_donation: "500000",
  existing_signatures: [],
  wallet_can_add: [],
  is_complete: false,
};

async function reviewTransaction() {
  fireEvent.change(screen.getByRole("textbox", { name: /unsigned transaction/i }), {
    target: { value: " 84a400 " },
  });
  fireEvent.click(screen.getByRole("button", { name: /review transaction/i }));
  await screen.findByRole("region", { name: /transaction effects/i });
}

test("Sign offline: signTx is called and the witness is shown", async () => {
  const decodeTx = vi.spyOn(client, "decodeTx").mockResolvedValue(txSummary);
  const signTx = vi
    .spyOn(client, "signTx")
    .mockResolvedValue({ witness_cbor: "81825820cafe" });

  render(<Offline />);

  await reviewTransaction();
  expect(decodeTx).toHaveBeenCalledWith("84a400");
  fireEvent.change(screen.getByRole("textbox", { name: /required signers/i }), {
    target: { value: "aabbccdd" },
  });
  fireEvent.change(screen.getByLabelText(/spending password/i), {
    target: { value: "pw" },
  });
  fireEvent.click(screen.getByRole("button", { name: /sign transaction/i }));

  await waitFor(() =>
    expect(signTx).toHaveBeenCalledWith({
      unsigned_tx_cbor: "84a400",
      password: "pw",
      required_signers: ["aabbccdd"],
    }),
  );
  expect(await screen.findByText("81825820cafe")).toBeInTheDocument();
});

test("Sign offline: shows transaction effects and gates signing on their review", async () => {
  vi.spyOn(client, "decodeTx").mockResolvedValue(txSummary);

  render(<Offline />);

  expect(screen.queryByLabelText(/spending password/i)).not.toBeInTheDocument();
  expect(screen.getByRole("button", { name: /sign transaction/i })).toBeDisabled();

  await reviewTransaction();

  const effects = screen.getByRole("region", { name: /transaction effects/i });
  expect(effects).toHaveTextContent("addr_test1offline");
  expect(effects).toHaveTextContent("policyasset");
  expect(effects).toHaveTextContent("42");
  expect(effects).toHaveTextContent("Treasury donation0.5 ADA");
  expect(screen.getByLabelText(/spending password/i)).toBeInTheDocument();
});

test("Sign offline: editing the reviewed CBOR requires another review", async () => {
  vi.spyOn(client, "decodeTx").mockResolvedValue(txSummary);

  render(<Offline />);
  await reviewTransaction();

  fireEvent.change(screen.getByRole("textbox", { name: /unsigned transaction/i }), {
    target: { value: "84a401" },
  });

  expect(screen.queryByRole("region", { name: /transaction effects/i })).not.toBeInTheDocument();
  expect(screen.queryByLabelText(/spending password/i)).not.toBeInTheDocument();
  expect(screen.getByRole("button", { name: /sign transaction/i })).toBeDisabled();
});

test("Sign offline: refuses effects the preview cannot fully show", async () => {
  vi.spyOn(client, "decodeTx").mockResolvedValue({
    ...txSummary,
    unsupported_effects: ["output 0 datum"],
  });

  render(<Offline />);
  await reviewTransaction();

  fireEvent.change(screen.getByRole("textbox", { name: /required signers/i }), {
    target: { value: "aabbccdd" },
  });
  fireEvent.change(screen.getByLabelText(/spending password/i), {
    target: { value: "pw" },
  });

  expect(screen.getByText(/full details unavailable for: output 0 datum/i)).toBeInTheDocument();
  expect(screen.getByText(/signing is unavailable/i)).toBeInTheDocument();
  expect(screen.getByRole("button", { name: /sign transaction/i })).toBeDisabled();
});

test("Submit signed: submitSigned is called and the tx hash is shown", async () => {
  const submitSigned = vi
    .spyOn(client, "submitSigned")
    .mockResolvedValue({ tx_hash: "deadbeef" });

  render(<Offline />);

  // Switch to the submit tab.
  fireEvent.click(screen.getByRole("button", { name: /submit signed/i }));

  fireEvent.change(screen.getByRole("textbox", { name: /unsigned transaction/i }), {
    target: { value: "84a400" },
  });
  fireEvent.change(screen.getByRole("textbox", { name: /^witness$/i }), {
    target: { value: "81825820cafe" },
  });
  fireEvent.click(screen.getByRole("button", { name: /attach witness & submit/i }));

  await waitFor(() =>
    expect(submitSigned).toHaveBeenCalledWith({
      unsigned_tx_cbor: "84a400",
      witness_cbor: "81825820cafe",
    }),
  );
  expect(await screen.findByText("deadbeef")).toBeInTheDocument();
});

test("Submit signed: shows the API error on a rejected witness", async () => {
  vi.spyOn(client, "submitSigned").mockRejectedValue(
    new client.ApiError(400, "invalid witness"),
  );

  render(<Offline />);
  fireEvent.click(screen.getByRole("button", { name: /submit signed/i }));
  fireEvent.change(screen.getByRole("textbox", { name: /unsigned transaction/i }), {
    target: { value: "84a400" },
  });
  fireEvent.change(screen.getByRole("textbox", { name: /^witness$/i }), {
    target: { value: "zz" },
  });
  fireEvent.click(screen.getByRole("button", { name: /attach witness & submit/i }));

  await waitFor(() =>
    expect(screen.getByText(/invalid witness/i)).toBeInTheDocument(),
  );
});

test("the Sign button is disabled until all fields are entered", () => {
  render(<Offline />);
  expect(screen.getByRole("button", { name: /sign transaction/i })).toBeDisabled();
});
