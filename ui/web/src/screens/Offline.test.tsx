import { render, screen, fireEvent, waitFor } from "@testing-library/react";
import { Offline } from "./Offline";
import * as client from "../api/client";

afterEach(() => {
  vi.restoreAllMocks();
});

test("Sign offline: signTx is called and the witness is shown", async () => {
  const signTx = vi
    .spyOn(client, "signTx")
    .mockResolvedValue({ witness_cbor: "81825820cafe" });

  render(<Offline />);

  fireEvent.change(screen.getByRole("textbox", { name: /unsigned transaction/i }), {
    target: { value: "84a400" },
  });
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
