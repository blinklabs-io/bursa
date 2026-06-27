import { render, screen, fireEvent, waitFor } from "@testing-library/react";
import { SignMessage } from "./SignMessage";
import * as client from "../api/client";
import type { Account } from "../api/types";

const account: Account = {
  network: "preview",
  stake_address: "stake_test1x",
  receive_addresses: ["addr_test1aaa", "addr_test1bbb"],
};

afterEach(() => {
  vi.restoreAllMocks();
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
