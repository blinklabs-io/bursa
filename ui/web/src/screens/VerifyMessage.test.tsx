import { render, screen, fireEvent, waitFor } from "@testing-library/react";
import { VerifyMessage } from "./VerifyMessage";
import * as client from "../api/client";

afterEach(() => {
  vi.restoreAllMocks();
});

test("verifies a signature and shows the signer address", async () => {
  const verifyData = vi
    .spyOn(client, "verifyData")
    .mockResolvedValue({ valid: true, address: "addr_test1signer" });

  render(<VerifyMessage />);

  fireEvent.change(screen.getByRole("textbox", { name: /signature/i }), {
    target: { value: "84a1cose" },
  });
  fireEvent.change(screen.getByRole("textbox", { name: /key/i }), {
    target: { value: "a401key" },
  });
  fireEvent.change(screen.getByRole("textbox", { name: /message/i }), {
    target: { value: "prove it" },
  });
  fireEvent.click(screen.getByRole("button", { name: /verify signature/i }));

  await waitFor(() =>
    expect(verifyData).toHaveBeenCalledWith({
      signature: "84a1cose",
      key: "a401key",
      message: "prove it",
    }),
  );
  expect(await screen.findByText(/valid signature/i)).toBeInTheDocument();
  expect(screen.getByText("addr_test1signer")).toBeInTheDocument();
});

test("passes expected_address when provided", async () => {
  const verifyData = vi
    .spyOn(client, "verifyData")
    .mockResolvedValue({ valid: false, address: "addr_test1other" });

  render(<VerifyMessage />);

  fireEvent.change(screen.getByRole("textbox", { name: /signature/i }), {
    target: { value: "84a1" },
  });
  fireEvent.change(screen.getByRole("textbox", { name: /key/i }), {
    target: { value: "a4" },
  });
  fireEvent.change(screen.getByRole("textbox", { name: /^message$/i }), {
    target: { value: "m" },
  });
  fireEvent.change(screen.getByRole("textbox", { name: /expected address/i }), {
    target: { value: "addr_test1expected" },
  });
  fireEvent.click(screen.getByRole("button", { name: /verify signature/i }));

  await waitFor(() =>
    expect(verifyData).toHaveBeenCalledWith({
      signature: "84a1",
      key: "a4",
      message: "m",
      expected_address: "addr_test1expected",
    }),
  );
  expect(await screen.findByText(/invalid signature/i)).toBeInTheDocument();
});

test("shows the API error message when verification errors", async () => {
  vi.spyOn(client, "verifyData").mockRejectedValue(
    new client.ApiError(400, "invalid hex"),
  );

  render(<VerifyMessage />);
  fireEvent.change(screen.getByRole("textbox", { name: /signature/i }), {
    target: { value: "zz" },
  });
  fireEvent.change(screen.getByRole("textbox", { name: /key/i }), {
    target: { value: "a4" },
  });
  fireEvent.click(screen.getByRole("button", { name: /verify signature/i }));

  await waitFor(() =>
    expect(screen.getByText(/invalid hex/i)).toBeInTheDocument(),
  );
});

test("the Verify button is disabled until signature and key are entered", () => {
  render(<VerifyMessage />);
  expect(screen.getByRole("button", { name: /verify signature/i })).toBeDisabled();
});
