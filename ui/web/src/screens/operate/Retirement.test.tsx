import { render, screen, fireEvent, waitFor } from "@testing-library/react";
import { Retirement } from "./Retirement";
import * as client from "../../api/client";

afterEach(() => {
  vi.restoreAllMocks();
});

function switchToAirGap() {
  fireEvent.click(screen.getByRole("button", { name: /air-gap/i }));
}

// --- seed mode: build certificate ---

test("seed mode builds a retirement certificate from the spending password", async () => {
  const build = vi
    .spyOn(client, "poolBuildRetirementCert")
    .mockResolvedValue({ pool_id: "pool1ret", cbor_hex: "8304cafe" });
  render(<Retirement />);

  fireEvent.change(screen.getByLabelText(/retirement epoch/i), { target: { value: "520" } });
  fireEvent.change(screen.getByLabelText(/spending password/i), { target: { value: "pw" } });
  fireEvent.click(screen.getByRole("button", { name: /^build certificate$/i }));

  await waitFor(() =>
    expect(build).toHaveBeenCalledWith({ password: "pw", epoch: 520 }),
  );
  expect(await screen.findByText("pool1ret")).toBeInTheDocument();
  expect(screen.getByText("8304cafe")).toBeInTheDocument();
});

// --- seed mode: submit transaction ---

test("seed mode submits a retirement transaction and shows the tx hash", async () => {
  const submit = vi
    .spyOn(client, "poolSubmitRetirement")
    .mockResolvedValue({ tx_hash: "deadbeef" });
  render(<Retirement />);

  fireEvent.change(screen.getByLabelText(/retirement epoch/i), { target: { value: "520" } });
  fireEvent.change(screen.getByLabelText(/spending password/i), { target: { value: "pw" } });
  fireEvent.click(screen.getByRole("button", { name: /build & submit retirement/i }));

  await waitFor(() => expect(submit).toHaveBeenCalledWith({ password: "pw", epoch: 520 }));
  expect(await screen.findByText("deadbeef")).toBeInTheDocument();
  expect(screen.getByText(/retirement transaction submitted/i)).toBeInTheDocument();
});

// --- air-gap mode: cold-vkey cert, no submit button ---

test("air-gap mode builds a certificate from a cold vkey and has no submit button", async () => {
  const build = vi
    .spyOn(client, "poolBuildRetirementCert")
    .mockResolvedValue({ pool_id: "pool1air", cbor_hex: "8304" });
  render(<Retirement />);
  switchToAirGap();

  // The seed-only submit action is not offered in air-gap mode.
  expect(screen.queryByRole("button", { name: /build & submit retirement/i })).toBeNull();
  expect(screen.queryByLabelText(/spending password/i)).toBeNull();

  fireEvent.change(screen.getByLabelText(/retirement epoch/i), { target: { value: "300" } });
  fireEvent.change(screen.getByLabelText(/cold verification key/i), { target: { value: "  c0ld  " } });
  fireEvent.click(screen.getByRole("button", { name: /^build certificate$/i }));

  await waitFor(() =>
    expect(build).toHaveBeenCalledWith({ cold_vkey_hex: "c0ld", epoch: 300 }),
  );
  expect(await screen.findByText("pool1air")).toBeInTheDocument();
});

// --- validation ---

test("build requires an epoch value", () => {
  const build = vi.spyOn(client, "poolBuildRetirementCert");
  render(<Retirement />);

  fireEvent.change(screen.getByLabelText(/spending password/i), { target: { value: "pw" } });
  fireEvent.click(screen.getByRole("button", { name: /^build certificate$/i }));

  expect(screen.getByRole("alert")).toHaveTextContent(/retirement epoch is required/i);
  expect(build).not.toHaveBeenCalled();
});

test("build rejects an epoch above the safe-integer range before calling the API", () => {
  const build = vi.spyOn(client, "poolBuildRetirementCert");
  render(<Retirement />);

  fireEvent.change(screen.getByLabelText(/retirement epoch/i), {
    target: { value: "9007199254740993" },
  });
  fireEvent.change(screen.getByLabelText(/spending password/i), { target: { value: "pw" } });
  fireEvent.click(screen.getByRole("button", { name: /^build certificate$/i }));

  expect(screen.getByRole("alert")).toHaveTextContent(
    /retirement epoch must be a non-negative integer/i,
  );
  expect(build).not.toHaveBeenCalled();
});

test("submit rejects a non-integer epoch before calling the API", () => {
  const submit = vi.spyOn(client, "poolSubmitRetirement");
  render(<Retirement />);

  // Epoch input is type=number; feed a value that fails the /^\d+$/ parse.
  fireEvent.change(screen.getByLabelText(/retirement epoch/i), { target: { value: "1.5" } });
  fireEvent.change(screen.getByLabelText(/spending password/i), { target: { value: "pw" } });
  fireEvent.click(screen.getByRole("button", { name: /build & submit retirement/i }));

  expect(screen.getByRole("alert")).toHaveTextContent(
    /retirement epoch must be a non-negative integer/i,
  );
  expect(submit).not.toHaveBeenCalled();
});

// --- disabled-state gating ---

test("seed build/submit buttons are gated on password and epoch", () => {
  render(<Retirement />);
  const buildBtn = screen.getByRole("button", { name: /^build certificate$/i });
  const submitBtn = screen.getByRole("button", { name: /build & submit retirement/i });

  expect(buildBtn).toBeDisabled();
  expect(submitBtn).toBeDisabled();

  fireEvent.change(screen.getByLabelText(/spending password/i), { target: { value: "pw" } });
  // Build only needs a password; submit also needs an epoch.
  expect(buildBtn).not.toBeDisabled();
  expect(submitBtn).toBeDisabled();

  fireEvent.change(screen.getByLabelText(/retirement epoch/i), { target: { value: "10" } });
  expect(submitBtn).not.toBeDisabled();
});

// --- error handling ---

test("surfaces an ApiError from a failed submission", async () => {
  vi.spyOn(client, "poolSubmitRetirement").mockRejectedValue(
    new client.ApiError(409, "pool is already retired"),
  );
  render(<Retirement />);

  fireEvent.change(screen.getByLabelText(/retirement epoch/i), { target: { value: "520" } });
  fireEvent.change(screen.getByLabelText(/spending password/i), { target: { value: "pw" } });
  fireEvent.click(screen.getByRole("button", { name: /build & submit retirement/i }));

  await waitFor(() =>
    expect(screen.getByRole("alert")).toHaveTextContent(/pool is already retired/i),
  );
});
