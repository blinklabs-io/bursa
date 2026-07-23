import { render, screen, fireEvent, waitFor } from "@testing-library/react";
import { OperationalCert } from "./OperationalCert";
import * as client from "../../api/client";
import type { OpCert, OpCertPayload, KESPeriodInfo } from "../../api/types";

const KES_INFO: KESPeriodInfo = {
  current_period: 42,
  tip_slot: 5_443_200,
  slots_per_kes_period: 129_600,
  max_kes_evolutions: 62,
};

const OPCERT: OpCert = {
  kes_vkey_hex: "ke5vkey",
  issue_number: 3,
  kes_period: 7,
  cold_signature_hex: "c0ldsig",
  kes_index: 0,
};

afterEach(() => {
  vi.restoreAllMocks();
});

function switchToAirGap() {
  fireEvent.click(screen.getByRole("button", { name: /^air-gap$/i }));
}

// --- KES period readout ---

test("reads and displays the current KES period", async () => {
  vi.spyOn(client, "poolKESPeriod").mockResolvedValue(KES_INFO);
  render(<OperationalCert />);

  fireEvent.click(screen.getByRole("button", { name: /read current kes period/i }));

  await waitFor(() => expect(screen.getByText("42")).toBeInTheDocument());
  expect(screen.getByText("5443200")).toBeInTheDocument();
  expect(screen.getByText("129600")).toBeInTheDocument();
});

test("surfaces an error when reading the KES period fails", async () => {
  vi.spyOn(client, "poolKESPeriod").mockRejectedValue(new client.ApiError(503, "tip unavailable"));
  render(<OperationalCert />);

  fireEvent.click(screen.getByRole("button", { name: /read current kes period/i }));
  await waitFor(() => expect(screen.getByRole("alert")).toHaveTextContent(/tip unavailable/i));
});

test("reading the KES period auto-fills the empty KES period input", async () => {
  vi.spyOn(client, "poolKESPeriod").mockResolvedValue(KES_INFO);
  render(<OperationalCert />);

  // Before reading: the seed form's KES period is empty with a prompt placeholder.
  const periodField = screen.getByLabelText(/^kes period$/i);
  expect(periodField).toHaveValue(null);

  fireEvent.click(screen.getByRole("button", { name: /read current kes period/i }));
  await waitFor(() => expect(periodField).toHaveValue(42));
});

// --- seed mode: issue ---

test("seed mode issues an operational certificate and clears the password", async () => {
  const issue = vi.spyOn(client, "poolIssueOpCert").mockResolvedValue(OPCERT);
  render(<OperationalCert />);

  fireEvent.change(screen.getByLabelText(/kes key index/i), { target: { value: "1" } });
  fireEvent.change(screen.getByLabelText(/issue number/i), { target: { value: "2" } });
  fireEvent.change(screen.getByLabelText(/^kes period$/i), { target: { value: "7" } });
  const pw = screen.getByLabelText(/spending password/i);
  fireEvent.change(pw, { target: { value: "pw" } });
  fireEvent.click(screen.getByRole("button", { name: /issue certificate/i }));

  await waitFor(() =>
    expect(issue).toHaveBeenCalledWith({
      password: "pw",
      kes_index: 1,
      issue_number: 2,
      kes_period: 7,
    }),
  );
  await waitFor(() => expect(pw).toHaveValue(""));
  expect(await screen.findByText("ke5vkey")).toBeInTheDocument();
  expect(screen.getByText("c0ldsig")).toBeInTheDocument();
});

// --- seed mode: rotate ---

test("checking KES rotation relabels the fields and calls poolRotateKES", async () => {
  const rotate = vi.spyOn(client, "poolRotateKES").mockResolvedValue(OPCERT);
  render(<OperationalCert />);

  fireEvent.click(screen.getByLabelText(/kes rotation/i));

  // Labels switch to the rotation wording.
  expect(screen.getByLabelText(/new kes key index/i)).toBeInTheDocument();
  expect(screen.getByLabelText(/previous issue number/i)).toBeInTheDocument();
  expect(screen.getByRole("button", { name: /rotate kes/i })).toBeInTheDocument();

  fireEvent.change(screen.getByLabelText(/new kes key index/i), { target: { value: "2" } });
  fireEvent.change(screen.getByLabelText(/previous issue number/i), { target: { value: "4" } });
  fireEvent.change(screen.getByLabelText(/^kes period$/i), { target: { value: "9" } });
  fireEvent.change(screen.getByLabelText(/spending password/i), { target: { value: "pw" } });
  fireEvent.click(screen.getByRole("button", { name: /rotate kes/i }));

  await waitFor(() =>
    expect(rotate).toHaveBeenCalledWith({
      password: "pw",
      new_kes_index: 2,
      prev_issue_number: 4,
      kes_period: 9,
    }),
  );
});

test("seed mode rejects a KES period that is not a whole number", async () => {
  const issue = vi.spyOn(client, "poolIssueOpCert");
  render(<OperationalCert />);

  // Clear the KES period so it fails parseNonNegativeInteger.
  fireEvent.change(screen.getByLabelText(/^kes period$/i), { target: { value: "" } });
  fireEvent.change(screen.getByLabelText(/spending password/i), { target: { value: "pw" } });
  fireEvent.click(screen.getByRole("button", { name: /issue certificate/i }));

  await waitFor(() =>
    expect(screen.getByRole("alert")).toHaveTextContent(/kes period must be a whole number/i),
  );
  expect(issue).not.toHaveBeenCalled();
});

test("the seed issue button is disabled until a password is entered", () => {
  render(<OperationalCert />);
  const button = screen.getByRole("button", { name: /issue certificate/i });
  expect(button).toBeDisabled();
  fireEvent.change(screen.getByLabelText(/spending password/i), { target: { value: "pw" } });
  expect(button).not.toBeDisabled();
});

// --- air-gap mode: two-step payload then assemble ---

test("air-gap mode builds the to-be-signed payload", async () => {
  const payload: OpCertPayload = {
    payload_hex: "5ec0ffee",
    kes_vkey_hex: "ke5vkey",
    issue_number: 0,
    kes_period: 5,
  };
  const build = vi.spyOn(client, "poolOpCertPayload").mockResolvedValue(payload);
  render(<OperationalCert />);
  switchToAirGap();

  fireEvent.change(screen.getByLabelText(/kes verification key/i), { target: { value: " ke5 " } });
  fireEvent.change(screen.getByLabelText(/^kes period$/i), { target: { value: "5" } });
  fireEvent.click(screen.getByRole("button", { name: /build to-be-signed payload/i }));

  await waitFor(() =>
    expect(build).toHaveBeenCalledWith({ kes_vkey_hex: "ke5", issue_number: 0, kes_period: 5 }),
  );
  expect(await screen.findByText("5ec0ffee")).toBeInTheDocument();
});

test("air-gap payload button is gated on the KES vkey", () => {
  render(<OperationalCert />);
  switchToAirGap();
  const button = screen.getByRole("button", { name: /build to-be-signed payload/i });
  expect(button).toBeDisabled();
  fireEvent.change(screen.getByLabelText(/kes verification key/i), { target: { value: "ke5" } });
  expect(button).not.toBeDisabled();
});

test("editing the KES vkey after building clears the stale payload", async () => {
  vi.spyOn(client, "poolOpCertPayload").mockResolvedValue({
    payload_hex: "5ec0ffee",
    kes_vkey_hex: "ke5",
    issue_number: 0,
    kes_period: 5,
  });
  render(<OperationalCert />);
  switchToAirGap();

  const vkey = screen.getByLabelText(/kes verification key/i);
  fireEvent.change(vkey, { target: { value: "ke5" } });
  fireEvent.change(screen.getByLabelText(/^kes period$/i), { target: { value: "5" } });
  fireEvent.click(screen.getByRole("button", { name: /build to-be-signed payload/i }));
  expect(await screen.findByText("5ec0ffee")).toBeInTheDocument();

  fireEvent.change(vkey, { target: { value: "ke5changed" } });
  expect(screen.queryByText("5ec0ffee")).toBeNull();
});

test("air-gap mode assembles a certificate from an offline signature", async () => {
  const assemble = vi.spyOn(client, "poolAssembleOpCert").mockResolvedValue(OPCERT);
  render(<OperationalCert />);
  switchToAirGap();

  fireEvent.change(screen.getByLabelText(/kes verification key/i), { target: { value: " ke5 " } });
  fireEvent.change(screen.getByLabelText(/^kes period$/i), { target: { value: "7" } });
  fireEvent.change(screen.getByLabelText(/cold verification key/i), { target: { value: " c0ld " } });
  fireEvent.change(screen.getByLabelText(/cold signature/i), { target: { value: " 5ig " } });
  fireEvent.click(screen.getByRole("button", { name: /assemble certificate/i }));

  await waitFor(() =>
    expect(assemble).toHaveBeenCalledWith({
      cold_vkey_hex: "c0ld",
      kes_vkey_hex: "ke5",
      signature_hex: "5ig",
      issue_number: 0,
      kes_period: 7,
    }),
  );
  expect(await screen.findByText("ke5vkey")).toBeInTheDocument();
});

test("assemble button is gated on cold vkey, signature, and KES vkey", () => {
  render(<OperationalCert />);
  switchToAirGap();
  const assemble = screen.getByRole("button", { name: /assemble certificate/i });
  expect(assemble).toBeDisabled();

  fireEvent.change(screen.getByLabelText(/kes verification key/i), { target: { value: "ke5" } });
  fireEvent.change(screen.getByLabelText(/cold verification key/i), { target: { value: "c0ld" } });
  expect(assemble).toBeDisabled(); // signature still missing

  fireEvent.change(screen.getByLabelText(/cold signature/i), { target: { value: "5ig" } });
  expect(assemble).not.toBeDisabled();
});

test("air-gap assemble surfaces an ApiError", async () => {
  vi.spyOn(client, "poolAssembleOpCert").mockRejectedValue(
    new client.ApiError(400, "signature does not verify"),
  );
  render(<OperationalCert />);
  switchToAirGap();

  fireEvent.change(screen.getByLabelText(/kes verification key/i), { target: { value: "ke5" } });
  fireEvent.change(screen.getByLabelText(/^kes period$/i), { target: { value: "7" } });
  fireEvent.change(screen.getByLabelText(/cold verification key/i), { target: { value: "c0ld" } });
  fireEvent.change(screen.getByLabelText(/cold signature/i), { target: { value: "bad" } });
  fireEvent.click(screen.getByRole("button", { name: /assemble certificate/i }));

  await waitFor(() =>
    expect(screen.getByRole("alert")).toHaveTextContent(/signature does not verify/i),
  );
});
