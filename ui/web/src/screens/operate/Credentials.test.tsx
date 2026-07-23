import { render, screen, fireEvent, waitFor } from "@testing-library/react";
import { Credentials } from "./Credentials";
import * as client from "../../api/client";
import type { PoolCredentials } from "../../api/types";

const CREDS: PoolCredentials = {
  network: "preview",
  pool_id: "pool1deadbeef",
  pool_id_hex: "abcd",
  cold: { vkey_hex: "c0ldvkey", hash_hex: "c0ldhash" },
  vrf: { vkey_hex: "vrfvkey", hash_hex: "vrfhash" },
  kes: { vkey_hex: "kesvkey", hash_hex: "keshash" },
  cold_index: 0,
  vrf_index: 0,
  kes_index: 0,
};

afterEach(() => {
  vi.restoreAllMocks();
});

test("derives credentials and renders the pool ID plus every key hash + vkey", async () => {
  vi.spyOn(client, "poolCredentials").mockResolvedValue(CREDS);
  render(<Credentials />);

  fireEvent.change(screen.getByLabelText(/spending password/i), { target: { value: "pw" } });
  fireEvent.click(screen.getByRole("button", { name: /generate credentials/i }));

  await waitFor(() => expect(client.poolCredentials).toHaveBeenCalledWith("pw"));
  expect(await screen.findByText("pool1deadbeef")).toBeInTheDocument();
  for (const v of ["c0ldvkey", "c0ldhash", "vrfvkey", "vrfhash", "kesvkey", "keshash"]) {
    expect(screen.getByText(v)).toBeInTheDocument();
  }
  // Per-key copy affordances are labelled distinctly.
  expect(screen.getByRole("button", { name: /copy cold verification key/i })).toBeInTheDocument();
  expect(screen.getByRole("button", { name: /copy vrf key hash/i })).toBeInTheDocument();
});

test("clears the password field after a successful derivation", async () => {
  vi.spyOn(client, "poolCredentials").mockResolvedValue(CREDS);
  render(<Credentials />);

  const pw = screen.getByLabelText(/spending password/i);
  fireEvent.change(pw, { target: { value: "pw" } });
  fireEvent.click(screen.getByRole("button", { name: /generate credentials/i }));

  await waitFor(() => expect(pw).toHaveValue(""));
});

test("the generate button is disabled until a password is entered", () => {
  render(<Credentials />);
  const button = screen.getByRole("button", { name: /generate credentials/i });
  expect(button).toBeDisabled();

  fireEvent.change(screen.getByLabelText(/spending password/i), { target: { value: "pw" } });
  expect(button).not.toBeDisabled();
});

test("submitting the form (Enter) derives without a button click", async () => {
  vi.spyOn(client, "poolCredentials").mockResolvedValue(CREDS);
  render(<Credentials />);

  const pw = screen.getByLabelText(/spending password/i);
  fireEvent.change(pw, { target: { value: "pw" } });
  fireEvent.submit(pw.closest("form")!);

  await waitFor(() => expect(client.poolCredentials).toHaveBeenCalledWith("pw"));
});

test("surfaces an ApiError from a wrong password", async () => {
  vi.spyOn(client, "poolCredentials").mockRejectedValue(
    new client.ApiError(401, "incorrect spending password"),
  );
  render(<Credentials />);

  fireEvent.change(screen.getByLabelText(/spending password/i), { target: { value: "bad" } });
  fireEvent.click(screen.getByRole("button", { name: /generate credentials/i }));

  await waitFor(() =>
    expect(screen.getByRole("alert")).toHaveTextContent(/incorrect spending password/i),
  );
});

test("typing in the password field clears a prior error", async () => {
  vi.spyOn(client, "poolCredentials").mockRejectedValue(new client.ApiError(401, "nope"));
  render(<Credentials />);

  const pw = screen.getByLabelText(/spending password/i);
  fireEvent.change(pw, { target: { value: "bad" } });
  fireEvent.click(screen.getByRole("button", { name: /generate credentials/i }));
  await waitFor(() => expect(screen.getByRole("alert")).toBeInTheDocument());

  fireEvent.change(pw, { target: { value: "retry" } });
  expect(screen.queryByRole("alert")).toBeNull();
});
