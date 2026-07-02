import { render, screen, fireEvent, waitFor } from "@testing-library/react";
import { Operate } from "./Operate";
import * as client from "../api/client";
import type { Account } from "../api/types";

const account: Account = {
  network: "preview",
  stake_address: "stake_test1xreward",
  receive_addresses: ["addr_test1aaa", "addr_test1bbb"],
};

afterEach(() => {
  vi.restoreAllMocks();
});

test("Operate tabs switch with ArrowRight and ArrowLeft", () => {
  render(<Operate account={account} />);

  const credentials = screen.getByRole("tab", { name: /credentials/i });
  credentials.focus();
  fireEvent.keyDown(credentials, { key: "ArrowRight" });

  const opcert = screen.getByRole("tab", { name: /operational cert/i });
  expect(opcert).toHaveAttribute("aria-selected", "true");
  expect(opcert).toHaveFocus();
  expect(screen.getByRole("button", { name: /read current kes period/i })).toBeInTheDocument();

  fireEvent.keyDown(opcert, { key: "ArrowLeft" });

  expect(credentials).toHaveAttribute("aria-selected", "true");
  expect(credentials).toHaveFocus();
  expect(screen.getByRole("button", { name: /generate credentials/i })).toBeInTheDocument();
});

test("Operate tab aria-controls targets stay mounted", () => {
  render(<Operate account={account} />);

  for (const tab of screen.getAllByRole("tab")) {
    const panelID = tab.getAttribute("aria-controls");
    expect(panelID).toBeTruthy();
    expect(document.getElementById(panelID!)).toBeInTheDocument();
  }

  fireEvent.click(screen.getByRole("tab", { name: /retirement/i }));

  for (const tab of screen.getAllByRole("tab")) {
    const panelID = tab.getAttribute("aria-controls");
    expect(panelID).toBeTruthy();
    expect(document.getElementById(panelID!)).toBeInTheDocument();
  }
});

test("Credentials tab derives and shows the pool ID + key hashes", async () => {
  vi.spyOn(client, "poolCredentials").mockResolvedValue({
    network: "preview",
    pool_id: "pool1deadbeef",
    pool_id_hex: "abcd",
    cold: { vkey_hex: "c0ld", hash_hex: "c0ldhash" },
    vrf: { vkey_hex: "5f", hash_hex: "5fhash" },
    kes: { vkey_hex: "ke5", hash_hex: "ke5hash" },
    cold_index: 0,
    vrf_index: 0,
    kes_index: 0,
  });

  render(<Operate account={account} />);
  // Credentials is the default tab.
  fireEvent.change(screen.getByLabelText(/spending password/i), { target: { value: "pw" } });
  fireEvent.click(screen.getByRole("button", { name: /generate credentials/i }));

  await waitFor(() => expect(client.poolCredentials).toHaveBeenCalledWith("pw"));
  expect(await screen.findByText("pool1deadbeef")).toBeInTheDocument();
  expect(screen.getByText("c0ldhash")).toBeInTheDocument();
  expect(screen.getByText("5fhash")).toBeInTheDocument();
  expect(screen.getByText("ke5hash")).toBeInTheDocument();
  expect(screen.getByRole("button", { name: /copy cold verification key/i })).toBeInTheDocument();
  expect(screen.getByRole("button", { name: /copy cold key hash/i })).toBeInTheDocument();
});

test("Credentials password form submits without clicking the button", async () => {
  vi.spyOn(client, "poolCredentials").mockResolvedValue({
    network: "preview",
    pool_id: "pool1deadbeef",
    pool_id_hex: "abcd",
    cold: { vkey_hex: "c0ld", hash_hex: "c0ldhash" },
    vrf: { vkey_hex: "5f", hash_hex: "5fhash" },
    kes: { vkey_hex: "ke5", hash_hex: "ke5hash" },
    cold_index: 0,
    vrf_index: 0,
    kes_index: 0,
  });

  render(<Operate account={account} />);
  const password = screen.getByLabelText(/spending password/i);
  fireEvent.change(password, { target: { value: "pw" } });
  fireEvent.submit(password.closest("form")!);

  await waitFor(() => expect(client.poolCredentials).toHaveBeenCalledWith("pw"));
});

test("Credentials surfaces the API error", async () => {
  vi.spyOn(client, "poolCredentials").mockRejectedValue(
    new client.ApiError(401, "incorrect spending password"),
  );
  render(<Operate account={account} />);
  fireEvent.change(screen.getByLabelText(/spending password/i), { target: { value: "bad" } });
  fireEvent.click(screen.getByRole("button", { name: /generate credentials/i }));
  await waitFor(() =>
    expect(screen.getByText(/incorrect spending password/i)).toBeInTheDocument(),
  );
});

test("Operational cert tab reads the current KES period", async () => {
  vi.spyOn(client, "poolKESPeriod").mockResolvedValue({
    current_period: 42,
    tip_slot: 5_443_200,
    slots_per_kes_period: 129600,
    max_kes_evolutions: 62,
  });
  render(<Operate account={account} />);
  fireEvent.click(screen.getByRole("tab", { name: /operational cert/i }));
  fireEvent.click(screen.getByRole("button", { name: /read current kes period/i }));
  await waitFor(() => expect(screen.getByText("42")).toBeInTheDocument());
  expect(screen.getByLabelText(/^KES period$/i)).toHaveValue(42);
});

test("Operational cert clears stale current KES period on refresh failure", async () => {
  vi.spyOn(client, "poolKESPeriod")
    .mockResolvedValueOnce({
      current_period: 42,
      tip_slot: 5_443_200,
      slots_per_kes_period: 129600,
      max_kes_evolutions: 62,
    })
    .mockRejectedValueOnce(new client.ApiError(503, "tip unavailable"));
  render(<Operate account={account} />);
  fireEvent.click(screen.getByRole("tab", { name: /operational cert/i }));

  fireEvent.click(screen.getByRole("button", { name: /read current kes period/i }));
  await waitFor(() => expect(screen.getByText("42")).toBeInTheDocument());

  fireEvent.click(screen.getByRole("button", { name: /read current kes period/i }));
  await waitFor(() => expect(screen.getByRole("alert")).toHaveTextContent(/tip unavailable/i));
  expect(screen.queryByText("42")).not.toBeInTheDocument();
  expect(screen.getByLabelText(/^KES period$/i)).toHaveValue(null);
});

test("Operational cert tab issues an opcert from the seed", async () => {
  vi.spyOn(client, "poolIssueOpCert").mockResolvedValue({
    kes_vkey_hex: "ke5vkey",
    issue_number: 3,
    kes_period: 7,
    cold_signature_hex: "5ig",
    kes_index: 0,
  });
  render(<Operate account={account} />);
  fireEvent.click(screen.getByRole("tab", { name: /operational cert/i }));
  fireEvent.change(screen.getByLabelText(/^KES period$/i), { target: { value: "7" } });
  const password = screen.getByLabelText(/spending password/i);
  fireEvent.change(password, { target: { value: "pw" } });
  fireEvent.click(screen.getByRole("button", { name: /issue certificate/i }));
  await waitFor(() => expect(client.poolIssueOpCert).toHaveBeenCalled());
  await waitFor(() => expect(password).toHaveValue(""));
  expect(await screen.findByText("ke5vkey")).toBeInTheDocument();
});

test("Registration tab builds a certificate with string lovelace amounts", async () => {
  vi.spyOn(client, "poolBuildRegistration").mockResolvedValue({
    pool_id: "pool1reg",
    cbor_hex: "8a03cafe",
  });
  render(<Operate account={account} />);
  fireEvent.click(screen.getByRole("tab", { name: /registration/i }));
  fireEvent.change(screen.getByLabelText(/^pledge/i), { target: { value: "9007199254740993" } });
  fireEvent.change(screen.getByLabelText(/spending password/i), { target: { value: "pw" } });
  fireEvent.click(screen.getByRole("button", { name: /build certificate/i }));

  await waitFor(() => expect(client.poolBuildRegistration).toHaveBeenCalled());
  const call = vi.mocked(client.poolBuildRegistration).mock.calls[0][0];
  expect(call.password).toBe("pw");
  expect(call.pledge).toBe("9007199254740993");
  expect(call.cost).toBe("340000000");
  expect(await screen.findByText("pool1reg")).toBeInTheDocument();
  expect(screen.getByText("8a03cafe")).toBeInTheDocument();
});

test("Registration relay editor adds a relay that is sent to the API", async () => {
  vi.spyOn(client, "poolBuildRegistration").mockResolvedValue({
    pool_id: "pool1reg",
    cbor_hex: "8a03",
  });
  render(<Operate account={account} />);
  fireEvent.click(screen.getByRole("tab", { name: /registration/i }));
  fireEvent.change(screen.getByLabelText(/^pledge/i), { target: { value: "1" } });
  fireEvent.click(screen.getByRole("button", { name: /add relay/i }));
  fireEvent.change(screen.getByLabelText(/relay host/i), { target: { value: "1.2.3.4" } });
  fireEvent.change(screen.getByLabelText(/relay port/i), { target: { value: "3001" } });
  fireEvent.change(screen.getByLabelText(/spending password/i), { target: { value: "pw" } });
  fireEvent.click(screen.getByRole("button", { name: /build certificate/i }));

  await waitFor(() => expect(client.poolBuildRegistration).toHaveBeenCalled());
  const call = vi.mocked(client.poolBuildRegistration).mock.calls[0][0];
  expect(call.relays).toEqual([
    { type: "single_host_address", ipv4: "1.2.3.4", port: 3001 },
  ]);
});

test("Registration clears hidden relay port when switching to DNS SRV", async () => {
  vi.spyOn(client, "poolBuildRegistration").mockResolvedValue({
    pool_id: "pool1reg",
    cbor_hex: "8a03",
  });
  render(<Operate account={account} />);
  fireEvent.click(screen.getByRole("tab", { name: /registration/i }));
  fireEvent.change(screen.getByLabelText(/^pledge/i), { target: { value: "1" } });
  fireEvent.click(screen.getByRole("button", { name: /add relay/i }));
  fireEvent.change(screen.getByLabelText(/relay port/i), { target: { value: "3001" } });
  fireEvent.change(screen.getByLabelText(/relay type/i), {
    target: { value: "multi_host_name" },
  });
  fireEvent.change(screen.getByLabelText(/spending password/i), { target: { value: "pw" } });
  fireEvent.click(screen.getByRole("button", { name: /build certificate/i }));

  await waitFor(() => expect(client.poolBuildRegistration).toHaveBeenCalled());
  const call = vi.mocked(client.poolBuildRegistration).mock.calls[0][0];
  expect(call.relays).toBeUndefined();
});

test("Registration rejects decimal pledge and cost before calling the API", () => {
  vi.spyOn(client, "poolBuildRegistration").mockResolvedValue({
    pool_id: "pool1reg",
    cbor_hex: "8a03",
  });
  render(<Operate account={account} />);
  fireEvent.click(screen.getByRole("tab", { name: /registration/i }));

  fireEvent.change(screen.getByLabelText(/^pledge/i), { target: { value: "1.5" } });
  fireEvent.change(screen.getByLabelText(/spending password/i), { target: { value: "pw" } });
  fireEvent.click(screen.getByRole("button", { name: /build certificate/i }));
  expect(screen.getByRole("alert")).toHaveTextContent(/pledge must be an integer/i);
  expect(client.poolBuildRegistration).not.toHaveBeenCalled();

  fireEvent.change(screen.getByLabelText(/^pledge/i), { target: { value: "1" } });
  fireEvent.change(screen.getByLabelText(/fixed cost/i), {
    target: { value: "340000000.5" },
  });
  fireEvent.click(screen.getByRole("button", { name: /build certificate/i }));
  expect(screen.getByRole("alert")).toHaveTextContent(/cost must be an integer/i);
  expect(client.poolBuildRegistration).not.toHaveBeenCalled();
});

test("Registration rejects lovelace amounts above uint64", () => {
  vi.spyOn(client, "poolBuildRegistration").mockResolvedValue({
    pool_id: "pool1reg",
    cbor_hex: "8a03",
  });
  render(<Operate account={account} />);
  fireEvent.click(screen.getByRole("tab", { name: /registration/i }));

  fireEvent.change(screen.getByLabelText(/^pledge/i), {
    target: { value: "18446744073709551616" },
  });
  fireEvent.change(screen.getByLabelText(/spending password/i), { target: { value: "pw" } });
  fireEvent.click(screen.getByRole("button", { name: /build certificate/i }));

  expect(screen.getByRole("alert")).toHaveTextContent(/pledge is out of uint64 range/i);
  expect(client.poolBuildRegistration).not.toHaveBeenCalled();
});

test("Metadata tab builds the canonical JSON + hash", async () => {
  vi.spyOn(client, "poolBuildMetadata").mockResolvedValue({
    json: '{"name":"P","ticker":"T"}',
    hash_hex: "feedface",
  });
  render(<Operate account={account} />);
  fireEvent.click(screen.getByRole("tab", { name: /metadata/i }));
  fireEvent.change(screen.getByLabelText(/^name/i), { target: { value: "My Pool" } });
  fireEvent.change(screen.getByLabelText(/^ticker/i), { target: { value: "POOL" } });
  fireEvent.click(screen.getByRole("button", { name: /build metadata/i }));

  await waitFor(() => expect(client.poolBuildMetadata).toHaveBeenCalled());
  expect(await screen.findByText("feedface")).toBeInTheDocument();
});

test("Retirement tab builds an air-gap certificate from a cold vkey", async () => {
  vi.spyOn(client, "poolBuildRetirementCert").mockResolvedValue({
    pool_id: "pool1ret",
    cbor_hex: "8304",
  });
  render(<Operate account={account} />);
  fireEvent.click(screen.getByRole("tab", { name: /retirement/i }));
  fireEvent.click(screen.getByRole("button", { name: /air-gap/i }));
  fireEvent.change(screen.getByLabelText(/retirement epoch/i), { target: { value: "520" } });
  fireEvent.change(screen.getByLabelText(/cold verification key/i), {
    target: { value: "c0ld" },
  });
  fireEvent.click(screen.getByRole("button", { name: /build certificate/i }));

  await waitFor(() =>
    expect(client.poolBuildRetirementCert).toHaveBeenCalledWith({
      cold_vkey_hex: "c0ld",
      epoch: 520,
    }),
  );
  expect(await screen.findByText("pool1ret")).toBeInTheDocument();
  expect(screen.getByRole("button", { name: /copy retirement pool id/i })).toBeInTheDocument();
  expect(
    screen.getByRole("button", { name: /copy retirement certificate cbor hex/i }),
  ).toBeInTheDocument();
});

test("Retirement tab submits a retirement transaction", async () => {
  vi.spyOn(client, "poolSubmitRetirement").mockResolvedValue({ tx_hash: "deadbeef" });
  render(<Operate account={account} />);
  fireEvent.click(screen.getByRole("tab", { name: /retirement/i }));
  fireEvent.change(screen.getByLabelText(/retirement epoch/i), { target: { value: "520" } });
  fireEvent.change(screen.getByLabelText(/spending password/i), { target: { value: "pw" } });
  fireEvent.click(screen.getByRole("button", { name: /build & submit retirement/i }));

  await waitFor(() =>
    expect(client.poolSubmitRetirement).toHaveBeenCalledWith({ password: "pw", epoch: 520 }),
  );
  expect(await screen.findByText("deadbeef")).toBeInTheDocument();
  expect(
    screen.getByRole("button", { name: /copy retirement transaction hash/i }),
  ).toBeInTheDocument();
});

test("Retirement rejects unsafe epoch integers before calling the API", () => {
  vi.spyOn(client, "poolSubmitRetirement").mockResolvedValue({ tx_hash: "deadbeef" });
  render(<Operate account={account} />);
  fireEvent.click(screen.getByRole("tab", { name: /retirement/i }));
  fireEvent.change(screen.getByLabelText(/retirement epoch/i), {
    target: { value: "9007199254740993" },
  });
  fireEvent.change(screen.getByLabelText(/spending password/i), { target: { value: "pw" } });
  fireEvent.click(screen.getByRole("button", { name: /build & submit retirement/i }));

  expect(screen.getByRole("alert")).toHaveTextContent(/retirement epoch must be a non-negative integer/i);
  expect(client.poolSubmitRetirement).not.toHaveBeenCalled();
});
