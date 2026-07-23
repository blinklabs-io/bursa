import { render, screen, fireEvent, waitFor } from "@testing-library/react";
import { Registration } from "./Registration";
import * as client from "../../api/client";
import type { Account } from "../../api/types";

const account: Account = {
  network: "preview",
  stake_address: "stake_test1reward",
  receive_addresses: ["addr_test1aaa"],
};

afterEach(() => {
  vi.restoreAllMocks();
});

function renderReg() {
  render(<Registration account={account} />);
}

// Fill the minimum a build needs in seed mode: pledge + password.
function fillSeedMinimum(pledge = "100000000", password = "pw") {
  fireEvent.change(screen.getByLabelText(/^pledge/i), { target: { value: pledge } });
  fireEvent.change(screen.getByLabelText(/spending password/i), { target: { value: password } });
}

// --- air-gap mode (the branch Operate.test.tsx does not exercise) ---

test("air-gap mode builds from a cold vkey + VRF key hash, not a password", async () => {
  const build = vi
    .spyOn(client, "poolBuildRegistrationAirGap")
    .mockResolvedValue({ pool_id: "pool1air", cbor_hex: "8a03air" });
  renderReg();

  fireEvent.click(screen.getByRole("button", { name: /air-gap/i }));
  expect(screen.queryByLabelText(/spending password/i)).toBeNull();

  fireEvent.change(screen.getByLabelText(/^pledge/i), { target: { value: "100000000" } });
  fireEvent.change(screen.getByLabelText(/cold verification key/i), { target: { value: " c0ld " } });
  fireEvent.change(screen.getByLabelText(/vrf key hash/i), { target: { value: " vrf " } });
  fireEvent.click(screen.getByRole("button", { name: /build certificate/i }));

  await waitFor(() => expect(build).toHaveBeenCalled());
  const arg = vi.mocked(build).mock.calls[0][0];
  expect(arg.cold_vkey_hex).toBe("c0ld");
  expect(arg.vrf_key_hash_hex).toBe("vrf");
  expect(arg.pledge).toBe("100000000");
  expect(await screen.findByText("pool1air")).toBeInTheDocument();
  expect(screen.getByText("8a03air")).toBeInTheDocument();
});

test("air-gap build button is gated on both cold vkey and VRF hash", () => {
  renderReg();
  fireEvent.click(screen.getByRole("button", { name: /air-gap/i }));
  const build = screen.getByRole("button", { name: /build certificate/i });
  expect(build).toBeDisabled();

  fireEvent.change(screen.getByLabelText(/cold verification key/i), { target: { value: "c0ld" } });
  expect(build).toBeDisabled(); // VRF hash still missing

  fireEvent.change(screen.getByLabelText(/vrf key hash/i), { target: { value: "vrf" } });
  expect(build).not.toBeDisabled();
});

// --- optional field passthrough ---

test("owners are split on commas/whitespace and reward + metadata fields pass through", async () => {
  const build = vi
    .spyOn(client, "poolBuildRegistration")
    .mockResolvedValue({ pool_id: "pool1reg", cbor_hex: "8a03" });
  renderReg();

  fillSeedMinimum();
  fireEvent.change(screen.getByLabelText(/reward account/i), { target: { value: " stake_test1xyz " } });
  fireEvent.change(screen.getByLabelText(/^owners/i), {
    target: { value: "stake1a, stake1b   stake1c" },
  });
  fireEvent.change(screen.getByLabelText(/metadata url/i), {
    target: { value: " https://p.example/m.json " },
  });
  fireEvent.change(screen.getByLabelText(/metadata hash/i), { target: { value: " abcdef " } });
  fireEvent.click(screen.getByRole("button", { name: /build certificate/i }));

  await waitFor(() => expect(build).toHaveBeenCalled());
  const arg = vi.mocked(build).mock.calls[0][0];
  expect(arg.owners).toEqual(["stake1a", "stake1b", "stake1c"]);
  expect(arg.reward_address).toBe("stake_test1xyz");
  expect(arg.metadata_url).toBe("https://p.example/m.json");
  expect(arg.metadata_hash).toBe("abcdef");
});

test("an IPv6-looking relay host maps to ipv6, not ipv4", async () => {
  const build = vi
    .spyOn(client, "poolBuildRegistration")
    .mockResolvedValue({ pool_id: "pool1reg", cbor_hex: "8a03" });
  renderReg();

  fillSeedMinimum();
  fireEvent.click(screen.getByRole("button", { name: /add relay/i }));
  fireEvent.change(screen.getByLabelText(/relay host/i), { target: { value: "2001:db8::1" } });
  fireEvent.change(screen.getByLabelText(/relay port/i), { target: { value: "3001" } });
  fireEvent.click(screen.getByRole("button", { name: /build certificate/i }));

  await waitFor(() => expect(build).toHaveBeenCalled());
  const arg = vi.mocked(build).mock.calls[0][0];
  expect(arg.relays).toEqual([
    { type: "single_host_address", ipv6: "2001:db8::1", port: 3001 },
  ]);
});

test("removing a relay row drops it from the request", async () => {
  const build = vi
    .spyOn(client, "poolBuildRegistration")
    .mockResolvedValue({ pool_id: "pool1reg", cbor_hex: "8a03" });
  renderReg();

  fillSeedMinimum();
  fireEvent.click(screen.getByRole("button", { name: /add relay/i }));
  fireEvent.change(screen.getByLabelText(/relay host/i), { target: { value: "1.2.3.4" } });
  fireEvent.click(screen.getByRole("button", { name: /^remove$/i }));
  fireEvent.click(screen.getByRole("button", { name: /build certificate/i }));

  await waitFor(() => expect(build).toHaveBeenCalled());
  expect(vi.mocked(build).mock.calls[0][0].relays).toBeUndefined();
});

// --- validation branches (API must not be called) ---

test("missing pledge blocks the build", () => {
  const build = vi.spyOn(client, "poolBuildRegistration");
  renderReg();

  fireEvent.change(screen.getByLabelText(/spending password/i), { target: { value: "pw" } });
  fireEvent.click(screen.getByRole("button", { name: /build certificate/i }));

  expect(screen.getByRole("alert")).toHaveTextContent(/pledge and cost are required/i);
  expect(build).not.toHaveBeenCalled();
});

test("a relay with a port but no host reports 'Relay host is required'", () => {
  const build = vi.spyOn(client, "poolBuildRegistration");
  renderReg();

  fillSeedMinimum();
  fireEvent.click(screen.getByRole("button", { name: /add relay/i }));
  fireEvent.change(screen.getByLabelText(/relay port/i), { target: { value: "3001" } });
  fireEvent.click(screen.getByRole("button", { name: /build certificate/i }));

  expect(screen.getByRole("alert")).toHaveTextContent(/relay host is required/i);
  expect(build).not.toHaveBeenCalled();
});

test("a relay port outside 0-65535 is rejected client-side", () => {
  const build = vi.spyOn(client, "poolBuildRegistration");
  renderReg();

  fillSeedMinimum();
  fireEvent.click(screen.getByRole("button", { name: /add relay/i }));
  fireEvent.change(screen.getByLabelText(/relay host/i), { target: { value: "1.2.3.4" } });
  fireEvent.change(screen.getByLabelText(/relay port/i), { target: { value: "99999" } });
  fireEvent.click(screen.getByRole("button", { name: /build certificate/i }));

  expect(screen.getByRole("alert")).toHaveTextContent(/must be an integer between 0 and 65535/i);
  expect(build).not.toHaveBeenCalled();
});

test("a non-positive margin denominator is rejected", () => {
  const build = vi.spyOn(client, "poolBuildRegistration");
  renderReg();

  fillSeedMinimum();
  fireEvent.change(screen.getByLabelText(/margin denominator/i), { target: { value: "0" } });
  fireEvent.click(screen.getByRole("button", { name: /build certificate/i }));

  expect(screen.getByRole("alert")).toHaveTextContent(
    /margin denominator must be greater than 0/i,
  );
  expect(build).not.toHaveBeenCalled();
});

test("a negative margin numerator is rejected", () => {
  const build = vi.spyOn(client, "poolBuildRegistration");
  renderReg();

  fillSeedMinimum();
  fireEvent.change(screen.getByLabelText(/margin numerator/i), { target: { value: "-1" } });
  fireEvent.click(screen.getByRole("button", { name: /build certificate/i }));

  expect(screen.getByRole("alert")).toHaveTextContent(
    /margin numerator must be greater than or equal to 0/i,
  );
  expect(build).not.toHaveBeenCalled();
});

// --- hand-off / error handling ---

test("documents that in-app submission is not yet wired (cert build + hand-off only)", () => {
  renderReg();
  expect(screen.getByText(/submitting a registration transaction in-app is not yet wired/i))
    .toBeInTheDocument();
  // There is no submit-transaction control on this screen — only a build.
  expect(screen.queryByRole("button", { name: /submit/i })).toBeNull();
});

test("surfaces an ApiError from a failed build", async () => {
  vi.spyOn(client, "poolBuildRegistration").mockRejectedValue(
    new client.ApiError(422, "reward account is not registered"),
  );
  renderReg();

  fillSeedMinimum();
  fireEvent.click(screen.getByRole("button", { name: /build certificate/i }));

  await waitFor(() =>
    expect(screen.getByRole("alert")).toHaveTextContent(/reward account is not registered/i),
  );
});
