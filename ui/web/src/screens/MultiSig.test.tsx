import { render, screen, fireEvent, waitFor } from "@testing-library/react";
import { MultiSig } from "./MultiSig";
import * as client from "../api/client";
import type { MultiSigAccount } from "../api/types";

afterEach(() => {
  vi.restoreAllMocks();
});

const KH_A = "a".repeat(56);
const KH_B = "b".repeat(56);

const sampleAccount: MultiSigAccount = {
  id: "acct1",
  label: "Treasury",
  network: "preview",
  policy: {
    threshold: 2,
    participants: [
      { key_hash_hex: KH_A, label: "me" },
      { key_hash_hex: KH_B },
    ],
  },
  script_cbor: "8201818200581c" + KH_A,
  script_address: "addr_test1wqscriptaddressxyz",
};

test("lists saved multi-sig accounts with their policy summary", async () => {
  vi.spyOn(client, "listMultiSig").mockResolvedValue([sampleAccount]);

  render(<MultiSig canSpend={true} canSign={true} />);

  expect(await screen.findByText("Treasury")).toBeInTheDocument();
  expect(screen.getByText(/2-of-2/)).toBeInTheDocument();
});

test("shows a user-facing error when listing multi-sig accounts fails", async () => {
  vi.spyOn(client, "listMultiSig").mockRejectedValue(new Error("list failed"));

  render(<MultiSig canSpend={true} canSign={true} />);

  expect(await screen.findByRole("alert")).toHaveTextContent("list failed");
});

test("create flow: reveals my-key and creates an account", async () => {
  vi.spyOn(client, "listMultiSig").mockResolvedValue([]);
  const myKey = vi
    .spyOn(client, "multiSigMyKey")
    .mockResolvedValue({ vkey_hex: "c".repeat(64), key_hash_hex: KH_A });
  const create = vi.spyOn(client, "createMultiSig").mockResolvedValue(sampleAccount);
  vi.spyOn(client, "multiSigBalance").mockResolvedValue({ lovelace: "0" });

  render(<MultiSig canSpend={true} canSign={true} />);

  fireEvent.click(await screen.findByRole("button", { name: /new multi-sig account/i }));

  fireEvent.change(screen.getByLabelText(/^label$/i), { target: { value: "Treasury" } });

  // Reveal my key.
  fireEvent.change(screen.getByLabelText(/spending password/i), { target: { value: "pw" } });
  fireEvent.click(screen.getByRole("button", { name: /reveal my key/i }));
  await waitFor(() => expect(myKey).toHaveBeenCalledWith("pw"));
  fireEvent.click(await screen.findByRole("button", { name: /add myself/i }));

  // Add a co-signer key-hash.
  fireEvent.change(screen.getByLabelText(/participant key hash/i), { target: { value: KH_B } });
  fireEvent.click(screen.getByRole("button", { name: /^add$/i }));

  fireEvent.click(screen.getByRole("button", { name: /create account/i }));

  await waitFor(() => expect(create).toHaveBeenCalled());
  const arg = create.mock.calls[0][0];
  expect(arg.label).toBe("Treasury");
  expect(arg.policy.threshold).toBe(2);
  expect(arg.policy.participants).toHaveLength(2);
});

test("seedless wallet can add external participants without revealing a local key", async () => {
  vi.spyOn(client, "listMultiSig").mockResolvedValue([]);

  render(<MultiSig canSpend={true} canSign={false} />);
  fireEvent.click(await screen.findByRole("button", { name: /new multi-sig account/i }));

  expect(screen.queryByText("Your participant key (CIP-1854)")).not.toBeInTheDocument();
  expect(screen.queryByRole("button", { name: /reveal my key/i })).not.toBeInTheDocument();
  expect(screen.getByLabelText(/participant key hash/i)).toBeInTheDocument();
});

test("create rejects a malformed co-signer key hash", async () => {
  vi.spyOn(client, "listMultiSig").mockResolvedValue([]);

  render(<MultiSig canSpend={true} canSign={true} />);
  fireEvent.click(await screen.findByRole("button", { name: /new multi-sig account/i }));

  fireEvent.change(screen.getByLabelText(/participant key hash/i), { target: { value: "xyz" } });
  fireEvent.click(screen.getByRole("button", { name: /^add$/i }));

  expect(await screen.findByText(/56 hex characters/i)).toBeInTheDocument();
});

test("delete flow removes the selected account from the list", async () => {
  vi.spyOn(client, "listMultiSig")
    .mockResolvedValueOnce([sampleAccount])
    .mockResolvedValueOnce([]);
  vi.spyOn(client, "multiSigBalance").mockResolvedValue({ lovelace: "0" });
  const del = vi.spyOn(client, "deleteMultiSig").mockResolvedValue({ status: "deleted" });

  render(<MultiSig canSpend={true} canSign={true} />);

  fireEvent.click(await screen.findByText("Treasury"));
  fireEvent.click(await screen.findByRole("button", { name: /^delete$/i }));

  await waitFor(() => expect(del).toHaveBeenCalledWith("acct1"));
  expect(await screen.findByText(/no multi-sig accounts yet/i)).toBeInTheDocument();
});

test("spend flow: build then collect a threshold of witnesses and submit", async () => {
  vi.spyOn(client, "listMultiSig").mockResolvedValue([sampleAccount]);
  const balance = vi
    .spyOn(client, "multiSigBalance")
    .mockResolvedValueOnce({ lovelace: "10000000" })
    .mockResolvedValueOnce({ lovelace: "7000000" });
  vi.spyOn(client, "multiSigBuild").mockResolvedValue({
    unsigned_tx_cbor: "84a400",
    required_signers: [KH_A, KH_B],
    threshold: 2,
  });
  const sign = vi.spyOn(client, "multiSigSign").mockResolvedValue({ witness_cbor: "81a0sigA" });
  const submit = vi.spyOn(client, "multiSigSubmit").mockResolvedValue({ tx_hash: "feedface" });

  render(<MultiSig canSpend={true} canSign={true} />);

  fireEvent.click(await screen.findByText("Treasury"));

  // Build a spend.
  fireEvent.change(await screen.findByLabelText(/recipient address/i), {
    target: { value: "addr_test1recipient" },
  });
  fireEvent.change(screen.getByLabelText(/amount \(ada\)/i), { target: { value: "3" } });
  fireEvent.click(screen.getByRole("button", { name: /build transaction/i }));

  // Collect screen: progress starts at 0 of 2.
  expect(await screen.findByText(/0 of 2 collected/i)).toBeInTheDocument();

  // Sign here (1 of 2).
  fireEvent.change(screen.getByLabelText(/sign with this wallet/i), { target: { value: "pw" } });
  fireEvent.click(screen.getByRole("button", { name: /sign here/i }));
  await waitFor(() => expect(sign).toHaveBeenCalled());
  expect(await screen.findByText(/1 of 2 collected/i)).toBeInTheDocument();

  // Paste a second co-signer witness (2 of 2 → threshold met).
  fireEvent.change(screen.getByLabelText(/co-signer witness/i), { target: { value: "81a0sigB" } });
  fireEvent.click(screen.getByRole("button", { name: /add witness/i }));
  expect(await screen.findByText(/2 of 2 collected/i)).toBeInTheDocument();

  // Submit.
  fireEvent.click(screen.getByRole("button", { name: /^submit$/i }));
  await waitFor(() =>
    expect(submit).toHaveBeenCalledWith("acct1", {
      unsigned_tx_cbor: "84a400",
      witnesses: ["81a0sigA", "81a0sigB"],
    }),
  );
  expect(await screen.findByText("feedface")).toBeInTheDocument();
  await waitFor(() => expect(balance).toHaveBeenCalledTimes(2));
  expect(await screen.findByText("7 ADA")).toBeInTheDocument();
});

test("seedless wallet can build, collect external witnesses, and submit without signing locally", async () => {
  vi.spyOn(client, "listMultiSig").mockResolvedValue([sampleAccount]);
  vi.spyOn(client, "multiSigBalance").mockResolvedValue({ lovelace: "10000000" });
  const build = vi.spyOn(client, "multiSigBuild").mockResolvedValue({
    unsigned_tx_cbor: "84a400",
    required_signers: [KH_A, KH_B],
    threshold: 2,
  });
  const sign = vi.spyOn(client, "multiSigSign");
  const submit = vi.spyOn(client, "multiSigSubmit").mockResolvedValue({ tx_hash: "feedface" });

  render(<MultiSig canSpend={true} canSign={false} />);
  fireEvent.click(await screen.findByText("Treasury"));

  fireEvent.change(await screen.findByLabelText(/recipient address/i), {
    target: { value: "addr_test1recipient" },
  });
  fireEvent.change(screen.getByLabelText(/amount \(ada\)/i), { target: { value: "3" } });
  fireEvent.click(screen.getByRole("button", { name: /build transaction/i }));
  await waitFor(() => expect(build).toHaveBeenCalled());

  expect(await screen.findByText(/0 of 2 collected/i)).toBeInTheDocument();
  expect(screen.queryByLabelText(/sign with this wallet/i)).not.toBeInTheDocument();
  expect(screen.queryByRole("button", { name: /sign here/i })).not.toBeInTheDocument();

  for (const witness of ["81a0sigA", "81a0sigB"]) {
    fireEvent.change(screen.getByLabelText(/co-signer witness/i), { target: { value: witness } });
    fireEvent.click(screen.getByRole("button", { name: /add witness/i }));
  }
  fireEvent.click(await screen.findByRole("button", { name: /^submit$/i }));

  await waitFor(() =>
    expect(submit).toHaveBeenCalledWith("acct1", {
      unsigned_tx_cbor: "84a400",
      witnesses: ["81a0sigA", "81a0sigB"],
    }),
  );
  expect(sign).not.toHaveBeenCalled();
});

test("shows a user-facing error when building a multi-sig spend fails", async () => {
  vi.spyOn(client, "listMultiSig").mockResolvedValue([sampleAccount]);
  vi.spyOn(client, "multiSigBalance").mockResolvedValue({ lovelace: "10000000" });
  vi.spyOn(client, "multiSigBuild").mockRejectedValue(new Error("build failed"));

  render(<MultiSig canSpend={true} canSign={true} />);

  fireEvent.click(await screen.findByText("Treasury"));
  fireEvent.change(await screen.findByLabelText(/recipient address/i), {
    target: { value: "addr_test1recipient" },
  });
  fireEvent.change(screen.getByLabelText(/amount \(ada\)/i), { target: { value: "3" } });
  fireEvent.click(screen.getByRole("button", { name: /build transaction/i }));

  expect(await screen.findByRole("alert")).toHaveTextContent("build failed");
});

test("submit is disabled until the threshold is met", async () => {
  vi.spyOn(client, "listMultiSig").mockResolvedValue([sampleAccount]);
  vi.spyOn(client, "multiSigBalance").mockResolvedValue({ lovelace: "10000000" });
  vi.spyOn(client, "multiSigBuild").mockResolvedValue({
    unsigned_tx_cbor: "84a400",
    required_signers: [KH_A, KH_B],
    threshold: 2,
  });

  render(<MultiSig canSpend={true} canSign={true} />);
  fireEvent.click(await screen.findByText("Treasury"));
  fireEvent.change(await screen.findByLabelText(/recipient address/i), {
    target: { value: "addr_test1recipient" },
  });
  fireEvent.change(screen.getByLabelText(/amount \(ada\)/i), { target: { value: "3" } });
  fireEvent.click(screen.getByRole("button", { name: /build transaction/i }));

  // The submit button reads "Need 2 more" and is disabled.
  expect(await screen.findByRole("button", { name: /need 2 more/i })).toBeDisabled();
});

test("spend is unavailable when canSpend is false", async () => {
  vi.spyOn(client, "listMultiSig").mockResolvedValue([sampleAccount]);
  vi.spyOn(client, "multiSigBalance").mockResolvedValue({ lovelace: "0" });

  render(<MultiSig canSpend={false} canSign={true} />);
  fireEvent.click(await screen.findByText("Treasury"));

  expect(
    await screen.findByText(/spending needs a fully synced node/i),
  ).toBeInTheDocument();
});
