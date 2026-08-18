import { render, screen, fireEvent, waitFor } from "@testing-library/react";
import { ComposeMultiSig, MultiSigSpend } from "./MultiSig";
import * as client from "../api/client";
import type { MultiSigAccount, WalletView } from "../api/types";

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

const createdWallet: WalletView = {
  id: "acct1",
  name: "Treasury",
  network: "preview",
  stake_address: "",
  addresses: ["addr_test1wqscriptaddressxyz"],
  active: true,
  type: "multi_signature",
  multisig: sampleAccount,
};

// --- Composing a multi-signature wallet -----------------------------------

test("composes a policy into a wallet, revealing this wallet's own key first", async () => {
  const myKey = vi
    .spyOn(client, "multiSigMyKey")
    .mockResolvedValue({ vkey_hex: "c".repeat(64), key_hash_hex: KH_A });
  const create = vi.spyOn(client, "createMultiSig").mockResolvedValue(createdWallet);
  const onCreated = vi.fn();

  render(<ComposeMultiSig canSign onCancel={vi.fn()} onCreated={onCreated} />);

  fireEvent.change(screen.getByLabelText(/^label$/i), { target: { value: "Treasury" } });

  fireEvent.change(screen.getByLabelText(/spending password/i), { target: { value: "pw" } });
  fireEvent.click(screen.getByRole("button", { name: /reveal my key/i }));
  await waitFor(() => expect(myKey).toHaveBeenCalledWith("pw"));
  fireEvent.click(await screen.findByRole("button", { name: /add myself/i }));

  fireEvent.change(screen.getByLabelText(/participant key hash/i), { target: { value: KH_B } });
  fireEvent.click(screen.getByRole("button", { name: /^add$/i }));

  // Storing it is a vault write, so it needs the vault password like any other
  // add-wallet path.
  fireEvent.change(screen.getByLabelText(/vault password/i), { target: { value: "vault-pw" } });
  fireEvent.click(screen.getByRole("button", { name: /create wallet/i }));

  await waitFor(() => expect(create).toHaveBeenCalled());
  const arg = create.mock.calls[0][0];
  expect(arg.label).toBe("Treasury");
  expect(arg.policy.threshold).toBe(2);
  expect(arg.policy.participants).toHaveLength(2);
  expect(arg.vault_password).toBe("vault-pw");

  // The result is a wallet, and it goes back to the add-wallet flow as one.
  expect(onCreated).toHaveBeenCalledWith(createdWallet);
});

test("cannot create without the vault password", () => {
  render(<ComposeMultiSig canSign onCancel={vi.fn()} onCreated={vi.fn()} />);

  fireEvent.change(screen.getByLabelText(/participant key hash/i), { target: { value: KH_B } });
  fireEvent.click(screen.getByRole("button", { name: /^add$/i }));

  expect(screen.getByRole("button", { name: /create wallet/i })).toBeDisabled();
});

test("a seedless wallet can add external participants without revealing a local key", () => {
  render(<ComposeMultiSig canSign={false} onCancel={vi.fn()} onCreated={vi.fn()} />);

  expect(screen.queryByText("Your participant key (CIP-1854)")).not.toBeInTheDocument();
  expect(screen.queryByRole("button", { name: /reveal my key/i })).not.toBeInTheDocument();
  expect(screen.getByLabelText(/participant key hash/i)).toBeInTheDocument();
});

test("rejects a malformed co-signer key hash", async () => {
  render(<ComposeMultiSig canSign onCancel={vi.fn()} onCreated={vi.fn()} />);

  fireEvent.change(screen.getByLabelText(/participant key hash/i), { target: { value: "xyz" } });
  fireEvent.click(screen.getByRole("button", { name: /^add$/i }));

  expect(await screen.findByText(/56 hex characters/i)).toBeInTheDocument();
});

// --- Spending from one -----------------------------------------------------

function renderSpend(canSign = true, canSpend = true) {
  return render(
    <MultiSigSpend
      account={sampleAccount}
      canSpend={canSpend}
      canSign={canSign}
      onSpent={vi.fn()}
    />,
  );
}

async function buildASpend() {
  fireEvent.change(await screen.findByLabelText(/recipient address/i), {
    target: { value: "addr_test1recipient" },
  });
  fireEvent.change(screen.getByLabelText(/amount \(ada\)/i), { target: { value: "3" } });
  fireEvent.click(screen.getByRole("button", { name: /build transaction/i }));
}

test("build, collect a threshold of witnesses, submit", async () => {
  vi.spyOn(client, "multiSigBuild").mockResolvedValue({
    unsigned_tx_cbor: "84a400",
    required_signers: [KH_A, KH_B],
    threshold: 2,
  });
  const sign = vi.spyOn(client, "multiSigSign").mockResolvedValue({ witness_cbor: "81a0sigA" });
  const submit = vi.spyOn(client, "multiSigSubmit").mockResolvedValue({ tx_hash: "feedface" });

  renderSpend();
  await buildASpend();

  expect(await screen.findByText(/0 of 2 signed/i)).toBeInTheDocument();

  fireEvent.change(screen.getByLabelText(/sign with this wallet/i), { target: { value: "pw" } });
  fireEvent.click(screen.getByRole("button", { name: /sign here/i }));
  await waitFor(() => expect(sign).toHaveBeenCalled());
  expect(await screen.findByText(/1 of 2 signed/i)).toBeInTheDocument();

  fireEvent.change(screen.getByLabelText(/co-signer witness/i), { target: { value: "81a0sigB" } });
  fireEvent.click(screen.getByRole("button", { name: /add witness/i }));
  expect(await screen.findByText(/2 of 2 signed/i)).toBeInTheDocument();
  expect(await screen.findByText(/threshold met/i)).toBeInTheDocument();

  fireEvent.click(screen.getByRole("button", { name: /^submit$/i }));
  await waitFor(() =>
    expect(submit).toHaveBeenCalledWith("acct1", {
      unsigned_tx_cbor: "84a400",
      witnesses: ["81a0sigA", "81a0sigB"],
    }),
  );
  expect(await screen.findByText("feedface")).toBeInTheDocument();
});

test("a seedless wallet can collect external witnesses and submit without signing locally", async () => {
  const build = vi.spyOn(client, "multiSigBuild").mockResolvedValue({
    unsigned_tx_cbor: "84a400",
    required_signers: [KH_A, KH_B],
    threshold: 2,
  });
  const sign = vi.spyOn(client, "multiSigSign");
  const submit = vi.spyOn(client, "multiSigSubmit").mockResolvedValue({ tx_hash: "feedface" });

  renderSpend(false);
  await buildASpend();
  await waitFor(() => expect(build).toHaveBeenCalled());

  expect(await screen.findByText(/0 of 2 signed/i)).toBeInTheDocument();
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

test("shows a user-facing error when building fails", async () => {
  vi.spyOn(client, "multiSigBuild").mockRejectedValue(new Error("build failed"));

  renderSpend();
  await buildASpend();

  expect(await screen.findByRole("alert")).toHaveTextContent("build failed");
});

test("submit stays disabled until the threshold is met", async () => {
  vi.spyOn(client, "multiSigBuild").mockResolvedValue({
    unsigned_tx_cbor: "84a400",
    required_signers: [KH_A, KH_B],
    threshold: 2,
  });

  renderSpend();
  await buildASpend();

  expect(await screen.findByRole("button", { name: /need 2 more/i })).toBeDisabled();
});

test("spending is unavailable without a synced node", async () => {
  renderSpend(true, false);

  expect(await screen.findByText(/spending needs a fully synced node/i)).toBeInTheDocument();
});
