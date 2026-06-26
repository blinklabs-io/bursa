import { render, screen, fireEvent, waitFor } from "@testing-library/react";
import { Setup } from "./Setup";
import * as client from "../api/client";
import type { Account } from "../api/types";

const mockAccount: Account = {
  network: "preview",
  stake_address: "stake_test1abc",
  receive_addresses: ["addr_test1abc"],
};

afterEach(() => {
  vi.restoreAllMocks();
});

test("(a) no password → calls loadWallet and invokes onLoaded with returned account", async () => {
  const loadWalletSpy = vi.spyOn(client, "loadWallet").mockResolvedValue(mockAccount);
  const onLoaded = vi.fn();

  render(<Setup network="preview" onLoaded={onLoaded} />);

  fireEvent.change(screen.getByRole("textbox", { name: /mnemonic/i }), {
    target: { value: "word1 word2 word3 word4 word5 word6 word7 word8 word9 word10 word11 word12" },
  });

  fireEvent.click(screen.getByRole("button", { name: /load wallet/i }));

  await waitFor(() => expect(loadWalletSpy).toHaveBeenCalledWith({
    mnemonic: "word1 word2 word3 word4 word5 word6 word7 word8 word9 word10 word11 word12",
    network: "preview",
  }));
  await waitFor(() => expect(onLoaded).toHaveBeenCalledWith(mockAccount, false));
});

test("(b) with password → calls createKeystore", async () => {
  const createKeystoreSpy = vi.spyOn(client, "createKeystore").mockResolvedValue(mockAccount);
  const onLoaded = vi.fn();

  render(<Setup network="preview" onLoaded={onLoaded} />);

  fireEvent.change(screen.getByRole("textbox", { name: /mnemonic/i }), {
    target: { value: "word1 word2 word3 word4 word5 word6 word7 word8 word9 word10 word11 word12" },
  });

  fireEvent.change(screen.getByLabelText(/spending password/i), {
    target: { value: "mysecretpassword" },
  });

  fireEvent.click(screen.getByRole("button", { name: /load wallet/i }));

  await waitFor(() => expect(createKeystoreSpy).toHaveBeenCalledWith({
    mnemonic: "word1 word2 word3 word4 word5 word6 word7 word8 word9 word10 word11 word12",
    network: "preview",
    password: "mysecretpassword",
  }));
  await waitFor(() => expect(onLoaded).toHaveBeenCalledWith(mockAccount, true));
});

test("(c) ApiError from createKeystore renders the error message", async () => {
  vi.spyOn(client, "createKeystore").mockRejectedValue(
    new client.ApiError(400, "node rejected the keystore request"),
  );
  const onLoaded = vi.fn();

  render(<Setup network="preview" onLoaded={onLoaded} />);

  fireEvent.change(screen.getByRole("textbox", { name: /mnemonic/i }), {
    target: { value: "word1 word2 word3 word4 word5 word6 word7 word8 word9 word10 word11 word12" },
  });

  fireEvent.change(screen.getByLabelText(/spending password/i), {
    target: { value: "a-valid-spending-password" },
  });

  fireEvent.click(screen.getByRole("button", { name: /load wallet/i }));

  await waitFor(() =>
    expect(screen.getByText("node rejected the keystore request")).toBeInTheDocument(),
  );
  expect(onLoaded).not.toHaveBeenCalled();
});

test("(d) a too-short spending password is rejected client-side before any request", async () => {
  const createKeystoreSpy = vi.spyOn(client, "createKeystore");
  const onLoaded = vi.fn();

  render(<Setup network="preview" onLoaded={onLoaded} />);

  fireEvent.change(screen.getByRole("textbox", { name: /mnemonic/i }), {
    target: { value: "word1 word2 word3 word4 word5 word6 word7 word8 word9 word10 word11 word12" },
  });

  fireEvent.change(screen.getByLabelText(/spending password/i), {
    target: { value: "short" },
  });

  fireEvent.click(screen.getByRole("button", { name: /load wallet/i }));

  await waitFor(() =>
    expect(screen.getByText(/at least 12 characters/i)).toBeInTheDocument(),
  );
  // The short password never reaches the node.
  expect(createKeystoreSpy).not.toHaveBeenCalled();
  expect(onLoaded).not.toHaveBeenCalled();
});
