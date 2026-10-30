import { render, screen, fireEvent, waitFor } from "@testing-library/react";
import { Vote } from "./Vote";
import * as client from "../../api/client";

afterEach(() => {
  vi.restoreAllMocks();
});

test("submits vote and shows tx hash", async () => {
  const submit = vi
    .spyOn(client, "poolSubmitVote")
    .mockResolvedValue({ tx_hash: "abc123" });
  render(<Vote />);

  fireEvent.change(screen.getByLabelText(/governance action tx id/i), {
    target: { value: "a".repeat(64) },
  });
  fireEvent.change(screen.getByLabelText(/action index/i), { target: { value: "0" } });
  fireEvent.change(screen.getByLabelText(/vote/i), { target: { value: "yes" } });
  fireEvent.change(screen.getByLabelText(/spending password/i), { target: { value: "pw" } });
  fireEvent.click(screen.getByRole("button", { name: /submit vote/i }));

  await waitFor(() =>
    expect(submit).toHaveBeenCalledWith({
      password: "pw",
      action_tx_id: "a".repeat(64),
      action_index: 0,
      vote: "yes",
    }),
  );
  expect(await screen.findByText("abc123")).toBeInTheDocument();
});

// --- validation ---

test("invalid input is not submitted", () => {
  const submit = vi.spyOn(client, "poolSubmitVote");
  render(<Vote />);

  // Missing required fields
  fireEvent.click(screen.getByRole("button", { name: /submit vote/i }));
  expect(screen.getByRole("alert")).toBeInTheDocument();
  expect(submit).not.toHaveBeenCalled();
});

test("rejects bad tx id before submit", () => {
  const submit = vi.spyOn(client, "poolSubmitVote");
  render(<Vote />);

  fireEvent.change(screen.getByLabelText(/governance action tx id/i), {
    target: { value: "bad" },
  });
  fireEvent.change(screen.getByLabelText(/action index/i), { target: { value: "0" } });
  fireEvent.change(screen.getByLabelText(/spending password/i), { target: { value: "pw" } });
  fireEvent.click(screen.getByRole("button", { name: /submit vote/i }));

  expect(screen.getByRole("alert")).toBeInTheDocument();
  expect(submit).not.toHaveBeenCalled();
});

test("anchor submit passes url and hash to client and clears password after success", async () => {
  const submit = vi
    .spyOn(client, "poolSubmitVote")
    .mockResolvedValue({ tx_hash: "abc123" });
  render(<Vote />);

  fireEvent.change(screen.getByLabelText(/governance action tx id/i), {
    target: { value: "b".repeat(64) },
  });
  fireEvent.change(screen.getByLabelText(/action index/i), { target: { value: "3" } });
  fireEvent.change(screen.getByLabelText(/vote/i), { target: { value: "yes" } });
  fireEvent.change(screen.getByLabelText(/anchor url/i), {
    target: { value: "ipfs://QmTest" },
  });
  fireEvent.change(screen.getByLabelText(/anchor hash/i), {
    target: { value: "c".repeat(64) },
  });
  const pw = screen.getByLabelText(/spending password/i);
  fireEvent.change(pw, { target: { value: "pw" } });
  fireEvent.click(screen.getByRole("button", { name: /submit vote/i }));

  await waitFor(() =>
    expect(submit).toHaveBeenCalledWith({
      password: "pw",
      action_tx_id: "b".repeat(64),
      action_index: 3,
      vote: "yes",
      anchor_url: "ipfs://QmTest",
      anchor_hash: "c".repeat(64),
    }),
  );
  await waitFor(() => expect(pw).toHaveValue(""));
});

test("non-zero index passed through", async () => {
  const submit = vi
    .spyOn(client, "poolSubmitVote")
    .mockResolvedValue({ tx_hash: "def456" });
  render(<Vote />);

  fireEvent.change(screen.getByLabelText(/governance action tx id/i), {
    target: { value: "d".repeat(64) },
  });
  fireEvent.change(screen.getByLabelText(/action index/i), { target: { value: "7" } });
  fireEvent.change(screen.getByLabelText(/spending password/i), { target: { value: "pw" } });
  fireEvent.click(screen.getByRole("button", { name: /submit vote/i }));

  await waitFor(() =>
    expect(submit).toHaveBeenCalledWith(
      expect.objectContaining({ action_index: 7 }),
    ),
  );
});

test("clears password after a rejected submit", async () => {
  vi.spyOn(client, "poolSubmitVote").mockRejectedValue(new Error("boom"));
  render(<Vote />);

  fireEvent.change(screen.getByLabelText(/governance action tx id/i), {
    target: { value: "e".repeat(64) },
  });
  fireEvent.change(screen.getByLabelText(/action index/i), { target: { value: "1" } });
  const pw = screen.getByLabelText(/spending password/i);
  fireEvent.change(pw, { target: { value: "pw" } });
  fireEvent.click(screen.getByRole("button", { name: /submit vote/i }));

  expect(await screen.findByRole("alert")).toHaveTextContent("boom");
  expect(pw).toHaveValue("");
});

test("validation rejects an anchor url without a hash", () => {
  const submit = vi.spyOn(client, "poolSubmitVote");
  render(<Vote />);

  // anchor url without hash
  fireEvent.change(screen.getByLabelText(/governance action tx id/i), {
    target: { value: "e".repeat(64) },
  });
  fireEvent.change(screen.getByLabelText(/action index/i), { target: { value: "1" } });
  fireEvent.change(screen.getByLabelText(/anchor url/i), {
    target: { value: "ipfs://x" },
  });
  const pw = screen.getByLabelText(/spending password/i);
  fireEvent.change(pw, { target: { value: "pw" } });
  fireEvent.click(screen.getByRole("button", { name: /submit vote/i }));
  expect(screen.getByRole("alert")).toBeInTheDocument();
  expect(submit).not.toHaveBeenCalled();
});

test("rejects bad hash, index 65536, and 129-byte url", () => {
  const submit = vi.spyOn(client, "poolSubmitVote");
  render(<Vote />);

  // bad hash
  fireEvent.change(screen.getByLabelText(/governance action tx id/i), {
    target: { value: "f".repeat(64) },
  });
  fireEvent.change(screen.getByLabelText(/action index/i), { target: { value: "0" } });
  fireEvent.change(screen.getByLabelText(/anchor url/i), {
    target: { value: "ipfs://x" },
  });
  fireEvent.change(screen.getByLabelText(/anchor hash/i), {
    target: { value: "gg" },
  });
  fireEvent.change(screen.getByLabelText(/spending password/i), { target: { value: "pw" } });
  fireEvent.click(screen.getByRole("button", { name: /submit vote/i }));
  expect(screen.getByRole("alert")).toBeInTheDocument();
  expect(submit).not.toHaveBeenCalled();

  // index 65536
  fireEvent.change(screen.getByLabelText(/action index/i), { target: { value: "65536" } });
  fireEvent.change(screen.getByLabelText(/anchor url/i), { target: { value: "" } });
  fireEvent.change(screen.getByLabelText(/anchor hash/i), { target: { value: "" } });
  fireEvent.click(screen.getByRole("button", { name: /submit vote/i }));
  expect(screen.getByRole("alert")).toBeInTheDocument();
  expect(submit).not.toHaveBeenCalled();

  // 129-byte URL
  const longUrl = "http://" + "a".repeat(122);
  fireEvent.change(screen.getByLabelText(/action index/i), { target: { value: "0" } });
  fireEvent.change(screen.getByLabelText(/anchor url/i), { target: { value: longUrl } });
  fireEvent.change(screen.getByLabelText(/anchor hash/i), { target: { value: "a".repeat(64) } });
  fireEvent.click(screen.getByRole("button", { name: /submit vote/i }));
  expect(screen.getByRole("alert")).toBeInTheDocument();
  expect(submit).not.toHaveBeenCalled();
});
