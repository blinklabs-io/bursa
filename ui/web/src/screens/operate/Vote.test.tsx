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
