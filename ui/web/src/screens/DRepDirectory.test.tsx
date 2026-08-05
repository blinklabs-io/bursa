import { render, screen, fireEvent, waitFor } from "@testing-library/react";
import { DRepDirectory } from "./DRepDirectory";
import * as client from "../api/client";
import type { DRepInfo, DRepDirectoryResponse } from "../api/types";

const DREP_A: DRepInfo = {
  drep_id: "drep1aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa0001",
  hex: "aa",
  has_script: false,
  registered: true,
  amount: "1500000000",
  active: true,
  live_stake: "1500000000",
  anchor_url: "https://example.com/drep-a.json",
};

const DREP_B: DRepInfo = {
  drep_id: "drep1bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb0002",
  hex: "bb",
  has_script: true,
  registered: false,
  amount: "0",
  active: false,
  live_stake: "0",
};

function directory(dreps: DRepInfo[], overrides?: Partial<DRepDirectoryResponse>): DRepDirectoryResponse {
  return { dreps, total: dreps.length, page: 1, count: 50, ...overrides };
}

afterEach(() => {
  vi.restoreAllMocks();
});

test("lists DReps read from the node with formatted voting power and status", async () => {
  vi.spyOn(client, "getDReps").mockResolvedValue(directory([DREP_A, DREP_B]));

  render(<DRepDirectory network="preview" />);

  // 1500000000 lovelace → 1500 ADA; active/inactive statuses shown.
  expect(await screen.findByText("1500")).toBeInTheDocument();
  expect(screen.getByText("Active")).toBeInTheDocument();
  expect(screen.getByText("Inactive")).toBeInTheDocument();
  // Copy affordance carries the full (untruncated) drep id.
  expect(
    screen.getByRole("button", { name: `Copy drep id ${DREP_A.drep_id}` }),
  ).toBeInTheDocument();
});

test("search box queries the node server-side with the typed term", async () => {
  const getDReps = vi
    .spyOn(client, "getDReps")
    .mockResolvedValue(directory([DREP_A]));

  render(<DRepDirectory network="preview" />);
  await screen.findByText("Active");

  getDReps.mockResolvedValue(directory([DREP_B]));
  fireEvent.change(screen.getByLabelText(/search by drep id/i), {
    target: { value: "bbb" },
  });

  await waitFor(() =>
    expect(getDReps).toHaveBeenLastCalledWith({ q: "bbb", page: 1 }),
  );
  await waitFor(() =>
    expect(
      screen.getByRole("button", { name: `Copy drep id ${DREP_B.drep_id}` }),
    ).toBeInTheDocument(),
  );
});

test("shows an empty message when nothing matches", async () => {
  vi.spyOn(client, "getDReps").mockResolvedValue(directory([], { total: 0 }));

  render(<DRepDirectory network="preview" />);
  expect(await screen.findByText(/no dreps found/i)).toBeInTheDocument();
});

test("surfaces an API error", async () => {
  vi.spyOn(client, "getDReps").mockRejectedValue(
    new client.ApiError(503, "node not ready"),
  );

  render(<DRepDirectory network="preview" />);
  expect(await screen.findByRole("alert")).toHaveTextContent(/node not ready/i);
  // The error is the sole result state — it must not also claim no DReps
  // were found, which would misrepresent a failed request as an empty one.
  expect(screen.queryByText(/no dreps found/i)).not.toBeInTheDocument();
});

test("hides the Delegate shortcut when the active wallet cannot stake", async () => {
  vi.spyOn(client, "getDReps").mockResolvedValue(directory([DREP_A]));

  render(<DRepDirectory network="preview" canDelegate={false} />);

  expect(
    await screen.findByRole("button", { name: `Copy drep id ${DREP_A.drep_id}` }),
  ).toBeInTheDocument();
  expect(screen.queryByRole("button", { name: "Delegate" })).not.toBeInTheDocument();
});
