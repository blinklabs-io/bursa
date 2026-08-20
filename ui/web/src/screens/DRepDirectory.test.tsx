import { render, screen, fireEvent, waitFor } from "@testing-library/react";
import { DRepDirectory } from "./DRepDirectory";
import * as client from "../api/client";
import type { DRepListItem, DRepDirectoryResponse } from "../api/types";

const DREP_A: DRepListItem = {
  drep_id: "drep1aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa0001",
  hex: "22aa",
  has_script: false,
  amount: "1500000000",
  retired: false,
  expired: false,
  last_active_epoch: 512,
  metadata: { url: "https://example.com/drep-a.json", hash: "cafe" },
};

const DREP_B: DRepListItem = {
  drep_id: "drep1bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb0002",
  hex: "23bb",
  has_script: true,
  amount: "0",
  retired: true,
  expired: false,
  last_active_epoch: null,
  metadata: null,
};

// Registered, but past the node's DRep inactivity period without voting: the
// row the old `active` column rendered as "Active".
const DREP_EXPIRED: DRepListItem = {
  drep_id: "drep1cccccccccccccccccccccccccccccccccccccccccccccccccc0003",
  hex: "22cc",
  has_script: false,
  amount: "9000000",
  retired: false,
  expired: true,
  last_active_epoch: 480,
  metadata: null,
};

// One of the two predefined targets the node interleaves into its list. It has
// no bech32 id and no credential hex, and is chosen in Staking rather than by
// pasting an id.
const DREP_ABSTAIN: DRepListItem = {
  drep_id: "drep_always_abstain",
  hex: "",
  has_script: false,
  amount: "7000000000",
  retired: false,
  expired: false,
  last_active_epoch: null,
  metadata: null,
};

function directory(dreps: DRepListItem[], overrides?: Partial<DRepDirectoryResponse>): DRepDirectoryResponse {
  return { dreps, total: dreps.length, page: 1, count: 50, ...overrides };
}

afterEach(() => {
  vi.restoreAllMocks();
});

test("lists DReps read from the node with formatted voting power and status", async () => {
  vi.spyOn(client, "getDReps").mockResolvedValue(directory([DREP_A, DREP_B]));

  render(<DRepDirectory network="preview" />);

  // 1500000000 lovelace → 1,500 ADA (grouped).
  expect(await screen.findByText("1,500")).toBeInTheDocument();
  expect(screen.getByText("Registered")).toBeInTheDocument();
  expect(screen.getByText("Retired")).toBeInTheDocument();
  // Copy affordance carries the full (untruncated) drep id.
  expect(
    screen.getByRole("button", { name: `Copy drep id ${DREP_A.drep_id}` }),
  ).toBeInTheDocument();
});

test("distinguishes registered, retired and expired DReps", async () => {
  // The node's list has no single "active" flag: a DRep that registered and
  // then stopped voting is still registered but expired under CIP-1694, and
  // must not read the same as one that deregistered.
  vi.spyOn(client, "getDReps").mockResolvedValue(
    directory([DREP_A, DREP_B, DREP_EXPIRED]),
  );

  render(<DRepDirectory network="preview" />);

  expect(await screen.findByText("Registered")).toBeInTheDocument();
  expect(screen.getByText("Retired")).toBeInTheDocument();
  const expired = screen.getByText("Expired");
  expect(expired).toBeInTheDocument();
  // The epoch it was last active in is what tells an operator how stale it is.
  expect(expired).toHaveAttribute("title", expect.stringContaining("480"));
});

test("shows the metadata anchor the node resolved, without fetching it", async () => {
  vi.spyOn(client, "getDReps").mockResolvedValue(directory([DREP_A, DREP_B]));

  render(<DRepDirectory network="preview" />);

  const anchor = await screen.findByTitle("https://example.com/drep-a.json");
  expect(anchor).toBeInTheDocument();
  // It is display-only text, never a link the user can follow from here.
  expect(anchor.closest("a")).toBeNull();
  // A DRep with no anchor renders a placeholder rather than an empty cell.
  expect(screen.getByText("—")).toBeInTheDocument();
});

test("renders the predefined DReps as targets chosen in Staking", async () => {
  vi.spyOn(client, "getDReps").mockResolvedValue(directory([DREP_ABSTAIN]));

  render(<DRepDirectory network="preview" />);

  // Listed deliberately: they carry real delegated voting power (7,000 ADA
  // here), so hiding them would understate what the node indexed.
  expect(await screen.findByText("drep_always_abstain")).toBeInTheDocument();
  expect(screen.getByText("7,000")).toBeInTheDocument();
  expect(screen.getByText("Predefined")).toBeInTheDocument();
  // They have no on-chain registration to look up and no id worth pasting —
  // Staking offers them as their own options — so neither affordance is shown.
  expect(
    screen.queryByRole("button", { name: /copy drep id/i }),
  ).not.toBeInTheDocument();
  expect(screen.queryByRole("link")).not.toBeInTheDocument();
});

test("search box queries the node server-side with the typed term", async () => {
  const getDReps = vi
    .spyOn(client, "getDReps")
    .mockResolvedValue(directory([DREP_A]));

  render(<DRepDirectory network="preview" />);
  await screen.findByText("Registered");

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

  const { container } = render(
    <DRepDirectory network="preview" canDelegate={false} />,
  );

  expect(
    await screen.findByRole("button", { name: `Copy drep id ${DREP_A.drep_id}` }),
  ).toBeInTheDocument();
  expect(screen.queryByRole("button", { name: "Delegate" })).not.toBeInTheDocument();
  // The intro copy must not point users at a "Delegate" shortcut that isn't
  // rendered for read-only/hardware wallets.
  const helperText = container.querySelector(".helper-text")?.textContent ?? "";
  expect(helperText).toMatch(/paste it into Staking\.$/);
  expect(helperText).not.toMatch(/or use Delegate/);
});

test("mentions the Delegate shortcut in the intro copy when it is available", async () => {
  vi.spyOn(client, "getDReps").mockResolvedValue(directory([DREP_A]));

  const { container } = render(<DRepDirectory network="preview" />);
  await screen.findByText("Registered");

  const helperText = container.querySelector(".helper-text")?.textContent ?? "";
  expect(helperText).toMatch(/or use Delegate\.$/);
});

test("marks the results stale while a new page is still loading", async () => {
  // The pager advances to the requested page immediately, so the rows for the
  // previous page must not read as the answer to the new one.
  let resolveSecond: ((value: DRepDirectoryResponse) => void) | undefined;
  const pending = new Promise<DRepDirectoryResponse>((resolve) => {
    resolveSecond = resolve;
  });
  let call = 0;
  vi.spyOn(client, "getDReps").mockImplementation(() => {
    call += 1;
    return call === 1
      ? Promise.resolve(directory([DREP_A], { total: 100, count: 1 }))
      : pending;
  });

  render(<DRepDirectory network="preview" />);
  await screen.findByText(/drep1aaaa/i);

  const busyRegion = () => screen.getByText(/drep1aaaa/i).closest("[aria-busy]");
  expect(busyRegion()).toHaveAttribute("aria-busy", "false");

  fireEvent.click(screen.getByRole("button", { name: /next/i }));

  // Still showing page 1's row, but now explicitly marked busy, so the stale
  // rows do not silently read as page 2.
  await waitFor(() => {
    expect(busyRegion()).toHaveAttribute("aria-busy", "true");
  });
  expect(screen.getByRole("status")).toHaveTextContent(/updating/i);

  resolveSecond?.(directory([DREP_B], { total: 100, count: 1, page: 2 }));
  await waitFor(() => {
    expect(screen.queryByRole("status")).toBeNull();
  });
});

test("marks an empty result set busy while the next query loads", async () => {
  // The previous search matching nothing must not leave "No DReps match your
  // search." standing as the answer to the query now in flight.
  let resolveSecond: ((value: DRepDirectoryResponse) => void) | undefined;
  const pending = new Promise<DRepDirectoryResponse>((resolve) => {
    resolveSecond = resolve;
  });
  let call = 0;
  vi.spyOn(client, "getDReps").mockImplementation(() => {
    call += 1;
    return call === 1 ? Promise.resolve(directory([])) : pending;
  });

  render(<DRepDirectory network="preview" />);
  const empty = await screen.findByText(/no dreps found/i);
  expect(empty.closest("[aria-busy]")).toHaveAttribute("aria-busy", "false");

  fireEvent.change(screen.getByLabelText(/search by drep id/i), {
    target: { value: "zzz" },
  });

  await waitFor(() => {
    expect(
      screen.getByText(/no dreps/i).closest("[aria-busy]"),
    ).toHaveAttribute("aria-busy", "true");
  });
  expect(screen.getByRole("status")).toHaveTextContent(/updating/i);

  resolveSecond?.(directory([DREP_A]));
  await screen.findByText(/drep1aaaa/i);
});
