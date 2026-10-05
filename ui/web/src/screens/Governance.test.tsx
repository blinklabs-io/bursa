import { render, screen, fireEvent, waitFor, within } from "@testing-library/react";
import { Governance } from "./Governance";
import * as client from "../api/client";
import type { GovernanceAction, GovernanceActionsResponse, SurveySummary } from "../api/types";

const ACTION_A: GovernanceAction = {
  action_id: "gov_action1aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaqqq0001",
  tx_hash: "aa",
  action_index: 0,
  type: "info",
  proposed_epoch: 100,
  expires_epoch: 130,
  status: "active",
  anchor_url: "https://example.test/info.json",
  deposit: "100000000000",
  yes_votes: 2,
  no_votes: 1,
  abstain_votes: 3,
};

const ACTION_B: GovernanceAction = {
  action_id: "gov_action1bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbqqq0002",
  tx_hash: "bb",
  action_index: 1,
  type: "treasury-withdrawal",
  proposed_epoch: 90,
  expires_epoch: 120,
  status: "enacted",
  anchor_url: "",
  deposit: "100000000000",
  yes_votes: 10,
  no_votes: 0,
  abstain_votes: 0,
};

function response(
  actions: GovernanceAction[],
  overrides?: Partial<GovernanceActionsResponse>,
): GovernanceActionsResponse {
  return { actions, total: actions.length, page: 1, count: 50, ...overrides };
}

afterEach(() => {
  vi.restoreAllMocks();
});

test("lists governance actions read from the node with type, status, and tallies", async () => {
  vi.spyOn(client, "getGovernanceActions").mockResolvedValue(response([ACTION_A, ACTION_B]));

  render(<Governance network="preview" />);

  expect(await screen.findByText("Info")).toBeInTheDocument();
  expect(screen.getByText("Treasury withdrawal")).toBeInTheDocument();
  expect(screen.getByText("Active")).toBeInTheDocument();
  expect(screen.getByText("Enacted")).toBeInTheDocument();
  // Vote tallies rendered as Y / N / A.
  expect(screen.getByText("2 / 1 / 3")).toBeInTheDocument();
  // Copy affordance carries the full (untruncated) action id.
  expect(
    screen.getByRole("button", { name: `Copy action id ${ACTION_A.action_id}` }),
  ).toBeInTheDocument();
});

test("search box queries the node server-side with the typed term", async () => {
  const getGovernanceActions = vi
    .spyOn(client, "getGovernanceActions")
    .mockResolvedValue(response([ACTION_A, ACTION_B]));

  render(<Governance network="preview" />);
  await screen.findByText("Info");

  getGovernanceActions.mockResolvedValue(response([ACTION_B]));
  fireEvent.change(screen.getByLabelText(/search by action id/i), {
    target: { value: "treasury" },
  });

  await waitFor(() =>
    expect(getGovernanceActions).toHaveBeenLastCalledWith({ q: "treasury", page: 1 }),
  );
  await waitFor(() =>
    expect(
      screen.getByRole("button", { name: `Copy action id ${ACTION_B.action_id}` }),
    ).toBeInTheDocument(),
  );
});

test("shows an empty state when nothing matches", async () => {
  vi.spyOn(client, "getGovernanceActions").mockResolvedValue(response([], { total: 0 }));

  render(<Governance network="preview" />);
  expect(await screen.findByText(/no governance actions found/i)).toBeInTheDocument();
});

test("surfaces an API error", async () => {
  vi.spyOn(client, "getGovernanceActions").mockRejectedValue(
    new client.ApiError(503, "node not ready"),
  );

  render(<Governance network="preview" />);
  expect(await screen.findByRole("alert")).toHaveTextContent(/node not ready/i);
  // An unavailable node read must not be mistaken for an empty database.
  expect(screen.queryByText(/no governance actions found/i)).not.toBeInTheDocument();
});

function linkedSurvey(over: Partial<SurveySummary> = {}): SurveySummary {
  return {
    id: `${"cc".repeat(32)}:0`,
    tx_hash: "cc".repeat(32),
    index: 0,
    title: "Treasury poll",
    description: "",
    owner: "dd".repeat(28),
    owner_script: false,
    roles: [0],
    end_epoch: 130,
    status: "open",
    sealed: false,
    questions: 1,
    linked_actions: [],
    owned: false,
    ...over,
  };
}

test("shows the survey a governance action links to, and none for unlinked actions", async () => {
  vi.spyOn(client, "getGovernanceActions").mockResolvedValue(response([ACTION_A, ACTION_B]));
  vi.spyOn(client, "getSurveys").mockResolvedValue({
    surveys: [linkedSurvey({ linked_actions: [ACTION_A.action_id] })],
    total: 1,
    page: 1,
    count: 200,
  });

  render(<Governance network="preview" />);

  const link = await screen.findByRole("button", { name: "Treasury poll" });
  // Only the linked action's row carries it.
  expect(screen.getAllByRole("button", { name: "Treasury poll" })).toHaveLength(1);
  expect(within(link.closest("tr") as HTMLElement).getByText("Info")).toBeInTheDocument();
  const rowB = screen.getByText("Treasury withdrawal").closest("tr") as HTMLElement;
  expect(within(rowB).queryByRole("button", { name: "Treasury poll" })).not.toBeInTheDocument();

  // The link opens that survey, not the survey list.
  fireEvent.click(link);
  expect(window.location.hash).toBe(`#/surveys/${encodeURIComponent(`${"cc".repeat(32)}:0`)}`);
});

test("finds linked surveys beyond the first page", async () => {
  vi.spyOn(client, "getGovernanceActions").mockResolvedValue(response([ACTION_A, ACTION_B]));
  const unrelated = Array.from({ length: 200 }, (_, i) =>
    linkedSurvey({ id: `${i.toString(16).padStart(64, "0")}:0`, title: `Other ${i}`, linked_actions: [`gov_action_other${i}`] }),
  );
  const getSurveys = vi
    .spyOn(client, "getSurveys")
    .mockResolvedValueOnce({ surveys: unrelated, total: 201, page: 1, count: 200 })
    .mockResolvedValueOnce({
      surveys: [linkedSurvey({ title: "Late poll", linked_actions: [ACTION_B.action_id] })],
      total: 201,
      page: 2,
      count: 200,
    });

  render(<Governance network="preview" />);

  const link = await screen.findByRole("button", { name: "Late poll" });
  expect(within(link.closest("tr") as HTMLElement).getByText("Treasury withdrawal")).toBeInTheDocument();
  expect(getSurveys).toHaveBeenNthCalledWith(1, { linked: true, page: 1, count: 200 });
  expect(getSurveys).toHaveBeenNthCalledWith(2, { linked: true, page: 2, count: 200 });
  expect(getSurveys).toHaveBeenCalledTimes(2);
});

test("a failed survey lookup leaves the governance list intact", async () => {
  vi.spyOn(client, "getGovernanceActions").mockResolvedValue(response([ACTION_A]));
  vi.spyOn(client, "getSurveys").mockRejectedValue(new client.ApiError(503, "node not ready"));

  render(<Governance network="preview" />);

  expect(await screen.findByText("Info")).toBeInTheDocument();
  expect(screen.queryByRole("alert")).not.toBeInTheDocument();
});
