import { render, screen, fireEvent, waitFor } from "@testing-library/react";
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
  expect(link).toBeInTheDocument();
  // Only the linked action carries it.
  expect(screen.getAllByRole("button", { name: "Treasury poll" })).toHaveLength(1);

  fireEvent.click(link);
  expect(window.location.hash).toBe("#/surveys");
});

test("a failed survey lookup leaves the governance list intact", async () => {
  vi.spyOn(client, "getGovernanceActions").mockResolvedValue(response([ACTION_A]));
  vi.spyOn(client, "getSurveys").mockRejectedValue(new client.ApiError(503, "node not ready"));

  render(<Governance network="preview" />);

  expect(await screen.findByText("Info")).toBeInTheDocument();
  expect(screen.queryByRole("alert")).not.toBeInTheDocument();
});
