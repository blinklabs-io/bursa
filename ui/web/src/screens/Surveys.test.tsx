import { render, screen, fireEvent, waitFor, within } from "@testing-library/react";
import { Surveys } from "./Surveys";
import * as client from "../api/client";
import type { Preview, SurveyDetail, SurveyQuestion, SurveySummary, SurveysResponse } from "../api/types";

const ID_A = `${"aa".repeat(32)}:0`;
const ID_B = `${"bb".repeat(32)}:0`;

function summary(over: Partial<SurveySummary> = {}): SurveySummary {
  return {
    id: ID_A,
    tx_hash: "aa".repeat(32),
    index: 0,
    title: "Fund the thing?",
    description: "Should we fund the thing",
    owner: "cd".repeat(28),
    owner_script: false,
    roles: [0, 3],
    end_epoch: 700,
    status: "open",
    sealed: false,
    questions: 1,
    linked_actions: [],
    owned: false,
    ...over,
  };
}

const YES_NO: SurveyQuestion = { kind: 1, prompt: "Fund it?", options: ["Yes", "No"] };

function detail(over: Partial<SurveyDetail> = {}, questions: SurveyQuestion[] = [YES_NO]): SurveyDetail {
  return {
    ...summary(),
    questions: questions.length,
    definition: {
      title: "Fund the thing?",
      description: "Should we fund the thing",
      roles: [0, 3],
      end_epoch: 700,
      mode: { sealed: false },
      questions,
    },
    // Three DReps answered the first question (two for Yes, one abstained);
    // later questions have no answers.
    tally: {
      roles: [
        {
          role: 0,
          responses: 3,
          questions: questions.map((_, i) =>
            i === 0 ? { answered: 2, abstained: 1, options: [{ count: 2 }, { count: 0 }] } : { answered: 0, abstained: 3 },
          ),
        },
        { role: 3, responses: 0, questions: questions.map(() => ({ answered: 0, abstained: 0 })) },
      ],
      excluded: [],
    },
    ...over,
  };
}

function list(surveys: SurveySummary[]): SurveysResponse {
  return { surveys, total: surveys.length, page: 1, count: 50 };
}

const PREVIEW: Preview = { pending_id: "pending-1", inputs: [], outputs: [], fee: "180000", change: "0" };

afterEach(() => {
  vi.restoreAllMocks();
});

async function openSurvey(d: SurveyDetail, canSubmit = true) {
  vi.spyOn(client, "getSurveys").mockResolvedValue(list([summary({ id: d.id, title: d.title })]));
  vi.spyOn(client, "getSurvey").mockResolvedValue(d);
  render(<Surveys canSubmit={canSubmit} />);
  fireEvent.click(await screen.findByRole("button", { name: d.title }));
  await screen.findByText(d.description);
}

describe("list", () => {
  test("lists surveys with status, roles and notes", async () => {
    vi.spyOn(client, "getSurveys").mockResolvedValue(
      list([
        summary({ linked_actions: ["gov_action1xyz"] }),
        summary({ id: ID_B, title: "Sealed poll", status: "closed", sealed: true, owned: true, roles: [4] }),
      ]),
    );
    render(<Surveys canSubmit />);

    expect(await screen.findByRole("button", { name: "Fund the thing?" })).toBeInTheDocument();
    // "Open" and "Closed" also name the status filter's options.
    const table = within(screen.getByRole("table"));
    expect(table.getByText("Open")).toBeInTheDocument();
    expect(table.getByText("Closed")).toBeInTheDocument();
    expect(table.getByText("DRep, Stakeholder")).toBeInTheDocument();
    expect(table.getByText("Linked to governance")).toBeInTheDocument();
    expect(table.getByText("Sealed · Yours")).toBeInTheDocument();
  });

  test("search and status filter query the node with the typed terms", async () => {
    const getSurveys = vi.spyOn(client, "getSurveys").mockResolvedValue(list([summary()]));
    render(<Surveys canSubmit />);
    await screen.findByRole("button", { name: "Fund the thing?" });

    fireEvent.change(screen.getByLabelText(/search by title/i), { target: { value: "fund" } });
    await waitFor(() => expect(getSurveys).toHaveBeenLastCalledWith({ q: "fund", status: "", page: 1 }));

    fireEvent.change(screen.getByLabelText("Status"), { target: { value: "closed" } });
    await waitFor(() => expect(getSurveys).toHaveBeenLastCalledWith({ q: "fund", status: "closed", page: 1 }));
  });

  test("pages through results", async () => {
    const getSurveys = vi
      .spyOn(client, "getSurveys")
      .mockResolvedValue({ surveys: [summary()], total: 120, page: 1, count: 50 });
    render(<Surveys canSubmit />);
    await screen.findByText("Page 1 of 3");

    fireEvent.click(screen.getByRole("button", { name: "Next" }));
    await waitFor(() => expect(getSurveys).toHaveBeenLastCalledWith({ q: "", status: "", page: 2 }));
    expect(screen.getByRole("button", { name: "Previous" })).toBeEnabled();
  });

  test("an empty list and a failed read look different", async () => {
    vi.spyOn(client, "getSurveys").mockResolvedValue(list([]));
    const { unmount } = render(<Surveys canSubmit />);
    expect(await screen.findByText(/no surveys found/i)).toBeInTheDocument();
    unmount();

    vi.spyOn(client, "getSurveys").mockRejectedValue(new client.ApiError(503, "node not ready"));
    render(<Surveys canSubmit />);
    expect(await screen.findByRole("alert")).toHaveTextContent(/node not ready/i);
    expect(screen.queryByText(/no surveys found/i)).not.toBeInTheDocument();
  });

  test("creating a survey needs a synced node and a signing wallet", async () => {
    vi.spyOn(client, "getSurveys").mockResolvedValue(list([summary()]));
    render(<Surveys canSubmit={false} />);
    await screen.findByRole("button", { name: "Fund the thing?" });
    expect(screen.getByRole("button", { name: "New survey" })).toBeDisabled();
  });
});

describe("detail and results", () => {
  test("shows the survey, per-role results and abstains without merging roles", async () => {
    await openSurvey(detail({ linked_actions: ["gov_action1abcdefghijklmnop"] }));

    expect(screen.getByText("Results: DRep")).toBeInTheDocument();
    expect(screen.getByText("Results: Stakeholder")).toBeInTheDocument();
    expect(screen.getByText("3 responses")).toBeInTheDocument();
    expect(screen.getByText("2 answered, 1 abstained")).toBeInTheDocument();
    expect(screen.getByLabelText("Yes count")).toHaveAttribute("value", "2");
    expect(screen.getByText("2 votes")).toBeInTheDocument();
    expect(screen.queryByText(/total/i)).not.toBeInTheDocument();
    expect(screen.getByText(/linked from governance action/i)).toBeInTheDocument();
  });

  test("shows the presentation document a survey points at without fetching it", async () => {
    const d = detail();
    d.definition.anchor = { uri: "ipfs://bafyroadmapsurvey", hash: "aa".repeat(32) };
    await openSurvey(d);
    expect(screen.getByText("ipfs://bafyroadmapsurvey")).toBeInTheDocument();
  });

  test("lists excluded responses with their reasons", async () => {
    const d = detail();
    d.tally!.excluded = [{ tx_hash: "dd".repeat(32), role: 0, credential: "ee".repeat(28), reason: "credential not proven" }];
    await openSurvey(d);
    expect(screen.getByText("Excluded responses")).toBeInTheDocument();
    expect(screen.getByText(/credential not proven/)).toBeInTheDocument();
  });

  test("a cancelled survey shows no results and no way to respond", async () => {
    await openSurvey(detail({ status: "cancelled", tally: undefined }));
    expect(screen.getByText(/owner cancelled this survey/i)).toBeInTheDocument();
    expect(screen.queryByText(/^Results/)).not.toBeInTheDocument();
    expect(screen.queryByRole("button", { name: /review response/i })).not.toBeInTheDocument();
  });

  test("a failed detail read shows the error", async () => {
    vi.spyOn(client, "getSurveys").mockResolvedValue(list([summary()]));
    vi.spyOn(client, "getSurvey").mockRejectedValue(new client.ApiError(404, "survey: not found"));
    render(<Surveys canSubmit />);
    fireEvent.click(await screen.findByRole("button", { name: "Fund the thing?" }));
    expect(await screen.findByRole("alert")).toHaveTextContent(/not found/i);
    fireEvent.click(screen.getByRole("button", { name: "Back" }));
    expect(await screen.findByRole("button", { name: "New survey" })).toBeInTheDocument();
  });

  test("each kind of result is described", async () => {
    const questions: SurveyQuestion[] = [
      { kind: 3, prompt: "Rank", options: ["a", "b"], min: 1, max: 2 },
      { kind: 4, prompt: "Number", range: { min: 0, max: 9 } },
      { kind: 5, prompt: "Points", options: ["a", "b"], budget: 10 },
      { kind: 6, prompt: "Rate", options: ["a", "b"], scale: { grid: { min: 1, max: 5 } } },
    ];
    const d = detail({}, questions);
    d.tally = {
      roles: [
        {
          role: 0,
          responses: 2,
          questions: [
            { answered: 2, abstained: 0, options: [{ count: 2, first: 1 }, { count: 1, first: 1 }] },
            { answered: 2, abstained: 0, numeric: { sum: 14, min: 4, max: 10 } },
            { answered: 2, abstained: 0, options: [{ count: 2, sum: 12 }, { count: 1, sum: 8 }] },
            { answered: 2, abstained: 0, options: [{ count: 2, sum: 9 }, { count: 1, sum: 3 }] },
          ],
        },
      ],
      excluded: [],
    };
    await openSurvey(d);
    expect(screen.getByText("2 rankings, 1 first")).toBeInTheDocument();
    expect(screen.getByText("Sum 14, lowest 4, highest 10")).toBeInTheDocument();
    expect(screen.getByText("12 points from 2 responses")).toBeInTheDocument();
    expect(screen.getByText("2 ratings, total 9")).toBeInTheDocument();
  });
});

describe("respond", () => {
  test("answers a single-choice question, reviews, and submits with the spending password", async () => {
    await openSurvey(detail());
    const respond = vi.spyOn(client, "respondToSurvey").mockResolvedValue(PREVIEW);
    const confirm = vi.spyOn(client, "confirmSend").mockResolvedValue({ tx_hash: "ff".repeat(32) });

    // Abstaining is the default: nothing is answered until the box is ticked.
    expect(screen.queryByRole("radio", { name: "Yes" })).not.toBeInTheDocument();
    fireEvent.click(screen.getByLabelText(/answer this question/i));
    fireEvent.click(screen.getByRole("radio", { name: "No" }));
    fireEvent.click(screen.getByRole("button", { name: /review response/i }));

    await waitFor(() =>
      expect(respond).toHaveBeenCalledWith({ survey: ID_A, role: 0, answers: [{ kind: 1, question: 0, choice: 1 }] }),
    );
    expect(await screen.findByText(/publish your response to “fund the thing\?”/i)).toBeInTheDocument();
    expect(screen.getByText("0.18 ADA")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: /confirm & sign/i })).toBeDisabled();

    fireEvent.change(screen.getByLabelText("Spending password"), { target: { value: "pw" } });
    fireEvent.click(screen.getByRole("button", { name: /confirm & sign/i }));

    await waitFor(() => expect(confirm).toHaveBeenCalledWith("pending-1", "pw"));
    expect(await screen.findByText("ff".repeat(32))).toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: "Done" }));
    expect(await screen.findByRole("button", { name: "New survey" })).toBeInTheDocument();
  });

  test("a failed confirm keeps the transaction and lets the user go back", async () => {
    await openSurvey(detail());
    vi.spyOn(client, "respondToSurvey").mockResolvedValue(PREVIEW);
    vi.spyOn(client, "confirmSend").mockRejectedValue(new client.ApiError(401, "wrong password"));

    fireEvent.click(screen.getByLabelText(/answer this question/i));
    fireEvent.click(screen.getByRole("radio", { name: "Yes" }));
    fireEvent.click(screen.getByRole("button", { name: /review response/i }));
    fireEvent.change(await screen.findByLabelText("Spending password"), { target: { value: "bad" } });
    fireEvent.click(screen.getByRole("button", { name: /confirm & sign/i }));

    expect(await screen.findByRole("alert")).toHaveTextContent(/wrong password/i);
    fireEvent.click(screen.getByRole("button", { name: "Back" }));
    expect(await screen.findByRole("button", { name: /review response/i })).toBeInTheDocument();
  });

  test("a response that abstains on everything is not built", async () => {
    await openSurvey(detail());
    const respond = vi.spyOn(client, "respondToSurvey").mockResolvedValue(PREVIEW);
    fireEvent.click(screen.getByRole("button", { name: /review response/i }));
    expect(await screen.findByRole("alert")).toHaveTextContent(/answer at least one question/i);
    expect(respond).not.toHaveBeenCalled();
  });

  test("an invalid answer is reported on its question and nothing is built", async () => {
    await openSurvey(detail());
    const respond = vi.spyOn(client, "respondToSurvey").mockResolvedValue(PREVIEW);
    fireEvent.click(screen.getByLabelText(/answer this question/i));
    fireEvent.click(screen.getByRole("button", { name: /review response/i }));
    expect(await screen.findByText("Pick an option.")).toBeInTheDocument();
    expect(respond).not.toHaveBeenCalled();
  });

  test("a server rejection is shown", async () => {
    await openSurvey(detail());
    vi.spyOn(client, "respondToSurvey").mockRejectedValue(new client.ApiError(400, "survey: invalid: survey is cancelled"));
    fireEvent.click(screen.getByLabelText(/answer this question/i));
    fireEvent.click(screen.getByRole("radio", { name: "Yes" }));
    fireEvent.click(screen.getByRole("button", { name: /review response/i }));
    expect(await screen.findByRole("alert")).toHaveTextContent(/survey is cancelled/i);
  });

  test("a required question starts answered and cannot be skipped", async () => {
    await openSurvey(detail({}, [{ ...YES_NO, required: true }]));
    const toggle = screen.getByLabelText(/answer this question/i);
    expect(toggle).toBeChecked();
    expect(toggle).toBeDisabled();
    expect(screen.getByRole("radio", { name: "Yes" })).toBeInTheDocument();
  });

  test("answers every kind of question", async () => {
    const questions: SurveyQuestion[] = [
      YES_NO,
      { kind: 2, prompt: "Pick some", options: ["a", "b", "c"], min: 0, max: 2 },
      { kind: 3, prompt: "Rank them", options: ["a", "b", "c"], min: 1, max: 2 },
      { kind: 4, prompt: "How many", range: { min: 10, max: 100, step: 5 } },
      { kind: 5, prompt: "Share points", options: ["a", "b"], budget: 100 },
      { kind: 6, prompt: "Rate them", options: ["a", "b"], scale: { labels: ["bad", "good"] } },
      { kind: 0, prompt: "Custom thing", anchor: { uri: "ipfs://x", hash: "00".repeat(32) } },
    ];
    await openSurvey(detail({}, questions));
    const respond = vi.spyOn(client, "respondToSurvey").mockResolvedValue(PREVIEW);

    const toggles = screen.getAllByLabelText(/answer this question/i);
    expect(toggles).toHaveLength(7);
    expect(toggles[6]).toBeDisabled(); // custom questions can only be abstained from
    for (const t of toggles.slice(0, 6)) fireEvent.click(t);

    fireEvent.click(within(screen.getByRole("group", { name: /1\. Fund it/ })).getByRole("radio", { name: "Yes" }));
    const multi = within(screen.getByRole("group", { name: /2\. Pick some/ }));
    fireEvent.click(multi.getByRole("checkbox", { name: "a" }));
    fireEvent.click(multi.getByRole("checkbox", { name: "c" }));
    fireEvent.change(screen.getByLabelText("Rank 1"), { target: { value: "2" } });
    fireEvent.change(screen.getByLabelText("Rank 2"), { target: { value: "0" } });
    fireEvent.change(screen.getByLabelText(/whole number from 10 to 100/i), { target: { value: "35" } });
    fireEvent.change(screen.getByLabelText("a points"), { target: { value: "70" } });
    fireEvent.change(screen.getByLabelText("b points"), { target: { value: "30" } });
    fireEvent.change(screen.getByLabelText("a rating"), { target: { value: "1" } });

    fireEvent.click(screen.getByRole("button", { name: /review response/i }));
    await waitFor(() => expect(respond).toHaveBeenCalled());
    expect(respond).toHaveBeenCalledWith({
      survey: ID_A,
      role: 0,
      answers: [
        { kind: 1, question: 0, choice: 0 },
        { kind: 2, question: 1, indices: [0, 2] },
        { kind: 3, question: 2, indices: [2, 0] },
        { kind: 4, question: 3, number: 35 },
        { kind: 5, question: 4, pairs: [{ option: 0, value: 70 }, { option: 1, value: 30 }] },
        { kind: 6, question: 5, pairs: [{ option: 0, value: 1 }] },
      ],
    });
  });

  test("points that miss the budget are rejected before building", async () => {
    await openSurvey(detail({}, [{ kind: 5, prompt: "Share", options: ["a", "b"], budget: 100 }]));
    const respond = vi.spyOn(client, "respondToSurvey").mockResolvedValue(PREVIEW);
    fireEvent.click(screen.getByLabelText(/answer this question/i));
    fireEvent.change(screen.getByLabelText("a points"), { target: { value: "60" } });
    fireEvent.click(screen.getByRole("button", { name: /review response/i }));
    expect(await screen.findByText(/must total 100 \(currently 60\)/)).toBeInTheDocument();
    expect(respond).not.toHaveBeenCalled();
  });

  test("the respondent picks among the roles this wallet can sign as", async () => {
    // SPO and CC credentials are not wallet keys, so only DRep and Stakeholder are offered.
    const d = detail({}, [YES_NO]);
    d.definition.roles = [1, 2, 3, 0];
    await openSurvey(d);
    const respond = vi.spyOn(client, "respondToSurvey").mockResolvedValue(PREVIEW);
    const role = screen.getByLabelText("Respond as") as HTMLSelectElement;
    expect(Array.from(role.options).map((o) => o.textContent)).toEqual(["Stakeholder", "DRep"]);

    fireEvent.change(role, { target: { value: "0" } });
    fireEvent.click(screen.getByLabelText(/answer this question/i));
    fireEvent.click(screen.getByRole("radio", { name: "Yes" }));
    fireEvent.click(screen.getByRole("button", { name: /review response/i }));
    await waitFor(() => expect(respond).toHaveBeenCalledWith(expect.objectContaining({ role: 0 })));
  });

  test("a survey open only to roles the wallet cannot sign as explains why", async () => {
    const d = detail({}, [YES_NO]);
    d.definition.roles = [1];
    await openSurvey(d);
    expect(screen.getByText(/not keys this wallet holds/i)).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: /review response/i })).not.toBeInTheDocument();
  });

  test("a sealed survey says answers are encrypted until the reveal time", async () => {
    const d = detail();
    d.definition.mode = { sealed: true, round: 100, padding_size: 512 };
    await openSurvey(d);
    expect(screen.getByText(/responses to this survey are sealed/i)).toBeInTheDocument();
  });

  test("a wallet that cannot sign sees why it cannot respond", async () => {
    await openSurvey(detail(), false);
    expect(screen.getByText(/needs a synced node and a wallet that signs/i)).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: /review response/i })).not.toBeInTheDocument();
  });

  test("a closed survey offers no response form", async () => {
    await openSurvey(detail({ status: "closed" }));
    expect(screen.queryByRole("button", { name: /review response/i })).not.toBeInTheDocument();
    expect(screen.getByText("Results: DRep")).toBeInTheDocument();
  });
});

describe("cancel", () => {
  test("the owner builds a cancellation and confirms it", async () => {
    await openSurvey(detail({ owned: true }));
    const cancel = vi.spyOn(client, "cancelSurvey").mockResolvedValue(PREVIEW);
    const confirm = vi.spyOn(client, "confirmSend").mockResolvedValue({ tx_hash: "ab".repeat(32) });

    fireEvent.click(screen.getByRole("button", { name: "Cancel survey" }));
    await waitFor(() => expect(cancel).toHaveBeenCalledWith(ID_A));
    expect(await screen.findByText(/cancel the survey “fund the thing\?”/i)).toBeInTheDocument();
    fireEvent.change(screen.getByLabelText("Spending password"), { target: { value: "pw" } });
    fireEvent.click(screen.getByRole("button", { name: /confirm & sign/i }));
    await waitFor(() => expect(confirm).toHaveBeenCalledWith("pending-1", "pw"));
  });

  test("someone else's survey cannot be cancelled", async () => {
    await openSurvey(detail({ owned: false }));
    expect(screen.queryByRole("button", { name: "Cancel survey" })).not.toBeInTheDocument();
  });

  test("a closed survey cannot be cancelled", async () => {
    await openSurvey(detail({ owned: true, status: "closed" }));
    expect(screen.queryByRole("button", { name: "Cancel survey" })).not.toBeInTheDocument();
  });

  test("a rejected cancellation is shown", async () => {
    await openSurvey(detail({ owned: true }));
    vi.spyOn(client, "cancelSurvey").mockRejectedValue(new client.ApiError(400, "not owned by this wallet"));
    fireEvent.click(screen.getByRole("button", { name: "Cancel survey" }));
    expect(await screen.findByRole("alert")).toHaveTextContent(/not owned/i);
  });
});

describe("reveal", () => {
  function sealed(): SurveyDetail {
    const d = detail();
    d.sealed = true;
    d.definition.mode = { sealed: true, round: 100, padding_size: 512 };
    d.tally!.roles[0].sealed = 3;
    return d;
  }

  test("fetching the beacon needs explicit consent", async () => {
    await openSurvey(sealed());
    const reveal = vi.spyOn(client, "revealSurvey").mockResolvedValue(detail());
    const button = screen.getByRole("button", { name: "Reveal responses" });
    expect(button).toBeDisabled();
    expect(reveal).not.toHaveBeenCalled();

    fireEvent.click(screen.getByLabelText(/fetch the beacon from api\.drand\.sh/i));
    expect(button).toBeEnabled();
    fireEvent.click(button);
    await waitFor(() => expect(reveal).toHaveBeenCalledWith(ID_A, { consent: true }));
  });

  test("a pasted beacon is sent without fetching", async () => {
    await openSurvey(sealed());
    const reveal = vi.spyOn(client, "revealSurvey").mockResolvedValue(detail());
    fireEvent.change(screen.getByLabelText(/paste the beacon/i), { target: { value: " abcd " } });
    fireEvent.click(screen.getByRole("button", { name: "Reveal responses" }));
    await waitFor(() => expect(reveal).toHaveBeenCalledWith(ID_A, { beacon: "abcd" }));
  });

  test("a rejected reveal is shown", async () => {
    await openSurvey(sealed());
    vi.spyOn(client, "revealSurvey").mockRejectedValue(new client.ApiError(400, "reveal round 100 is not yet published"));
    fireEvent.click(screen.getByLabelText(/fetch the beacon/i));
    fireEvent.click(screen.getByRole("button", { name: "Reveal responses" }));
    expect(await screen.findByRole("alert")).toHaveTextContent(/not yet published/i);
  });

  test("no reveal panel when nothing is sealed", async () => {
    await openSurvey(detail());
    expect(screen.queryByText("Reveal sealed responses")).not.toBeInTheDocument();
  });
});

describe("create", () => {
  async function openBuilder() {
    vi.spyOn(client, "getSurveys").mockResolvedValue(list([]));
    render(<Surveys canSubmit />);
    fireEvent.click(await screen.findByRole("button", { name: "New survey" }));
    await screen.findByText("Question 1");
  }

  function fillBasics() {
    fireEvent.change(screen.getByLabelText("Title"), { target: { value: "Pick a colour" } });
    fireEvent.change(screen.getByLabelText("Description"), { target: { value: "Favourite colour" } });
    fireEvent.change(screen.getByLabelText(/last epoch that accepts/i), { target: { value: "800" } });
    fireEvent.click(screen.getByRole("checkbox", { name: "DRep" }));
    fireEvent.click(screen.getByRole("checkbox", { name: "Keyholder" }));
    fireEvent.change(screen.getByLabelText("Prompt"), { target: { value: "Which?" } });
    fireEvent.change(screen.getByLabelText(/^Options/), { target: { value: "red\ngreen" } });
  }

  test("builds a survey, reviews it and submits", async () => {
    await openBuilder();
    const create = vi.spyOn(client, "createSurvey").mockResolvedValue(PREVIEW);
    const confirm = vi.spyOn(client, "confirmSend").mockResolvedValue({ tx_hash: "cc".repeat(32) });
    fillBasics();
    fireEvent.click(screen.getByRole("button", { name: "Review survey" }));

    await waitFor(() =>
      expect(create).toHaveBeenCalledWith({
        title: "Pick a colour",
        description: "Favourite colour",
        roles: [0, 4],
        end_epoch: 800,
        questions: [{ kind: 1, prompt: "Which?", options: ["red", "green"] }],
      }),
    );
    expect(await screen.findByText(/publish the survey “pick a colour”/i)).toBeInTheDocument();
    fireEvent.change(screen.getByLabelText("Spending password"), { target: { value: "pw" } });
    fireEvent.click(screen.getByRole("button", { name: /confirm & sign/i }));
    await waitFor(() => expect(confirm).toHaveBeenCalledWith("pending-1", "pw"));
  });

  test("lists everything wrong instead of building", async () => {
    await openBuilder();
    const create = vi.spyOn(client, "createSurvey").mockResolvedValue(PREVIEW);
    fireEvent.click(screen.getByRole("button", { name: "Review survey" }));
    const alert = await screen.findByRole("alert");
    expect(alert).toHaveTextContent(/write a title/i);
    expect(alert).toHaveTextContent(/who may respond/i);
    expect(alert).toHaveTextContent(/end epoch must be a whole number/i);
    expect(alert).toHaveTextContent(/question 1: write the prompt/i);
    expect(create).not.toHaveBeenCalled();
  });

  test("a survey can point at a presentation document instead of carrying a title", async () => {
    await openBuilder();
    const create = vi.spyOn(client, "createSurvey").mockResolvedValue(PREVIEW);
    fireEvent.change(screen.getByLabelText(/last epoch that accepts/i), { target: { value: "800" } });
    fireEvent.click(screen.getByRole("checkbox", { name: "DRep" }));
    fireEvent.change(screen.getByLabelText("Prompt"), { target: { value: "Which?" } });
    fireEvent.change(screen.getByLabelText(/^Options/), { target: { value: "red\ngreen" } });
    fireEvent.change(screen.getByLabelText(/presentation document uri/i), { target: { value: "ipfs://doc" } });
    fireEvent.change(screen.getByLabelText(/presentation document text/i), { target: { value: '{"title":"Long"}' } });
    fireEvent.click(screen.getByRole("button", { name: "Review survey" }));

    await waitFor(() => expect(create).toHaveBeenCalled());
    expect(create.mock.calls[0][0]).toMatchObject({
      title: "",
      anchor_uri: "ipfs://doc",
      anchor_document: '{"title":"Long"}',
    });
  });

  test("a server rejection is shown", async () => {
    await openBuilder();
    vi.spyOn(client, "createSurvey").mockRejectedValue(new client.ApiError(400, "end epoch 3 must be after the current epoch 50"));
    fillBasics();
    fireEvent.click(screen.getByRole("button", { name: "Review survey" }));
    expect(await screen.findByRole("alert")).toHaveTextContent(/must be after the current epoch/i);
  });

  test("questions can be added, reordered and removed, and each type has its own fields", async () => {
    await openBuilder();
    expect(screen.getByRole("button", { name: "Remove question" })).toBeDisabled(); // the last one stays

    fireEvent.click(screen.getByRole("button", { name: "Add question" }));
    expect(screen.getByText("Question 2")).toBeInTheDocument();
    const prompts = screen.getAllByLabelText("Prompt");
    fireEvent.change(prompts[0], { target: { value: "first" } });
    fireEvent.change(prompts[1], { target: { value: "second" } });

    fireEvent.click(screen.getAllByRole("button", { name: "Move down" })[0]);
    expect((screen.getAllByLabelText("Prompt")[0] as HTMLInputElement).value).toBe("second");
    expect(screen.getAllByRole("button", { name: "Move up" })[0]).toBeDisabled();

    // Type-specific controls.
    const kinds = screen.getAllByLabelText("Type");
    fireEvent.change(kinds[0], { target: { value: "2" } });
    expect(screen.getByLabelText("Minimum selections")).toBeInTheDocument();
    fireEvent.change(kinds[0], { target: { value: "4" } });
    expect(screen.getByLabelText("Minimum value")).toBeInTheDocument();
    expect(screen.queryByLabelText(/^Options/, { selector: "#builder-q0-options" })).not.toBeInTheDocument();
    fireEvent.change(kinds[0], { target: { value: "5" } });
    expect(screen.getByLabelText("Points to share")).toBeInTheDocument();
    fireEvent.change(kinds[0], { target: { value: "6" } });
    expect(screen.getByLabelText("Lowest rating")).toBeInTheDocument();
    fireEvent.change(screen.getByLabelText("Rating scale"), { target: { value: "labels" } });
    expect(screen.getByLabelText(/rating labels/i)).toBeInTheDocument();

    fireEvent.click(screen.getAllByRole("button", { name: "Remove question" })[0]);
    expect(screen.queryByText("Question 2")).not.toBeInTheDocument();
  });

  test("a sealed survey asks for a reveal time and shows the Drand round", async () => {
    await openBuilder();
    const create = vi.spyOn(client, "createSurvey").mockResolvedValue(PREVIEW);
    fillBasics();
    fireEvent.click(screen.getByLabelText(/seal responses until/i));
    const future = new Date(Date.now() + 7 * 86400_000);
    const local = new Date(future.getTime() - future.getTimezoneOffset() * 60_000).toISOString().slice(0, 16);
    fireEvent.change(screen.getByLabelText("Reveal time"), { target: { value: local } });
    expect(screen.getByText(/^Drand round \d+$/)).toBeInTheDocument();

    fireEvent.click(screen.getByRole("button", { name: "Review survey" }));
    await waitFor(() => expect(create).toHaveBeenCalled());
    const seal = create.mock.calls[0][0].seal;
    expect(seal?.padding_size).toBe(512);
    expect(seal?.round).toBeGreaterThan(1);
  });

  test("going back from the builder returns to the list", async () => {
    await openBuilder();
    fireEvent.click(screen.getByRole("button", { name: "Back" }));
    expect(await screen.findByRole("button", { name: "New survey" })).toBeInTheDocument();
  });
});
