import {
  answerFor,
  answersFor,
  buildCreateRequest,
  emptyBuilderDraft,
  emptyBuilderQuestion,
  answerableHere,
  emptyDraft,
  optionLabels,
  onScale,
  ratingChoices,
  roundAt,
  roundTime,
  surveyIdFromRoute,
  surveyRoute,
} from "./surveys";
import type { QuestionDraft, BuilderDraft } from "./surveys";
import type { SurveyDefinition, SurveyQuestion } from "./api/types";

const OPTS = ["a", "b", "c"];

function draft(q: SurveyQuestion, patch: Partial<QuestionDraft>): QuestionDraft {
  return { ...emptyDraft(q), answered: true, ...patch };
}

test("round arithmetic follows drand quicknet", () => {
  // Round 1 is published at genesis, then one round every 3 seconds.
  expect(roundAt(1692803367 * 1000)).toBe(1);
  expect(roundAt(1692803369 * 1000)).toBe(1);
  expect(roundAt(1692803370 * 1000)).toBe(2);
  expect(roundAt(1692800000 * 1000)).toBe(1); // before genesis
  expect(roundTime(100).getTime()).toBe((1692803367 + 99 * 3) * 1000);
  expect(roundAt(roundTime(5000).getTime())).toBe(5000);
});

test("option labels fall back to positions when the labels are off-chain", () => {
  expect(optionLabels({ kind: 1, prompt: "", options: OPTS })).toEqual(OPTS);
  expect(optionLabels({ kind: 1, prompt: "", option_count: 2 })).toEqual(["Option 1", "Option 2"]);
});

test("rating choices cover a grid, labels and levels", () => {
  expect(ratingChoices({ grid: { min: 1, max: 5 } }).map((c) => c.value)).toEqual(["1", "2", "3", "4", "5"]);
  expect(ratingChoices({ grid: { min: 0, max: 10, step: 5 } }).map((c) => c.value)).toEqual(["0", "5", "10"]);
  expect(ratingChoices({ labels: ["bad", "ok"] })).toEqual([
    { value: "0", label: "bad" },
    { value: "1", label: "ok" },
  ]);
  expect(ratingChoices({ levels: 3 }).map((c) => c.value)).toEqual(["0", "1", "2"]);
  expect(ratingChoices(undefined)).toEqual([]);
  // A pathological grid is capped rather than rendered in full.
  expect(ratingChoices({ grid: { min: 0, max: 1_000_000 } }).length).toBeLessThanOrEqual(101);
  expect(ratingChoices({ grid: { min: "9223372036854775806", max: "9223372036854775807" } })).toEqual([
    { value: "9223372036854775806", label: "9223372036854775806" },
    { value: "9223372036854775807", label: "9223372036854775807" },
  ]);
});

describe("answerFor", () => {
  test("an unanswered question abstains, unless it is required", () => {
    const q: SurveyQuestion = { kind: 1, prompt: "", options: OPTS };
    expect(answerFor(q, 0, emptyDraft(q))).toEqual({});
    const required = { ...q, required: true };
    expect(answerFor(required, 0, { ...emptyDraft(required), answered: false })).toEqual({
      error: expect.stringMatching(/required/i),
    });
    // A required question starts answered, so its control is shown and the
    // respondent is asked for a value rather than allowed to skip.
    expect(emptyDraft(required).answered).toBe(true);
    expect(answerFor(required, 0, emptyDraft(required)).error).toMatch(/pick/i);
  });

  test("single choice", () => {
    const q: SurveyQuestion = { kind: 1, prompt: "", options: OPTS };
    expect(answerFor(q, 3, draft(q, { choice: "2" })).answer).toEqual({ kind: 1, question: 3, choice: 2 });
    expect(answerFor(q, 0, draft(q, {})).error).toMatch(/pick/i);
  });

  test("multi-select allows none selected only when the minimum is zero", () => {
    const q: SurveyQuestion = { kind: 2, prompt: "", options: OPTS, min: 0, max: 2 };
    expect(answerFor(q, 0, draft(q, { selected: [] })).answer).toEqual({ kind: 2, question: 0, indices: [] });
    expect(answerFor(q, 0, draft(q, { selected: [0, 2] })).answer?.indices).toEqual([0, 2]);
    expect(answerFor(q, 0, draft(q, { selected: [0, 1, 2] })).error).toMatch(/between 0 and 2/);
    const needOne = { ...q, min: 1 };
    expect(answerFor(needOne, 0, draft(needOne, { selected: [] })).error).toMatch(/between 1 and 2/);
  });

  test("ranking keeps order and rejects repeats", () => {
    const q: SurveyQuestion = { kind: 3, prompt: "", options: OPTS, min: 1, max: 3 };
    expect(answerFor(q, 0, draft(q, { ranked: ["2", "0", ""] })).answer?.indices).toEqual([2, 0]);
    expect(answerFor(q, 0, draft(q, { ranked: ["1", "1"] })).error).toMatch(/once/);
    expect(answerFor(q, 0, draft(q, { ranked: ["", "", ""] })).error).toMatch(/between 1 and 3/);
  });

  test("numeric range checks bounds and step", () => {
    const q: SurveyQuestion = { kind: 4, prompt: "", range: { min: 10, max: 1000, step: 5 } };
    expect(answerFor(q, 0, draft(q, { number: "325" })).answer?.number).toBe("325");
    expect(answerFor(q, 0, draft(q, { number: "10" })).answer?.number).toBe("10");
    expect(answerFor(q, 0, draft(q, { number: "1000" })).answer?.number).toBe("1000");
    expect(answerFor(q, 0, draft(q, { number: "5" })).error).toMatch(/from 10 to 1000/);
    expect(answerFor(q, 0, draft(q, { number: "1005" })).error).toMatch(/from 10 to 1000/);
    expect(answerFor(q, 0, draft(q, { number: "326" })).error).toMatch(/steps of 5/);
    expect(answerFor(q, 0, draft(q, { number: "3.5" })).error).toMatch(/whole number/);
    expect(answerFor(q, 0, draft(q, { number: "" })).error).toMatch(/whole number/);
  });

  test("a numeric answer of zero is an answer", () => {
    const q: SurveyQuestion = { kind: 4, prompt: "", range: { min: -5, max: 5 } };
    expect(answerFor(q, 0, draft(q, { number: "0" })).answer).toEqual({ kind: 4, question: 0, number: "0" });
  });

  test("numeric answers preserve the full int64 range", () => {
    const q: SurveyQuestion = {
      kind: 4,
      prompt: "",
      range: { min: "-9223372036854775808", max: "9223372036854775807" },
    };
    expect(answerFor(q, 0, draft(q, { number: "9223372036854775807" })).answer?.number).toBe("9223372036854775807");
    expect(answerFor(q, 0, draft(q, { number: "-9223372036854775808" })).answer?.number).toBe("-9223372036854775808");
    expect(answerFor(q, 0, draft(q, { number: "9223372036854775808" })).error).toMatch(/whole number/i);
  });

  test("points must total the budget", () => {
    const q: SurveyQuestion = { kind: 5, prompt: "", options: OPTS, budget: 100 };
    expect(answerFor(q, 0, draft(q, { points: ["60", "", "40"] })).answer?.pairs).toEqual([
      { option: 0, value: 60 },
      { option: 2, value: 40 },
    ]);
    expect(answerFor(q, 0, draft(q, { points: ["60", "", "41"] })).error).toMatch(/total 100 \(currently 101\)/);
    expect(answerFor(q, 0, draft(q, { points: ["60", "", ""] })).error).toMatch(/total 100 \(currently 60\)/);
    expect(answerFor(q, 0, draft(q, { points: ["-5", "105", ""] })).error).toMatch(/0 or more/);
  });

  test("rating can require every option", () => {
    const q: SurveyQuestion = { kind: 6, prompt: "", options: OPTS, scale: { grid: { min: 1, max: 5 } } };
    expect(onScale(q.scale, "5")).toBe(true);
    expect(answerFor(q, 0, draft(q, { ratings: ["5", "", "1"] })).answer?.pairs).toEqual([
      { option: 0, value: "5" },
      { option: 2, value: "1" },
    ]);
    expect(answerFor(q, 0, draft(q, { ratings: ["", "", ""] })).error).toMatch(/at least one/);
    const all = { ...q, require_all: true };
    expect(answerFor(all, 0, draft(all, { ratings: ["5", "", "1"] })).error).toMatch(/every option/);
    expect(answerFor(all, 0, draft(all, { ratings: ["5", "4", "1"] })).answer).toBeDefined();
  });

  test("custom questions cannot be answered here", () => {
    const q: SurveyQuestion = { kind: 0, prompt: "", anchor: { uri: "ipfs://x", hash: "00" } };
    expect(answerFor(q, 0, draft(q, {})).error).toMatch(/another tool/);
    expect(answerFor(q, 0, emptyDraft(q))).toEqual({}); // abstaining is fine
  });
});

test("answersFor collects answers and one error per bad question", () => {
  const def: SurveyDefinition = {
    title: "",
    description: "",
    roles: [4],
    end_epoch: 9,
    mode: { sealed: false },
    questions: [
      { kind: 1, prompt: "", options: OPTS },
      { kind: 1, prompt: "", options: OPTS },
      { kind: 1, prompt: "", options: OPTS },
    ],
  };
  const drafts = def.questions.map((q) => emptyDraft(q));
  drafts[0] = { ...drafts[0], answered: true, choice: "1" };
  drafts[2] = { ...drafts[2], answered: true, choice: "" };
  const { answers, errors } = answersFor(def, drafts);
  expect(answers).toEqual([{ kind: 1, question: 0, choice: 1 }]);
  expect(Object.keys(errors)).toEqual(["2"]);
});

describe("buildCreateRequest", () => {
  const NOW = Date.UTC(2030, 0, 1);

  function valid(): BuilderDraft {
    return {
      ...emptyBuilderDraft(),
      title: " Poll ",
      description: "About things",
      roles: [0, 3],
      endEpoch: "600",
      questions: [{ ...emptyBuilderQuestion(1), prompt: "Pick one", optionsText: "yes\n no \n\nmaybe" }],
    };
  }

  test("builds a request from trimmed input", () => {
    const { request, errors } = buildCreateRequest(valid(), NOW);
    expect(errors).toEqual([]);
    expect(request).toEqual({
      title: "Poll",
      description: "About things",
      roles: [0, 3],
      end_epoch: 600,
      questions: [{ kind: 1, prompt: "Pick one", options: ["yes", "no", "maybe"] }],
    });
  });

  test("builds every question type", () => {
    const d = valid();
    d.questions = [
      { ...emptyBuilderQuestion(2), prompt: "m", optionsText: "a\nb\nc", min: "0", max: "2", required: true },
      { ...emptyBuilderQuestion(3), prompt: "r", optionsText: "a\nb", min: "1", max: "2" },
      { ...emptyBuilderQuestion(4), prompt: "n", rangeMin: "-5", rangeMax: "5", rangeStep: "5" },
      { ...emptyBuilderQuestion(5), prompt: "p", optionsText: "a\nb", budget: "100" },
      { ...emptyBuilderQuestion(6), prompt: "g", optionsText: "a\nb", scaleMin: "1", scaleMax: "5", requireAll: true },
      { ...emptyBuilderQuestion(6), prompt: "l", optionsText: "a\nb", scaleKind: "labels", scaleLabelsText: "bad\ngood" },
    ];
    const { request, errors } = buildCreateRequest(d, NOW);
    expect(errors).toEqual([]);
    expect(request?.questions).toEqual([
      { kind: 2, prompt: "m", options: ["a", "b", "c"], min: 0, max: 2, required: true },
      { kind: 3, prompt: "r", options: ["a", "b"], min: 1, max: 2 },
      { kind: 4, prompt: "n", range: { min: "-5", max: "5", step: "5" } },
      { kind: 5, prompt: "p", options: ["a", "b"], budget: 100 },
      { kind: 6, prompt: "g", options: ["a", "b"], require_all: true, scale: { grid: { min: "1", max: "5" } } },
      { kind: 6, prompt: "l", options: ["a", "b"], require_all: false, scale: { labels: ["bad", "good"] } },
    ]);
  });

  test.each([
    ["no title", (d: BuilderDraft) => (d.title = " "), /title/i],
    ["no roles", (d: BuilderDraft) => (d.roles = []), /who may respond/i],
    ["bad end epoch", (d: BuilderDraft) => (d.endEpoch = "soon"), /end epoch/i],
    ["no questions", (d: BuilderDraft) => (d.questions = []), /at least one question/i],
    ["no prompt", (d: BuilderDraft) => (d.questions[0].prompt = ""), /prompt/i],
    ["one option", (d: BuilderDraft) => (d.questions[0].optionsText = "only"), /two options/i],
    ["option too long", (d: BuilderDraft) => (d.questions[0].optionsText = `${"x".repeat(65)}\nb`), /64 bytes/],
    ["multibyte option too long", (d: BuilderDraft) => (d.questions[0].optionsText = `${"é".repeat(33)}\nb`), /64 bytes/],
  ])("rejects %s", (_name, mutate, message) => {
    const d = valid();
    mutate(d);
    const { request, errors } = buildCreateRequest(d, NOW);
    expect(request).toBeUndefined();
    expect(errors.join(" ")).toMatch(message);
  });

  test.each([
    ["multi min above max", { kind: 2 as const, optionsText: "a\nb", min: "2", max: "1" }, /selections need/],
    ["multi max above options", { kind: 2 as const, optionsText: "a\nb", min: "0", max: "3" }, /selections need/],
    ["multi not numbers", { kind: 2 as const, optionsText: "a\nb", min: "x", max: "1" }, /whole number/],
    ["ranking min zero", { kind: 3 as const, optionsText: "a\nb", min: "0", max: "1" }, /ranking needs/],
    ["numeric inverted", { kind: 4 as const, rangeMin: "9", rangeMax: "1" }, /above the maximum/],
    ["numeric zero step", { kind: 4 as const, rangeMin: "1", rangeMax: "9", rangeStep: "0" }, /step must be positive/],
    ["points no budget", { kind: 5 as const, optionsText: "a\nb", budget: "0" }, /budget must be positive/],
    ["rating labels short", { kind: 6 as const, optionsText: "a\nb", scaleKind: "labels" as const, scaleLabelsText: "only" }, /two rating labels/],
    ["rating grid inverted", { kind: 6 as const, optionsText: "a\nb", scaleMin: "5", scaleMax: "1" }, /rating minimum is above/],
  ])("rejects %s", (_name, patch, message) => {
    const d = valid();
    d.questions = [{ ...emptyBuilderQuestion(patch.kind), prompt: "q", ...patch }];
    const { request, errors } = buildCreateRequest(d, NOW);
    expect(request).toBeUndefined();
    expect(errors.join(" ")).toMatch(message);
  });

  test("a presentation document replaces the need for a title and is sent untrimmed", () => {
    const d = { ...valid(), title: "", anchorUri: " https://example.test/s.json ", anchorDocument: '{"title":"Long"}\n' };
    const { request, errors } = buildCreateRequest(d, NOW);
    expect(errors).toEqual([]);
    expect(request).toMatchObject({
      title: "",
      anchor_uri: "https://example.test/s.json",
      // The hash covers these exact bytes, trailing newline included.
      anchor_document: '{"title":"Long"}\n',
    });
  });

  test("a presentation document needs both its URI and its text", () => {
    for (const patch of [{ anchorUri: "ipfs://x" }, { anchorDocument: "{}" }]) {
      const { request, errors } = buildCreateRequest({ ...valid(), ...patch }, NOW);
      expect(request).toBeUndefined();
      expect(errors.join(" ")).toMatch(/both its URI and its text/);
    }
  });

  test("no presentation document sends no anchor fields", () => {
    const { request } = buildCreateRequest(valid(), NOW);
    expect(request).not.toHaveProperty("anchor_uri");
    expect(request).not.toHaveProperty("anchor_document");
  });

  test("sealed surveys need a future reveal time and padding", () => {
    const d = { ...valid(), sealed: true, revealAt: "2031-06-01T12:00", padding: "256" };
    const { request, errors } = buildCreateRequest(d, NOW);
    expect(errors).toEqual([]);
    expect(request?.seal).toEqual({ round: roundAt(new Date("2031-06-01T12:00").getTime()), padding_size: 256 });

    for (const [patch, message] of [
      [{ revealAt: "" }, /choose when/i],
      [{ revealAt: "2029-01-01T00:00" }, /in the future/i],
      [{ padding: "0" }, /padding size/i],
      [{ padding: "lots" }, /padding size/i],
    ] as [Partial<BuilderDraft>, RegExp][]) {
      const bad = buildCreateRequest({ ...d, ...patch }, NOW);
      expect(bad.request).toBeUndefined();
      expect(bad.errors.join(" ")).toMatch(message);
    }
    expect(buildCreateRequest({ ...valid(), sealed: false }, NOW).request?.seal).toBeUndefined();
  });
});

test("a grid too wide for a dropdown offers no choices instead of a truncated list", () => {
  expect(ratingChoices({ grid: { min: 0, max: 1_000_000 } })).toEqual([]);
  expect(ratingChoices({ grid: { min: 0, max: 100 } })).toHaveLength(101);
});

test("a survey link round-trips through the hash route", () => {
  const id = `${"ab".repeat(32)}:3`;
  expect(surveyIdFromRoute(surveyRoute(id))).toBe(id);
  expect(surveyIdFromRoute("surveys")).toBeUndefined();
  expect(surveyIdFromRoute("surveys/")).toBeUndefined();
  expect(surveyIdFromRoute("surveys/%E0%A4%A")).toBeUndefined();
  expect(surveyIdFromRoute("governance")).toBeUndefined();
});

test("a required custom question makes a survey unanswerable here", () => {
  const custom: SurveyQuestion = { kind: 0, prompt: "c", anchor: { uri: "ipfs://x", hash: "00".repeat(32) } };
  const def = (questions: SurveyQuestion[]): SurveyDefinition => ({
    title: "t", description: "", roles: [4], end_epoch: 9, mode: { sealed: false }, questions,
  });
  expect(answerableHere(def([custom]))).toBe(true);
  expect(answerableHere(def([{ ...custom, required: true }]))).toBe(false);
});

describe("answers are checked against the question", () => {
  test("single choice must name one of the options", () => {
    const q: SurveyQuestion = { kind: 1, prompt: "", options: OPTS };
    expect(answerFor(q, 0, draft(q, { choice: "2" })).answer?.choice).toBe(2);
    expect(answerFor(q, 0, draft(q, { choice: "3" })).error).toMatch(/pick an option/i);
    expect(answerFor(q, 0, draft(q, { choice: "-1" })).error).toMatch(/pick an option/i);
  });

  test("ratings are whole numbers on the scale", () => {
    const q: SurveyQuestion = { kind: 6, prompt: "", options: ["a", "b"], scale: { grid: { min: 1, max: 9, step: 2 } } };
    expect(answerFor(q, 0, draft(q, { ratings: ["3", ""] })).answer?.pairs).toEqual([{ option: 0, value: "3" }]);
    for (const bad of ["x", "2.5", "4", "11"]) {
      expect(answerFor(q, 0, draft(q, { ratings: [bad, ""] })).error).toMatch(/on the scale/i);
    }
    const levels: SurveyQuestion = { kind: 6, prompt: "", options: ["a"], scale: { levels: 3 } };
    expect(answerFor(levels, 0, draft(levels, { ratings: ["3"] })).error).toMatch(/on the scale/i);
  });

  test("ranked positions must be option numbers", () => {
    const q: SurveyQuestion = { kind: 3, prompt: "", options: OPTS, min: 1, max: 2 };
    expect(answerFor(q, 0, draft(q, { ranked: ["3", ""] })).error).toMatch(/1 to 3/);
    expect(answerFor(q, 0, draft(q, { ranked: ["x", ""] })).error).toMatch(/1 to 3/);
  });
});

test("an end epoch below 1 is rejected before building", () => {
  const d: BuilderDraft = {
    ...emptyBuilderDraft(),
    title: "t",
    roles: [4],
    endEpoch: "0",
    questions: [{ ...emptyBuilderQuestion(1), prompt: "p", optionsText: "a\nb" }],
  };
  expect(buildCreateRequest(d, 0).errors).toEqual(["End epoch must be a future epoch."]);
  expect(buildCreateRequest({ ...d, endEpoch: "1" }, 0).request?.end_epoch).toBe(1);
});
