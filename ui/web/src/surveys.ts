import type {
  SurveyAnswer,
  SurveyCreateRequest,
  SurveyDefinition,
  SurveyKind,
  SurveyQuestion,
  SurveyRole,
  SurveyScale,
} from "./api/types";

export const ROLE_LABELS: Record<SurveyRole, string> = {
  0: "DRep",
  1: "SPO",
  2: "Constitutional Committee",
  3: "Stakeholder",
  4: "Keyholder",
};

// Roles whose credential is a key this wallet holds (DRep, stake and payment
// keys). SPO and CC credentials are not wallet keys, so the wallet cannot
// answer as them.
export const WALLET_ROLES: SurveyRole[] = [0, 3, 4];

export const KIND_LABELS: Record<SurveyKind, string> = {
  0: "Custom",
  1: "Single choice",
  2: "Multi-select",
  3: "Ranking",
  4: "Numeric range",
  5: "Points allocation",
  6: "Rating",
};

// The kinds a survey can be built with here. Custom questions need an off-chain
// method schema, which the builder does not produce.
export const BUILDABLE_KINDS: SurveyKind[] = [1, 2, 3, 4, 5, 6];

// A grid wider than this is not offered as a dropdown.
const MAX_GRID_CHOICES = 101;

// A question whose dropdowns would hold more entries than this in total is
// answered by typing numbers instead: a definition may carry 1024 options, and
// a dropdown of every option for each of 1024 ranks freezes the page.
export const MAX_DROPDOWN_ENTRIES = 2000;

const SURVEY_ROUTE = "surveys/";

// surveyRoute is the hash route that opens one survey's detail view.
export function surveyRoute(id: string): string {
  return SURVEY_ROUTE + encodeURIComponent(id);
}

// surveyIdFromRoute reads the survey id from a surveyRoute, or undefined for
// any other route.
export function surveyIdFromRoute(route: string): string | undefined {
  if (!route.startsWith(SURVEY_ROUTE)) return undefined;
  try {
    return decodeURIComponent(route.slice(SURVEY_ROUTE.length)) || undefined;
  } catch {
    return undefined;
  }
}

// Drand quicknet: round 1 is published at genesis, then one round every 3 s.
const QUICKNET_GENESIS = 1692803367;
const QUICKNET_PERIOD = 3;

export function roundAt(ms: number): number {
  const seconds = Math.floor(ms / 1000);
  if (seconds < QUICKNET_GENESIS) return 1;
  return Math.floor((seconds - QUICKNET_GENESIS) / QUICKNET_PERIOD) + 1;
}

export function roundTime(round: number): Date {
  return new Date((QUICKNET_GENESIS + (round - 1) * QUICKNET_PERIOD) * 1000);
}

// optionLabels lists a question's options; a definition that keeps its labels
// off-chain is shown by position.
export function optionLabels(q: SurveyQuestion): string[] {
  if (q.options && q.options.length > 0) return q.options;
  return Array.from({ length: q.option_count ?? 0 }, (_, i) => `Option ${i + 1}`);
}

export interface RatingChoice {
  value: string;
  label: string;
}

// ratingChoices lists the values a rating scale accepts. A rating is always an
// integer on the wire: a grid value, or the index of a label or level. A grid
// too wide for a dropdown yields no choices; it is answered by typing a value.
export function ratingChoices(scale: SurveyScale | undefined): RatingChoice[] {
  if (!scale) return [];
  if (scale.grid) {
    const min = BigInt(scale.grid.min);
    const max = BigInt(scale.grid.max);
    const rawStep = scale.grid.step === undefined ? 0n : BigInt(scale.grid.step);
    const step = rawStep > 0n ? rawStep : 1n;
    if ((max - min) / step + 1n > BigInt(MAX_GRID_CHOICES)) return [];
    const out: RatingChoice[] = [];
    for (let v = min; v <= max; v += step) {
      out.push({ value: v.toString(), label: v.toString() });
    }
    return out;
  }
  if (scale.labels) return scale.labels.map((label, i) => ({ value: String(i), label }));
  return Array.from({ length: scale.levels }, (_, i) => ({ value: String(i), label: `Level ${i + 1}` }));
}

// positionToIndex turns a typed 1-based position into the 0-based index a draft
// holds. Anything that is not a whole number is kept so validation rejects it.
export function positionToIndex(text: string): string {
  const t = text.trim();
  if (t === "") return "";
  return /^\d+$/.test(t) ? String(Number(t) - 1) : t;
}

// indexToPosition shows a draft's 0-based index as the 1-based position typed.
export function indexToPosition(raw: string): string {
  return /^-?\d+$/.test(raw) ? String(Number(raw) + 1) : raw;
}

// QuestionDraft is a respondent's in-progress answer to one question; every
// field is raw input. A question that is not answered is an abstain.
export interface QuestionDraft {
  answered: boolean;
  choice: string;
  selected: number[];
  ranked: string[];
  number: string;
  points: string[];
  ratings: string[];
}

// onScale reports whether v is a value the rating scale accepts.
export function onScale(scale: SurveyScale | undefined, value: string): boolean {
  if (!scale) return false;
  if (!INTEGER.test(value)) return false;
  const v = BigInt(value);
  if (scale.grid) {
    const min = BigInt(scale.grid.min);
    const max = BigInt(scale.grid.max);
    const rawStep = scale.grid.step === undefined ? 0n : BigInt(scale.grid.step);
    const step = rawStep > 0n ? rawStep : 1n;
    return v >= min && v <= max && (v - min) % step === 0n;
  }
  const levels = BigInt(scale.labels ? scale.labels.length : scale.levels);
  return v >= 0n && v < levels;
}

// answerableHere reports whether this wallet can build a response: a required
// question with a custom method cannot be answered, and leaving it out makes
// every response invalid.
export function answerableHere(def: SurveyDefinition): boolean {
  return !def.questions.some((q) => q.kind === 0 && q.required === true);
}

export function emptyDraft(q: SurveyQuestion): QuestionDraft {
  const n = optionLabels(q).length;
  return {
    answered: q.required === true,
    choice: "",
    selected: [],
    ranked: [],
    number: "",
    points: Array.from({ length: n }, () => ""),
    ratings: Array.from({ length: n }, () => ""),
  };
}

const INTEGER = /^-?\d+$/;

function parseInteger(s: string): number | null {
  const t = s.trim();
  if (!INTEGER.test(t)) return null;
  const n = Number(t);
  return Number.isSafeInteger(n) ? n : null;
}

const INT64_MIN = -(1n << 63n);
const INT64_MAX = (1n << 63n) - 1n;
const UINT64_MAX = (1n << 64n) - 1n;

function parseInt64(s: string): string | null {
  const t = s.trim();
  if (!INTEGER.test(t)) return null;
  const n = BigInt(t);
  return n < INT64_MIN || n > INT64_MAX ? null : n.toString();
}

function parseUint64(s: string): string | null {
  const t = s.trim();
  if (!/^\d+$/.test(t)) return null;
  const n = BigInt(t);
  return n > UINT64_MAX ? null : n.toString();
}

// answerFor converts a draft to an answer item, or reports why it is not valid.
// An unanswered question yields neither: it is an abstain.
export function answerFor(
  q: SurveyQuestion,
  index: number,
  d: QuestionDraft,
): { answer?: SurveyAnswer; error?: string } {
  if (!d.answered) {
    return q.required ? { error: "This question is required." } : {};
  }
  const kind = q.kind;
  switch (kind) {
    case 0:
      return { error: "Custom questions are answered with another tool." };
    case 1: {
      const choice = parseInteger(d.choice);
      if (choice === null || choice < 0 || choice >= optionLabels(q).length) return { error: "Pick an option." };
      return { answer: { kind, question: index, choice } };
    }
    case 2: {
      const min = q.min ?? 0;
      const max = q.max ?? 0;
      if (d.selected.length < min || d.selected.length > max) {
        return { error: `Select between ${min} and ${max} options.` };
      }
      return { answer: { kind, question: index, indices: [...d.selected] } };
    }
    case 3: {
      const picked = d.ranked.filter((r) => r !== "");
      const indices = picked.map(parseInteger);
      const min = q.min ?? 1;
      const max = q.max ?? 0;
      const n = optionLabels(q).length;
      if (indices.some((i) => i === null || i < 0 || i >= n)) {
        return { error: `Rank options by their number, 1 to ${n}.` };
      }
      if (indices.length < min || indices.length > max) {
        return { error: `Rank between ${min} and ${max} options.` };
      }
      if (new Set(indices).size !== indices.length) return { error: "Each option can be ranked once." };
      return { answer: { kind, question: index, indices: indices as number[] } };
    }
    case 4: {
      const n = parseInt64(d.number);
      const r = q.range;
      if (n === null || !r) return { error: "Enter a whole number." };
      const value = BigInt(n);
      const min = BigInt(r.min);
      const max = BigInt(r.max);
      const step = r.step === undefined ? 0n : BigInt(r.step);
      if (value < min || value > max) return { error: `Enter a number from ${r.min} to ${r.max}.` };
      if (step > 0n && (value - min) % step !== 0n) return { error: `Enter a number in steps of ${r.step} from ${r.min}.` };
      return { answer: { kind, question: index, number: n } };
    }
    case 5: {
      const pairs = [];
      let total = 0;
      for (const [option, raw] of d.points.entries()) {
        if (raw.trim() === "") continue;
        const v = parseInteger(raw);
        if (v === null || v < 0) return { error: "Points are whole numbers, 0 or more." };
        total += v;
        pairs.push({ option, value: v });
      }
      const budget = q.budget ?? 0;
      if (total !== budget) return { error: `Points must total ${budget} (currently ${total}).` };
      return { answer: { kind, question: index, pairs } };
    }
    case 6: {
      const pairs = [];
      for (const [option, raw] of d.ratings.entries()) {
        if (raw.trim() === "") continue;
        const v = parseInt64(raw);
        if (v === null || !onScale(q.scale, v)) return { error: "Give each rating as a value on the scale." };
        pairs.push({ option, value: v });
      }
      if (pairs.length === 0) return { error: "Rate at least one option." };
      if (q.require_all && pairs.length !== d.ratings.length) return { error: "Rate every option." };
      return { answer: { kind, question: index, pairs } };
    }
  }
}

// answersFor converts every draft, collecting one error per invalid question.
export function answersFor(
  def: SurveyDefinition,
  drafts: QuestionDraft[],
): { answers: SurveyAnswer[]; errors: Record<number, string> } {
  const answers: SurveyAnswer[] = [];
  const errors: Record<number, string> = {};
  def.questions.forEach((q, i) => {
    const { answer, error } = answerFor(q, i, drafts[i]);
    if (error) errors[i] = error;
    else if (answer) answers.push(answer);
  });
  return { answers, errors };
}

// BuilderQuestion is one question of a survey being written; every field is raw
// input.
export interface BuilderQuestion {
  kind: SurveyKind;
  prompt: string;
  optionsText: string;
  min: string;
  max: string;
  budget: string;
  rangeMin: string;
  rangeMax: string;
  rangeStep: string;
  scaleKind: "grid" | "labels";
  scaleMin: string;
  scaleMax: string;
  scaleStep: string;
  scaleLabelsText: string;
  requireAll: boolean;
  required: boolean;
}

export interface BuilderDraft {
  title: string;
  description: string;
  roles: SurveyRole[];
  endEpoch: string;
  questions: BuilderQuestion[];
  anchorUri: string;
  anchorDocument: string;
  sealed: boolean;
  // datetime-local value of the moment sealed responses may be opened.
  revealAt: string;
  padding: string;
}

export function emptyBuilderQuestion(kind: SurveyKind = 1): BuilderQuestion {
  return {
    kind,
    prompt: "",
    optionsText: "",
    min: "",
    max: "",
    budget: "",
    rangeMin: "",
    rangeMax: "",
    rangeStep: "",
    scaleKind: "grid",
    scaleMin: "1",
    scaleMax: "5",
    scaleStep: "",
    scaleLabelsText: "",
    requireAll: false,
    required: false,
  };
}

export function emptyBuilderDraft(): BuilderDraft {
  return {
    title: "",
    description: "",
    roles: [],
    endEpoch: "",
    questions: [emptyBuilderQuestion()],
    anchorUri: "",
    anchorDocument: "",
    sealed: false,
    revealAt: "",
    padding: "512",
  };
}

const textBytes = (s: string) => new TextEncoder().encode(s).length;

function lines(text: string): string[] {
  return text
    .split("\n")
    .map((l) => l.trim())
    .filter((l) => l !== "");
}

function toInt(label: string, raw: string, errors: string[]): number {
  const n = parseInteger(raw);
  if (n === null) {
    errors.push(`${label} must be a whole number.`);
    return 0;
  }
  return n;
}

function toInt64(label: string, raw: string, errors: string[]): string {
  const value = parseInt64(raw);
  if (value === null) {
    errors.push(`${label} must be an integer in the int64 range.`);
    return "0";
  }
  return value;
}

function toUint64(label: string, raw: string, errors: string[]): string {
  const value = parseUint64(raw);
  if (value === null) {
    errors.push(`${label} must be an integer in the uint64 range.`);
    return "0";
  }
  return value;
}

function questionFrom(b: BuilderQuestion, n: number, errors: string[]): SurveyQuestion {
  const at = `Question ${n}`;
  const fail = (msg: string) => errors.push(`${at}: ${msg}`);
  const q: SurveyQuestion = { kind: b.kind, prompt: b.prompt.trim() };
  if (q.prompt === "") fail("write the prompt.");
  if (b.required) q.required = true;

  const e: string[] = [];
  if (b.kind !== 4) {
    const options = lines(b.optionsText);
    if (options.length < 2) fail("give at least two options, one per line.");
    if (options.some((o) => textBytes(o) > 64)) fail("each option must be 64 bytes or fewer.");
    q.options = options;
  }
  switch (b.kind) {
    case 2:
      q.min = toInt("Minimum selections", b.min, e);
      q.max = toInt("Maximum selections", b.max, e);
      if (e.length === 0 && (q.max < 1 || q.min < 0 || q.min > q.max || q.max > (q.options?.length ?? 0))) {
        fail("selections need 0 <= minimum <= maximum <= the number of options, and maximum >= 1.");
      }
      break;
    case 3:
      q.min = toInt("Minimum ranked", b.min, e);
      q.max = toInt("Maximum ranked", b.max, e);
      if (e.length === 0 && (q.min < 1 || q.min > q.max || q.max > (q.options?.length ?? 0))) {
        fail("ranking needs 1 <= minimum <= maximum <= the number of options.");
      }
      break;
    case 4: {
      const range = { min: toInt64("Minimum", b.rangeMin, e), max: toInt64("Maximum", b.rangeMax, e) } as {
        min: string;
        max: string;
        step?: string;
      };
      if (b.rangeStep.trim() !== "") {
        range.step = toUint64("Step", b.rangeStep, e);
        if (e.length === 0 && BigInt(range.step) < 1n) fail("the step must be positive.");
      }
      if (e.length === 0 && BigInt(range.min) > BigInt(range.max)) fail("the minimum is above the maximum.");
      q.range = range;
      break;
    }
    case 5:
      q.budget = toInt("Budget", b.budget, e);
      if (e.length === 0 && q.budget < 1) fail("the budget must be positive.");
      break;
    case 6: {
      q.require_all = b.requireAll;
      if (b.scaleKind === "labels") {
        const labels = lines(b.scaleLabelsText);
        if (labels.length < 2) fail("give at least two rating labels, worst first.");
        if (labels.some((l) => textBytes(l) > 64)) fail("each rating label must be 64 bytes or fewer.");
        q.scale = { labels };
      } else {
        const grid: { min: string; max: string; step?: string } = {
          min: toInt64("Rating minimum", b.scaleMin, e),
          max: toInt64("Rating maximum", b.scaleMax, e),
        };
        if (b.scaleStep.trim() !== "") {
          grid.step = toUint64("Rating step", b.scaleStep, e);
          if (e.length === 0 && BigInt(grid.step) < 1n) fail("the rating step must be positive.");
        }
        if (e.length === 0 && BigInt(grid.min) > BigInt(grid.max)) fail("the rating minimum is above the maximum.");
        q.scale = { grid };
      }
      break;
    }
  }
  e.forEach(fail);
  return q;
}

// buildCreateRequest converts a builder draft to a create request, or lists
// everything wrong with it. nowMs is the current time, used to check that the
// reveal moment of a sealed survey is in the future.
export function buildCreateRequest(
  d: BuilderDraft,
  nowMs: number,
): { request?: SurveyCreateRequest; errors: string[] } {
  const errors: string[] = [];
  const anchored = d.anchorUri.trim() !== "" || d.anchorDocument !== "";
  if (anchored && (d.anchorUri.trim() === "" || d.anchorDocument.trim() === "")) {
    errors.push("A presentation document needs both its URI and its text.");
  }
  if (d.title.trim() === "" && !anchored) errors.push("Write a title.");
  if (d.roles.length === 0) errors.push("Choose who may respond.");
  const before = errors.length;
  const endEpoch = toInt("End epoch", d.endEpoch, errors);
  if (errors.length === before && endEpoch < 1) errors.push("End epoch must be a future epoch.");
  if (d.questions.length === 0) errors.push("Add at least one question.");
  const questions = d.questions.map((b, i) => questionFrom(b, i + 1, errors));

  let seal: SurveyCreateRequest["seal"];
  if (d.sealed) {
    const at = new Date(d.revealAt).getTime();
    const padding = parseInteger(d.padding);
    if (Number.isNaN(at)) errors.push("Choose when sealed responses may be revealed.");
    else if (at <= nowMs) errors.push("The reveal time must be in the future.");
    if (padding === null || padding < 1) errors.push("Padding size must be a positive whole number.");
    else seal = { round: roundAt(at), padding_size: padding };
  }
  if (errors.length > 0) return { errors };
  return {
    errors,
    request: {
      title: d.title.trim(),
      description: d.description.trim(),
      roles: d.roles,
      end_epoch: endEpoch,
      questions,
      // The document is hashed byte for byte, so it is sent untrimmed.
      ...(anchored ? { anchor_uri: d.anchorUri.trim(), anchor_document: d.anchorDocument } : {}),
      ...(seal ? { seal } : {}),
    },
  };
}
