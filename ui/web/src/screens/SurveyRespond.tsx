import { useState } from "react";
import type { Preview, SurveyDetail, SurveyQuestion, SurveyRole } from "../api/types";
import { respondToSurvey } from "../api/client";
import { Card } from "../components/Card";
import { Button } from "../components/Button";
import { Input } from "../components/Input";
import { Select } from "../components/Select";
import { errorMessage } from "../errorMessage";
import {
  KIND_LABELS,
  MAX_DROPDOWN_ENTRIES,
  ROLE_LABELS,
  WALLET_ROLES,
  answerableHere,
  answersFor,
  emptyDraft,
  indexToPosition,
  optionLabels,
  positionToIndex,
  ratingChoices,
  roundTime,
} from "../surveys";
import type { QuestionDraft } from "../surveys";

// ratingHint says what a typed rating means for scales answered by number.
function ratingHint(q: SurveyQuestion): string {
  const grid = q.scale?.grid;
  if (grid) return `Type a whole number from ${grid.min} to ${grid.max}${grid.step ? ` in steps of ${grid.step}` : ""}.`;
  const levels = q.scale?.labels?.length ?? q.scale?.levels ?? 0;
  return `Type a level from 1 (lowest) to ${levels}.`;
}

interface QuestionInputProps {
  q: SurveyQuestion;
  index: number;
  draft: QuestionDraft;
  error?: string;
  onChange: (d: QuestionDraft) => void;
}

function QuestionInput({ q, index, draft, error, onChange }: QuestionInputProps) {
  const labels = optionLabels(q);
  const id = `survey-q${index}`;
  const set = (patch: Partial<QuestionDraft>) => onChange({ ...draft, ...patch });
  const maxRanks = q.max ?? 0;
  const rankByNumber = maxRanks * labels.length > MAX_DROPDOWN_ENTRIES;
  const choices = q.kind === 6 ? ratingChoices(q.scale) : [];
  const rateByNumber = choices.length === 0 || labels.length * choices.length > MAX_DROPDOWN_ENTRIES;

  return (
    <fieldset className="survey-question">
      <legend>
        {index + 1}. {q.prompt || KIND_LABELS[q.kind]}
        {q.required ? " (required)" : ""}
      </legend>
      <p className="helper-text">{KIND_LABELS[q.kind]}</p>
      <label className="survey-answer-toggle">
        <input
          type="checkbox"
          checked={draft.answered}
          disabled={q.required === true || q.kind === 0}
          onChange={(e) => set({ answered: e.target.checked })}
        />{" "}
        Answer this question (leave off to abstain)
      </label>

      {draft.answered && q.kind === 0 && (
        <p className="helper-text">This question uses a custom method this wallet cannot answer.</p>
      )}

      {draft.answered && q.kind === 1 &&
        labels.map((label, i) => (
          <label key={i} className="survey-choice">
            <input
              type="radio"
              name={id}
              checked={draft.choice === String(i)}
              onChange={() => set({ choice: String(i) })}
            />{" "}
            {label}
          </label>
        ))}

      {draft.answered && q.kind === 2 && (
        <>
          <p className="helper-text">
            Select between {q.min ?? 0} and {q.max ?? 0}.
          </p>
          {labels.map((label, i) => (
            <label key={i} className="survey-choice">
              <input
                type="checkbox"
                checked={draft.selected.includes(i)}
                onChange={(e) =>
                  set({ selected: e.target.checked ? [...draft.selected, i] : draft.selected.filter((s) => s !== i) })
                }
              />{" "}
              {label}
            </label>
          ))}
        </>
      )}

      {draft.answered && q.kind === 3 && (
        <>
          <p className="helper-text">
            Rank between {q.min ?? 1} and {maxRanks} options, most preferred first
            {rankByNumber ? `, by option number (1 to ${labels.length})` : ""}.
          </p>
          {Array.from({ length: maxRanks }, (_, rank) => {
            const setRank = (value: string) => {
              const ranked = Array.from({ length: maxRanks }, (_, r) => draft.ranked[r] ?? "");
              ranked[rank] = value;
              set({ ranked });
            };
            return (
              <div key={rank}>
                <label htmlFor={`${id}-rank${rank}`}>Rank {rank + 1}</label>
                {rankByNumber ? (
                  <Input
                    id={`${id}-rank${rank}`}
                    inputMode="numeric"
                    value={indexToPosition(draft.ranked[rank] ?? "")}
                    onChange={(e) => setRank(positionToIndex(e.target.value))}
                  />
                ) : (
                  <Select
                    id={`${id}-rank${rank}`}
                    value={draft.ranked[rank] ?? ""}
                    onChange={(e) => setRank(e.target.value)}
                    options={[{ value: "", label: "—" }, ...labels.map((label, i) => ({ value: String(i), label }))]}
                  />
                )}
              </div>
            );
          })}
        </>
      )}

      {draft.answered && q.kind === 4 && q.range && (
        <>
          <label htmlFor={id}>
            Whole number from {q.range.min} to {q.range.max}
            {q.range.step ? ` in steps of ${q.range.step}` : ""}
          </label>
          <Input id={id} inputMode="numeric" value={draft.number} onChange={(e) => set({ number: e.target.value })} />
        </>
      )}

      {draft.answered && q.kind === 5 && (
        <>
          <p className="helper-text">Share exactly {q.budget ?? 0} points between the options.</p>
          {labels.map((label, i) => (
            <div key={i}>
              <label htmlFor={`${id}-p${i}`}>{label} points</label>
              <Input
                id={`${id}-p${i}`}
                inputMode="numeric"
                value={draft.points[i] ?? ""}
                onChange={(e) => {
                  const points = [...draft.points];
                  points[i] = e.target.value;
                  set({ points });
                }}
              />
            </div>
          ))}
        </>
      )}

      {draft.answered && q.kind === 6 && (
        <>
          <p className="helper-text">
            {q.require_all ? "Rate every option." : "Rate any of the options."}
            {rateByNumber ? ` ${ratingHint(q)}` : ""}
          </p>
          {labels.map((label, i) => {
            const setRating = (value: string) => {
              const ratings = [...draft.ratings];
              ratings[i] = value;
              set({ ratings });
            };
            return (
              <div key={i}>
                <label htmlFor={`${id}-r${i}`}>{label} rating</label>
                {rateByNumber ? (
                  <Input
                    id={`${id}-r${i}`}
                    inputMode="numeric"
                    value={q.scale?.grid ? (draft.ratings[i] ?? "") : indexToPosition(draft.ratings[i] ?? "")}
                    onChange={(e) => setRating(q.scale?.grid ? e.target.value : positionToIndex(e.target.value))}
                  />
                ) : (
                  <Select
                    id={`${id}-r${i}`}
                    value={draft.ratings[i] ?? ""}
                    onChange={(e) => setRating(e.target.value)}
                    options={[{ value: "", label: "—" }, ...choices.map((c) => ({ value: String(c.value), label: c.label }))]}
                  />
                )}
              </div>
            );
          })}
        </>
      )}

      {error && (
        <p role="alert" className="error-text">
          {error}
        </p>
      )}
    </fieldset>
  );
}

interface SurveyRespondProps {
  survey: SurveyDetail;
  onPreview: (preview: Preview, summary: string) => void;
}

// SurveyRespond collects answers for every question (abstaining by default) and
// builds the response transaction for review.
export function SurveyRespond({ survey, onPreview }: SurveyRespondProps) {
  const def = survey.definition;
  const roles = def.roles.filter((r) => WALLET_ROLES.includes(r));
  const [role, setRole] = useState<SurveyRole | null>(roles[0] ?? null);
  const [drafts, setDrafts] = useState(() => def.questions.map((q) => emptyDraft(q)));
  const [errors, setErrors] = useState<Record<number, string>>({});
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);

  if (!answerableHere(def)) {
    return (
      <Card title="Respond">
        <p className="helper-text">
          This survey has a required question that uses a custom method, which this wallet cannot answer.
        </p>
      </Card>
    );
  }

  if (roles.length === 0 || role === null) {
    return (
      <Card title="Respond">
        <p className="helper-text">
          This survey is open to roles whose credentials are not keys this wallet holds (
          {def.roles.map((r) => ROLE_LABELS[r]).join(", ")}).
        </p>
      </Card>
    );
  }

  async function submit() {
    setError(null);
    const { answers, errors: found } = answersFor(def, drafts);
    setErrors(found);
    if (Object.keys(found).length > 0) return;
    if (answers.length === 0) {
      setError("Answer at least one question; a response that abstains on everything is not published.");
      return;
    }
    setLoading(true);
    try {
      const preview = await respondToSurvey({ survey: survey.id, role: role as SurveyRole, answers });
      onPreview(preview, `Publish your response to “${survey.title}”`);
    } catch (e) {
      setError(errorMessage(e));
    } finally {
      setLoading(false);
    }
  }

  return (
    <Card title="Respond">
      <div className="staking-form">
        {def.mode.sealed && (
          <p className="helper-text">
            Responses to this survey are sealed: your answers are encrypted on this device and can be opened by
            anyone once the reveal time
            {def.mode.round ? ` (${roundTime(def.mode.round).toLocaleString()})` : ""} passes.
          </p>
        )}
        <label htmlFor="survey-role">Respond as</label>
        <Select
          id="survey-role"
          value={String(role)}
          onChange={(e) => setRole(Number(e.target.value) as SurveyRole)}
          options={roles.map((r) => ({ value: String(r), label: ROLE_LABELS[r] }))}
        />
        {def.questions.map((q, i) => (
          <QuestionInput
            key={i}
            q={q}
            index={i}
            draft={drafts[i]}
            error={errors[i]}
            onChange={(d) => setDrafts((all) => all.map((x, j) => (j === i ? d : x)))}
          />
        ))}
        {error && (
          <p role="alert" className="error-text">
            {error}
          </p>
        )}
        <Button onClick={submit} disabled={loading}>
          {loading ? "Building…" : "Review response"}
        </Button>
      </div>
    </Card>
  );
}
