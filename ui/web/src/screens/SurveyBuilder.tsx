import { useState } from "react";
import type { Preview, SurveyKind, SurveyRole } from "../api/types";
import { createSurvey } from "../api/client";
import { Card } from "../components/Card";
import { Button } from "../components/Button";
import { Input } from "../components/Input";
import { Select } from "../components/Select";
import { errorMessage } from "../errorMessage";
import {
  BUILDABLE_KINDS,
  KIND_LABELS,
  ROLE_LABELS,
  buildCreateRequest,
  emptyBuilderDraft,
  emptyBuilderQuestion,
  roundAt,
} from "../surveys";
import type { BuilderDraft, BuilderQuestion } from "../surveys";

const ALL_ROLES: SurveyRole[] = [0, 1, 2, 3, 4];

interface QuestionEditorProps {
  n: number;
  q: BuilderQuestion;
  count: number;
  onChange: (q: BuilderQuestion) => void;
  onMove: (by: -1 | 1) => void;
  onRemove: () => void;
}

function QuestionEditor({ n, q, count, onChange, onMove, onRemove }: QuestionEditorProps) {
  const id = `builder-q${n}`;
  const set = (patch: Partial<BuilderQuestion>) => onChange({ ...q, ...patch });
  const hasOptions = q.kind !== 4;
  return (
    <fieldset className="survey-question">
      <legend>Question {n + 1}</legend>
      <label htmlFor={`${id}-kind`}>Type</label>
      <Select
        id={`${id}-kind`}
        value={String(q.kind)}
        onChange={(e) => set({ kind: Number(e.target.value) as SurveyKind })}
        options={BUILDABLE_KINDS.map((k) => ({ value: String(k), label: KIND_LABELS[k] }))}
      />
      <label htmlFor={`${id}-prompt`}>Prompt</label>
      <Input id={`${id}-prompt`} value={q.prompt} onChange={(e) => set({ prompt: e.target.value })} />

      {hasOptions && (
        <>
          <label htmlFor={`${id}-options`}>Options (one per line, 64 bytes each at most)</label>
          <textarea
            id={`${id}-options`}
            className="field"
            rows={4}
            value={q.optionsText}
            onChange={(e) => set({ optionsText: e.target.value })}
          />
        </>
      )}

      {(q.kind === 2 || q.kind === 3) && (
        <>
          <label htmlFor={`${id}-min`}>{q.kind === 2 ? "Minimum selections" : "Minimum ranked"}</label>
          <Input id={`${id}-min`} inputMode="numeric" value={q.min} onChange={(e) => set({ min: e.target.value })} />
          <label htmlFor={`${id}-max`}>{q.kind === 2 ? "Maximum selections" : "Maximum ranked"}</label>
          <Input id={`${id}-max`} inputMode="numeric" value={q.max} onChange={(e) => set({ max: e.target.value })} />
        </>
      )}

      {q.kind === 4 && (
        <>
          <label htmlFor={`${id}-rmin`}>Minimum value</label>
          <Input id={`${id}-rmin`} inputMode="numeric" value={q.rangeMin} onChange={(e) => set({ rangeMin: e.target.value })} />
          <label htmlFor={`${id}-rmax`}>Maximum value</label>
          <Input id={`${id}-rmax`} inputMode="numeric" value={q.rangeMax} onChange={(e) => set({ rangeMax: e.target.value })} />
          <label htmlFor={`${id}-rstep`}>Step (optional)</label>
          <Input id={`${id}-rstep`} inputMode="numeric" value={q.rangeStep} onChange={(e) => set({ rangeStep: e.target.value })} />
        </>
      )}

      {q.kind === 5 && (
        <>
          <label htmlFor={`${id}-budget`}>Points to share</label>
          <Input id={`${id}-budget`} inputMode="numeric" value={q.budget} onChange={(e) => set({ budget: e.target.value })} />
        </>
      )}

      {q.kind === 6 && (
        <>
          <label htmlFor={`${id}-scale`}>Rating scale</label>
          <Select
            id={`${id}-scale`}
            value={q.scaleKind}
            onChange={(e) => set({ scaleKind: e.target.value as "grid" | "labels" })}
            options={[
              { value: "grid", label: "Numbers" },
              { value: "labels", label: "Labels, worst to best" },
            ]}
          />
          {q.scaleKind === "grid" ? (
            <>
              <label htmlFor={`${id}-smin`}>Lowest rating</label>
              <Input id={`${id}-smin`} inputMode="numeric" value={q.scaleMin} onChange={(e) => set({ scaleMin: e.target.value })} />
              <label htmlFor={`${id}-smax`}>Highest rating</label>
              <Input id={`${id}-smax`} inputMode="numeric" value={q.scaleMax} onChange={(e) => set({ scaleMax: e.target.value })} />
              <label htmlFor={`${id}-sstep`}>Step (optional)</label>
              <Input id={`${id}-sstep`} inputMode="numeric" value={q.scaleStep} onChange={(e) => set({ scaleStep: e.target.value })} />
            </>
          ) : (
            <>
              <label htmlFor={`${id}-labels`}>Rating labels (one per line)</label>
              <textarea
                id={`${id}-labels`}
                className="field"
                rows={3}
                value={q.scaleLabelsText}
                onChange={(e) => set({ scaleLabelsText: e.target.value })}
              />
            </>
          )}
          <label>
            <input type="checkbox" checked={q.requireAll} onChange={(e) => set({ requireAll: e.target.checked })} /> Respondents must rate every option
          </label>
        </>
      )}

      <label>
        <input type="checkbox" checked={q.required} onChange={(e) => set({ required: e.target.checked })} /> Required (cannot be skipped)
      </label>
      <div className="preview-actions">
        <Button variant="ghost" onClick={() => onMove(-1)} disabled={n === 0}>
          Move up
        </Button>
        <Button variant="ghost" onClick={() => onMove(1)} disabled={n === count - 1}>
          Move down
        </Button>
        <Button variant="ghost" onClick={onRemove} disabled={count === 1}>
          Remove question
        </Button>
      </div>
    </fieldset>
  );
}

interface SurveyBuilderProps {
  onBack: () => void;
  onPreview: (preview: Preview, summary: string) => void;
}

// SurveyBuilder writes a new survey: questions of the six built-in types, who
// may respond, when it ends, and optionally a sealed reveal time.
export function SurveyBuilder({ onBack, onPreview }: SurveyBuilderProps) {
  const [draft, setDraft] = useState<BuilderDraft>(emptyBuilderDraft);
  const [errors, setErrors] = useState<string[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);
  const set = (patch: Partial<BuilderDraft>) => setDraft((d) => ({ ...d, ...patch }));

  function moveQuestion(i: number, by: -1 | 1) {
    setDraft((d) => {
      const questions = [...d.questions];
      [questions[i], questions[i + by]] = [questions[i + by], questions[i]];
      return { ...d, questions };
    });
  }

  async function publish() {
    setError(null);
    const { request, errors: found } = buildCreateRequest(draft, Date.now());
    setErrors(found);
    if (!request) return;
    setLoading(true);
    try {
      onPreview(await createSurvey(request), `Publish the survey “${request.title}”`);
    } catch (e) {
      setError(errorMessage(e));
    } finally {
      setLoading(false);
    }
  }

  const revealMs = new Date(draft.revealAt).getTime();
  return (
    <div className="staking">
      <Card title="New survey">
        <div className="staking-form">
          <label htmlFor="builder-title">Title</label>
          <Input id="builder-title" value={draft.title} onChange={(e) => set({ title: e.target.value })} />
          <label htmlFor="builder-description">Description</label>
          <textarea
            id="builder-description"
            className="field"
            rows={3}
            value={draft.description}
            onChange={(e) => set({ description: e.target.value })}
          />
          <label htmlFor="builder-end">Last epoch that accepts responses</label>
          <Input id="builder-end" inputMode="numeric" value={draft.endEpoch} onChange={(e) => set({ endEpoch: e.target.value })} />
          <label htmlFor="builder-anchor-uri">Presentation document URI (optional)</label>
          <Input id="builder-anchor-uri" value={draft.anchorUri} onChange={(e) => set({ anchorUri: e.target.value })} />
          <label htmlFor="builder-anchor-doc">Presentation document text (optional)</label>
          <textarea
            id="builder-anchor-doc"
            className="field"
            rows={4}
            value={draft.anchorDocument}
            onChange={(e) => set({ anchorDocument: e.target.value })}
          />
          <p className="helper-text">
            For a long description, publish a JSON document at that URI yourself and paste its exact text here;
            only its hash is put on chain, so readers can tell it was not changed. Without one, a title is required.
          </p>
          <fieldset className="survey-question">
            <legend>Who may respond</legend>
            {ALL_ROLES.map((r) => (
              <label key={r} className="survey-choice">
                <input
                  type="checkbox"
                  checked={draft.roles.includes(r)}
                  onChange={(e) =>
                    set({ roles: e.target.checked ? [...draft.roles, r] : draft.roles.filter((x) => x !== r) })
                  }
                />{" "}
                {ROLE_LABELS[r]}
              </label>
            ))}
          </fieldset>
          <p className="helper-text">The survey is owned by this wallet&apos;s payment key, which can cancel it.</p>
        </div>
      </Card>

      {draft.questions.map((q, i) => (
        <Card key={i}>
          <QuestionEditor
            n={i}
            q={q}
            count={draft.questions.length}
            onChange={(next) => set({ questions: draft.questions.map((x, j) => (j === i ? next : x)) })}
            onMove={(by) => moveQuestion(i, by)}
            onRemove={() => set({ questions: draft.questions.filter((_, j) => j !== i) })}
          />
        </Card>
      ))}
      <Button variant="ghost" onClick={() => set({ questions: [...draft.questions, emptyBuilderQuestion()] })}>
        Add question
      </Button>

      <Card title="Sealed responses">
        <div className="staking-form">
          <label>
            <input type="checkbox" checked={draft.sealed} onChange={(e) => set({ sealed: e.target.checked })} /> Seal responses until a reveal time
          </label>
          {draft.sealed && (
            <>
              <p className="helper-text">
                Answers are timelock-encrypted to a Drand quicknet round and cannot be read by anyone, including
                you, before it publishes.
              </p>
              <label htmlFor="builder-reveal">Reveal time</label>
              <Input id="builder-reveal" type="datetime-local" value={draft.revealAt} onChange={(e) => set({ revealAt: e.target.value })} />
              {!Number.isNaN(revealMs) && <p className="helper-text">Drand round {roundAt(revealMs)}</p>}
              <label htmlFor="builder-padding">Padding size (bytes)</label>
              <Input id="builder-padding" inputMode="numeric" value={draft.padding} onChange={(e) => set({ padding: e.target.value })} />
            </>
          )}
        </div>
      </Card>

      <Card title="Preview">
        <h3>{draft.title || "(untitled)"}</h3>
        <p className="helper-text">
          Open to {draft.roles.length > 0 ? draft.roles.map((r) => ROLE_LABELS[r]).join(", ") : "no one yet"}
        </p>
        <ol>
          {draft.questions.map((q, i) => (
            <li key={i}>
              {q.prompt || "(no prompt)"} <span className="helper-text">{KIND_LABELS[q.kind]}</span>
            </li>
          ))}
        </ol>
      </Card>

      {errors.length > 0 && (
        <div role="alert" className="error-text">
          <ul>
            {errors.map((m, i) => (
              <li key={i}>{m}</li>
            ))}
          </ul>
        </div>
      )}
      {error && (
        <p role="alert" className="error-text">
          {error}
        </p>
      )}
      <div className="preview-actions">
        <Button variant="ghost" onClick={onBack} disabled={loading}>
          Back
        </Button>
        <Button onClick={publish} disabled={loading}>
          {loading ? "Building…" : "Review survey"}
        </Button>
      </div>
    </div>
  );
}
