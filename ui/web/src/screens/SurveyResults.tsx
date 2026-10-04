import type { SurveyDetail, SurveyOptionTally, SurveyQuestion, SurveyQuestionTally } from "../api/types";
import { Card } from "../components/Card";
import { shortId } from "../format";
import { KIND_LABELS, ROLE_LABELS, optionLabels } from "../surveys";

function plural(n: number, word: string): string {
  return `${n} ${word}${n === 1 ? "" : "s"}`;
}

function optionCaption(kind: SurveyQuestion["kind"], o: SurveyOptionTally): string {
  switch (kind) {
    case 3:
      return `${plural(o.count, "ranking")}, ${o.first ?? 0} first`;
    case 5:
      return `${o.sum ?? 0} points from ${plural(o.count, "response")}`;
    case 6:
      return `${plural(o.count, "rating")}, total ${o.sum ?? 0}`;
    default:
      return plural(o.count, "vote");
  }
}

function QuestionResult({ index, q, t }: { index: number; q: SurveyQuestion; t: SurveyQuestionTally }) {
  const labels = optionLabels(q);
  const top = Math.max(1, ...(t.options ?? []).map((o) => o.count));
  return (
    <div className="survey-result">
      <p className="survey-prompt">
        {index + 1}. {q.prompt || KIND_LABELS[q.kind]}
      </p>
      <p className="helper-text">
        {t.answered} answered, {t.abstained} abstained
      </p>
      {t.options?.map((o, i) => (
        <div key={i} className="survey-option-result">
          <span>{labels[i] ?? `Option ${i + 1}`}</span>
          <meter min={0} max={top} value={o.count} aria-label={`${labels[i]} count`} />
          <span className="helper-text">{optionCaption(q.kind, o)}</span>
        </div>
      ))}
      {t.numeric && (
        <p className="helper-text">
          Sum {t.numeric.sum}, lowest {t.numeric.min}, highest {t.numeric.max}
        </p>
      )}
    </div>
  );
}

// SurveyResults shows per-role participation and per-question results. CIP-179
// defines no weighted total, so none is shown; roles are never merged.
export function SurveyResults({ survey }: { survey: SurveyDetail }) {
  const tally = survey.tally;
  if (!tally) return null;
  return (
    <>
      {tally.roles.map((r) => (
        <Card key={r.role} title={`Results: ${ROLE_LABELS[r.role]}`}>
          <p>
            {plural(r.responses, "response")}
            {r.sealed ? `, ${r.sealed} still sealed` : ""}
          </p>
          {r.responses > 0 &&
            survey.definition.questions.map((q, i) => (
              <QuestionResult key={i} index={i} q={q} t={r.questions[i]} />
            ))}
        </Card>
      ))}
      {tally.excluded.length > 0 && (
        <Card title="Excluded responses">
          <p className="helper-text">
            Left out of the results above because they failed a CIP-179 check or were replaced by a later
            response from the same credential.
          </p>
          <ul>
            {tally.excluded.map((e, i) => (
              <li key={i}>
                <code>{shortId(e.tx_hash)}</code> ({ROLE_LABELS[e.role]}): {e.reason}
              </li>
            ))}
          </ul>
        </Card>
      )}
    </>
  );
}
