// Pure logic for the recovery-phrase re-entry challenge shown in the
// create-confirm step: after the server generates the recovery phrase and the
// user has viewed it, they must correctly re-type a few random words (by
// position) before the "Create wallet" submit is enabled. This is a UX check
// that the phrase was actually saved, not an entropy or security boundary, so
// picking positions with Math.random is fine. Kept separate from the
// AddWallet screen so "which positions are asked" and "was the answer
// correct" are unit-testable without rendering anything.

// CHALLENGE_WORD_COUNT is how many random positions the user must confirm.
export const CHALLENGE_WORD_COUNT = 3;

/**
 * pickChallengeIndices picks `count` distinct random positions in
 * [0, wordCount), returned sorted ascending so the challenge always presents
 * "word #4, word #9, ..." in phrase order rather than a shuffled one. `rng`
 * defaults to Math.random but is injectable for deterministic tests.
 */
export function pickChallengeIndices(
  wordCount: number,
  count: number,
  rng: () => number = Math.random,
): number[] {
  if (count > wordCount) {
    throw new Error("challenge word count exceeds the mnemonic length");
  }
  const indices = new Set<number>();
  while (indices.size < count) {
    // Clamp defensively: the `rng` contract is [0, 1), but a custom test rng
    // could return exactly 1 (or higher) and push the index out of bounds.
    indices.add(Math.min(Math.floor(rng() * wordCount), wordCount - 1));
  }
  return [...indices].sort((a, b) => a - b);
}

// normalizeWord makes comparison whitespace- and case-insensitive: the user
// may type "Zebra" or add stray spaces, and it should still count as correct.
export function normalizeWord(word: string): string {
  return word.trim().toLowerCase();
}

/**
 * isChallengeAnswerCorrect reports whether a single typed answer matches the
 * mnemonic's actual word at the given index. A blank answer is never correct.
 */
export function isChallengeAnswerCorrect(words: string[], index: number, answer: string | undefined): boolean {
  if (!answer) return false;
  return normalizeWord(answer) === normalizeWord(words[index] ?? "");
}

/**
 * validateChallenge reports whether the user's answers match the mnemonic's
 * actual words at every challenged index. `answers` maps a challenged index
 * to the user's typed word; a missing or blank answer never counts as
 * correct.
 */
export function validateChallenge(
  words: string[],
  indices: number[],
  answers: Partial<Record<number, string>>,
): boolean {
  return indices.every((i) => isChallengeAnswerCorrect(words, i, answers[i]));
}
