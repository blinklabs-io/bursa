import {
  pickChallengeIndices,
  normalizeWord,
  isChallengeAnswerCorrect,
  validateChallenge,
  CHALLENGE_WORD_COUNT,
} from "./phraseChallenge";

test("CHALLENGE_WORD_COUNT is 3", () => {
  expect(CHALLENGE_WORD_COUNT).toBe(3);
});

test("pickChallengeIndices returns the requested count of distinct, in-range, sorted indices", () => {
  // A deterministic rng that cycles through fixed fractions.
  const values = [0.01, 0.5, 0.99, 0.2];
  let i = 0;
  const rng = () => values[i++ % values.length];
  const indices = pickChallengeIndices(24, 3, rng);
  expect(indices).toHaveLength(3);
  expect(new Set(indices).size).toBe(3);
  for (const idx of indices) {
    expect(idx).toBeGreaterThanOrEqual(0);
    expect(idx).toBeLessThan(24);
  }
  expect(indices).toEqual([...indices].sort((a, b) => a - b));
});

test("pickChallengeIndices retries on duplicate rng draws until distinct", () => {
  // First two draws collide (both map to index 0); rng must be called again.
  const values = [0.0, 0.0, 0.5, 0.9];
  let i = 0;
  const rng = () => values[i++];
  const indices = pickChallengeIndices(10, 2, rng);
  expect(indices).toHaveLength(2);
  expect(new Set(indices).size).toBe(2);
});

test("pickChallengeIndices throws when count exceeds wordCount", () => {
  expect(() => pickChallengeIndices(2, 3)).toThrow();
});

test("normalizeWord trims whitespace and lowercases", () => {
  expect(normalizeWord("  Zebra  ")).toBe("zebra");
  expect(normalizeWord("ZEBRA")).toBe("zebra");
  expect(normalizeWord("zebra")).toBe("zebra");
});

const WORDS = [
  "abandon", "ability", "able", "about", "above", "absent",
  "absorb", "abstract", "absurd", "abuse", "access", "accident",
  "account", "accuse", "achieve", "acid", "acoustic", "acquire",
  "across", "act", "action", "actor", "actress", "actual",
];

test("isChallengeAnswerCorrect matches case- and whitespace-insensitively", () => {
  expect(isChallengeAnswerCorrect(WORDS, 0, "  Abandon  ")).toBe(true);
  expect(isChallengeAnswerCorrect(WORDS, 0, "wrong")).toBe(false);
  expect(isChallengeAnswerCorrect(WORDS, 0, undefined)).toBe(false);
  expect(isChallengeAnswerCorrect(WORDS, 0, "   ")).toBe(false);
});

test("validateChallenge accepts exact matches at the challenged indices", () => {
  const indices = [0, 5, 23];
  const answers = { 0: "abandon", 5: "absent", 23: "actual" };
  expect(validateChallenge(WORDS, indices, answers)).toBe(true);
});

test("validateChallenge is case- and whitespace-insensitive", () => {
  const indices = [0, 5];
  const answers = { 0: "  Abandon", 5: "ABSENT  " };
  expect(validateChallenge(WORDS, indices, answers)).toBe(true);
});

test("validateChallenge rejects a wrong word at any challenged index", () => {
  const indices = [0, 5, 23];
  const answers = { 0: "abandon", 5: "wrong-word", 23: "actual" };
  expect(validateChallenge(WORDS, indices, answers)).toBe(false);
});

test("validateChallenge rejects a missing answer", () => {
  const indices = [0, 5];
  const answers = { 0: "abandon" };
  expect(validateChallenge(WORDS, indices, answers)).toBe(false);
});

test("validateChallenge rejects a blank answer", () => {
  const indices = [0, 5];
  const answers = { 0: "abandon", 5: "   " };
  expect(validateChallenge(WORDS, indices, answers)).toBe(false);
});

test("validateChallenge ignores unrelated answers outside the challenged indices", () => {
  const indices = [0];
  const answers = { 0: "abandon", 1: "totally-wrong-but-not-asked" };
  expect(validateChallenge(WORDS, indices, answers)).toBe(true);
});
