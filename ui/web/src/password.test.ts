import { MIN_PASSWORD_LEN, passwordLength } from "./password";

test("MIN_PASSWORD_LEN mirrors the node keystore minimum (12)", () => {
  expect(MIN_PASSWORD_LEN).toBe(12);
});

// --- passwordLength counts code points, not bytes or UTF-16 units ---

test("counts ASCII characters one-for-one", () => {
  expect(passwordLength("")).toBe(0);
  expect(passwordLength("abc")).toBe(3);
  expect(passwordLength("a".repeat(12))).toBe(12);
});

test("counts a multi-byte character as a single code point (not its UTF-8 byte length)", () => {
  // "é" is 2 UTF-8 bytes but one code point.
  expect(passwordLength("é")).toBe(1);
  // "€" is 3 UTF-8 bytes but one code point.
  expect(passwordLength("€")).toBe(1);
});

test("counts an astral-plane emoji as one code point, not two UTF-16 units", () => {
  // "😀" is a surrogate pair: length 2 via String.length, 1 code point.
  expect("😀".length).toBe(2);
  expect(passwordLength("😀")).toBe(1);
});

// --- boundary behavior at the MIN_PASSWORD_LEN gate ---
// Every create/add-wallet flow rejects `passwordLength(pw) < MIN_PASSWORD_LEN`.

test("a password one code point short of the minimum is below the gate", () => {
  const eleven = "a".repeat(MIN_PASSWORD_LEN - 1);
  expect(passwordLength(eleven)).toBe(MIN_PASSWORD_LEN - 1);
  expect(passwordLength(eleven) < MIN_PASSWORD_LEN).toBe(true);
});

test("a password of exactly the minimum length passes the gate", () => {
  const twelve = "a".repeat(MIN_PASSWORD_LEN);
  expect(passwordLength(twelve)).toBe(MIN_PASSWORD_LEN);
  expect(passwordLength(twelve) < MIN_PASSWORD_LEN).toBe(false);
});

test("12 emoji pass the gate on code points even though String.length is 24", () => {
  const pw = "😀".repeat(MIN_PASSWORD_LEN);
  expect(pw.length).toBe(MIN_PASSWORD_LEN * 2); // UTF-16 units
  expect(passwordLength(pw)).toBe(MIN_PASSWORD_LEN); // code points
  expect(passwordLength(pw) < MIN_PASSWORD_LEN).toBe(false);
});
