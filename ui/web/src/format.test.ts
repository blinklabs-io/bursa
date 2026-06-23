import { parseAda } from "./format";

// --- parseAda tests ---

test("parseAda: '1.5' → '1500000'", () => {
  expect(parseAda("1.5")).toBe("1500000");
});

test("parseAda: '1' → '1000000'", () => {
  expect(parseAda("1")).toBe("1000000");
});

test("parseAda: '0.000001' → '1'", () => {
  expect(parseAda("0.000001")).toBe("1");
});

test("parseAda: rejects 'abc'", () => {
  expect(() => parseAda("abc")).toThrow();
});

test("parseAda: rejects '-1'", () => {
  expect(() => parseAda("-1")).toThrow();
});

test("parseAda: rejects '0'", () => {
  expect(() => parseAda("0")).toThrow();
});

test("parseAda: rejects '1.1234567' (> 6 decimals)", () => {
  expect(() => parseAda("1.1234567")).toThrow();
});

test("parseAda: '10.5' → '10500000'", () => {
  expect(parseAda("10.5")).toBe("10500000");
});

test("parseAda: '0.5' → '500000'", () => {
  expect(parseAda("0.5")).toBe("500000");
});

test("parseAda: preserves values beyond 2^53 (no precision ceiling)", () => {
  // 9_007_199_255 ADA = 9007199255000000 lovelace, just past Number.MAX_SAFE_INTEGER
  // (9007199254740992). The old number-returning parseAda threw here.
  expect(parseAda("9007199255")).toBe("9007199255000000");
});

test("parseAda: rejects '' (empty string)", () => {
  expect(() => parseAda("")).toThrow();
});

test("parseAda: '0.0' is rejected (equals zero lovelace effectively? No, 0.0 = 0)", () => {
  expect(() => parseAda("0.0")).toThrow();
});
