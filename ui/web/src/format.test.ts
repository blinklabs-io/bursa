import { parseAda, formatTokenQuantity } from "./format";

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

// --- formatTokenQuantity tests ---
// The native-token generalization of formatAda (ADA is the 6-decimal special
// case of lovelace); used once a native asset's decimals is known from its
// on-chain metadata.

test("formatTokenQuantity: applies 6 decimals like ADA", () => {
  expect(formatTokenQuantity("4500000", 6)).toBe("4.5");
});

test("formatTokenQuantity: strips trailing zero fractional digits", () => {
  expect(formatTokenQuantity("1000000", 6)).toBe("1");
});

test("formatTokenQuantity: keeps significant fractional digits", () => {
  expect(formatTokenQuantity("1000001", 6)).toBe("1.000001");
});

test("formatTokenQuantity: works with 2 decimals", () => {
  expect(formatTokenQuantity("150", 2)).toBe("1.5");
});

test("formatTokenQuantity: 0 decimals returns the raw integer unchanged", () => {
  expect(formatTokenQuantity("12345", 0)).toBe("12345");
});

test("formatTokenQuantity: negative decimals is treated as no-op (returned unchanged)", () => {
  expect(formatTokenQuantity("12345", -1)).toBe("12345");
});

test("formatTokenQuantity: a non-integer quantity string is returned unchanged", () => {
  expect(formatTokenQuantity("abc", 6)).toBe("abc");
});

test("formatTokenQuantity: preserves values beyond 2^53 (no precision ceiling)", () => {
  expect(formatTokenQuantity("9007199255000000", 6)).toBe("9007199255");
});

test("formatTokenQuantity: formats a negative quantity", () => {
  expect(formatTokenQuantity("-1500000", 6)).toBe("-1.5");
});

test("formatTokenQuantity: decimals beyond the sane cap is returned unchanged (DoS guard)", () => {
  // decimals comes from on-chain metadata anyone can mint arbitrary values
  // into; an unbounded value must never reach BigInt exponentiation.
  expect(formatTokenQuantity("12345", 1_000_000_000)).toBe("12345");
});

test("formatTokenQuantity: decimals at the cap boundary still formats normally", () => {
  expect(formatTokenQuantity("1" + "0".repeat(18), 18)).toBe("1");
});
