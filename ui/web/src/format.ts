/**
 * Convert a lovelace amount (as a string) to an ADA display string.
 *
 * Uses BigInt to avoid float precision loss on values that exceed 2^53.
 * 1 ADA = 1_000_000 lovelace. Returns the integer part and up to six
 * fractional digits with trailing zeros stripped; whole amounts have no
 * decimal point. A non-integer input is returned unchanged rather than throwing.
 *
 * Examples:
 *   formatAda("4500000")        → "4.5"
 *   formatAda("1000000")        → "1"   (all trailing zeros stripped)
 *   formatAda("1000001")        → "1.000001"
 *   formatAda("0")              → "0"
 */
export function formatAda(lovelace: string): string {
  // BigInt() throws on a non-integer string; guard so a malformed API value
  // (e.g. an empty rewards field) shows through instead of crashing the screen.
  if (!/^-?\d+$/.test(lovelace)) {
    return lovelace;
  }
  const LOVELACE_PER_ADA = BigInt(1_000_000);
  const raw = BigInt(lovelace);
  const isNegative = raw < BigInt(0);
  const abs = isNegative ? -raw : raw;

  const intPart = abs / LOVELACE_PER_ADA;
  const fracPart = abs % LOVELACE_PER_ADA;

  if (fracPart === BigInt(0)) {
    return (isNegative ? "-" : "") + intPart.toString();
  }

  // Pad to 6 digits, then strip trailing zeros.
  const fracStr = fracPart.toString().padStart(6, "0").replace(/0+$/, "");
  return (isNegative ? "-" : "") + intPart.toString() + "." + fracStr;
}

/**
 * Convert an ADA amount string entered by the user to an integer lovelace count.
 *
 * Inverse of formatAda. Uses BigInt to avoid float drift.
 * 1 ADA = 1_000_000 lovelace.
 *
 * Rejects with a descriptive Error:
 *   - non-numeric or empty input
 *   - value ≤ 0
 *   - more than 6 fractional digits
 *
 * Returns the lovelace count as a decimal string (the spend API takes uint64
 * amounts as strings) so large values never round-trip through a lossy number.
 *
 * Examples:
 *   parseAda("1.5")      → "1500000"
 *   parseAda("1")        → "1000000"
 *   parseAda("0.000001") → "1"
 *   parseAda("abc")      → throws
 *   parseAda("-1")       → throws
 *   parseAda("0")        → throws
 *   parseAda("1.1234567")→ throws
 */
export function parseAda(ada: string): string {
  const trimmed = ada.trim();
  // Must be a positive decimal with at most 6 fractional digits.
  // Accepts: "1", "1.5", "0.000001" — rejects negatives, leading signs, etc.
  if (!/^\d+(\.\d+)?$/.test(trimmed)) {
    throw new Error("Invalid ADA amount");
  }

  const parts = trimmed.split(".");
  const intStr = parts[0];
  const fracStr = parts[1] ?? "";

  if (fracStr.length > 6) {
    throw new Error("ADA amount has more than 6 decimal places");
  }

  // Pad fractional part to 6 digits.
  const paddedFrac = fracStr.padEnd(6, "0");

  const lovelace = BigInt(intStr) * BigInt(1_000_000) + BigInt(paddedFrac);

  if (lovelace <= BigInt(0)) {
    throw new Error("ADA amount must be greater than 0");
  }

  return lovelace.toString();
}
