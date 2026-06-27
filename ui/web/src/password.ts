// Mirrors keystore.MinPasswordLen on the node; the server remains authoritative.
export const MIN_PASSWORD_LEN = 12;

// Count code points, not UTF-16 code units, to match Go's utf8.RuneCountInString.
export function passwordLength(password: string): number {
  return [...password].length;
}
