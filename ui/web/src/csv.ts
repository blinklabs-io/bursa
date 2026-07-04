/**
 * Escape one CSV field per RFC 4180: wrap in quotes if it contains a comma,
 * quote, newline, or carriage return, doubling any embedded quotes.
 *
 * Also neutralizes spreadsheet formula-injection (OWASP CSV-injection
 * guidance): a field whose first character is one of `= + - @`, tab, or CR
 * gets a leading single quote (') prefixed, forcing spreadsheet apps to
 * render it as text instead of evaluating it as a formula. This means e.g. a
 * negative amount like "-42" exports as "'-42" (rendered as text) — an
 * accepted, safe tradeoff.
 */
function csvField(value: string | number): string {
  let s = String(value);
  if (/^[=+\-@\t\r]/.test(s)) {
    s = `'${s}`;
  }
  if (/[",\n\r]/.test(s)) {
    return `"${s.replace(/"/g, '""')}"`;
  }
  return s;
}

/**
 * Build a CSV document (CRLF line endings, per RFC 4180) from a header row
 * and data rows. Entirely client-side — no network involved.
 */
export function toCsv(headers: string[], rows: (string | number)[][]): string {
  const lines = [headers.map(csvField).join(",")];
  for (const row of rows) {
    lines.push(row.map(csvField).join(","));
  }
  return lines.join("\r\n");
}
