import { toCsv } from "./csv";

test("toCsv joins headers and rows with commas and CRLF line endings", () => {
  const csv = toCsv(
    ["a", "b"],
    [
      ["1", "2"],
      ["3", "4"],
    ],
  );
  expect(csv).toBe("a,b\r\n1,2\r\n3,4");
});

test("toCsv quotes fields containing commas, quotes, or newlines", () => {
  const csv = toCsv(["field"], [['has,comma'], ['has"quote'], ["has\nnewline"]]);
  expect(csv).toBe('field\r\n"has,comma"\r\n"has""quote"\r\n"has\nnewline"');
});

test("toCsv accepts numeric fields", () => {
  const csv = toCsv(["n"], [[42]]);
  expect(csv).toBe("n\r\n42");
});

test("toCsv with no rows renders only the header", () => {
  expect(toCsv(["a", "b"], [])).toBe("a,b");
});

test("toCsv neutralizes formula-injection leading characters with a single quote", () => {
  const csv = toCsv(
    ["field"],
    [["=cmd|' /C calc'!A1"], ["+1+1"], ["-1+1"], ["@SUM(A1:A2)"]],
  );
  expect(csv).toBe(
    [
      "field",
      "'=cmd|' /C calc'!A1",
      "'+1+1",
      "'-1+1",
      "'@SUM(A1:A2)",
    ].join("\r\n"),
  );
});

test("toCsv quotes a field starting with a leading single quote after neutralizing AND containing a comma", () => {
  const csv = toCsv(["field"], [["=1,2"]]);
  expect(csv).toBe('field\r\n"\'=1,2"');
});

test("toCsv quotes fields containing a bare carriage return", () => {
  const csv = toCsv(["field"], [["has\rcr"]]);
  expect(csv).toBe('field\r\n"has\rcr"');
});

test("toCsv does not alter a plain negative-looking numeric field differently than any other leading-dash field", () => {
  // Documents the accepted tradeoff: a negative amount exports as text.
  expect(toCsv(["n"], [["-42"]])).toBe("n\r\n'-42");
});
