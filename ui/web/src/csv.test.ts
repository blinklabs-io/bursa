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
    [
      ["=cmd|' /C calc'!A1"],
      ["+1+1"],
      ["-1+1"],
      ["@SUM(A1:A2)"],
      ["\t=SUM(A1:A2)"],
      ["\n=SUM(A1:A2)"],
      ["\r=SUM(A1:A2)"],
    ],
  );
  expect(csv).toBe(
    [
      "field",
      "'=cmd|' /C calc'!A1",
      "'+1+1",
      "'-1+1",
      "'@SUM(A1:A2)",
      "'\t=SUM(A1:A2)",
      "\"'\n=SUM(A1:A2)\"",
      "\"'\r=SUM(A1:A2)\"",
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

test("toCsv preserves plain signed numeric fields", () => {
  const csv = toCsv(
    ["n"],
    [[-42], ["-42"], ["+42"], ["-.5"], ["+1.25e-3"], ["-1E+3"]],
  );
  expect(csv).toBe("n\r\n-42\r\n-42\r\n+42\r\n-.5\r\n+1.25e-3\r\n-1E+3");
});
