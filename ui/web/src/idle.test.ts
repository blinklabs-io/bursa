import { isIdleTimeoutElapsed } from "./idle";

test("Off (0) never elapses regardless of how much time has passed", () => {
  expect(isIdleTimeoutElapsed(0, 10_000_000, 0)).toBe(false);
});

test("a negative timeout is treated as Off", () => {
  expect(isIdleTimeoutElapsed(0, 10_000_000, -5)).toBe(false);
});

test("elapses exactly at the boundary", () => {
  const timeoutMinutes = 5;
  const last = 0;
  const now = timeoutMinutes * 60_000;
  expect(isIdleTimeoutElapsed(last, now, timeoutMinutes)).toBe(true);
});

test("does not elapse just before the boundary", () => {
  const timeoutMinutes = 5;
  const last = 0;
  const now = timeoutMinutes * 60_000 - 1;
  expect(isIdleTimeoutElapsed(last, now, timeoutMinutes)).toBe(false);
});

test("does not elapse immediately after activity", () => {
  const last = 1_000_000;
  expect(isIdleTimeoutElapsed(last, last + 1, 15)).toBe(false);
});

test("elapses well past the boundary", () => {
  expect(isIdleTimeoutElapsed(0, 999_999_999, 1)).toBe(true);
});
