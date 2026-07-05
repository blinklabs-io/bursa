import { renderHook, act } from "@testing-library/react";
import {
  getStoredTheme,
  getSystemTheme,
  resolveTheme,
  applyTheme,
  setTheme,
  initTheme,
  watchSystemTheme,
  useTheme,
} from "./theme";

const STORAGE_KEY = "bursa:theme";

function mockMatchMedia(matchesLight: boolean) {
  const listeners = new Set<(e: MediaQueryListEvent) => void>();
  const mql = {
    matches: matchesLight,
    media: "(prefers-color-scheme: light)",
    onchange: null,
    addListener: () => {},
    removeListener: () => {},
    addEventListener: (_event: string, cb: (e: MediaQueryListEvent) => void) => listeners.add(cb),
    removeEventListener: (_event: string, cb: (e: MediaQueryListEvent) => void) =>
      listeners.delete(cb),
    dispatchEvent: () => false,
  } as unknown as MediaQueryList;
  window.matchMedia = vi.fn().mockReturnValue(mql);
  return {
    fire: (matches: boolean) => listeners.forEach((cb) => cb({ matches } as MediaQueryListEvent)),
  };
}

afterEach(() => {
  localStorage.clear();
  document.documentElement.removeAttribute("data-theme");
  vi.restoreAllMocks();
});

test("getStoredTheme returns null when nothing has been saved", () => {
  expect(getStoredTheme()).toBeNull();
});

test("getStoredTheme returns a previously persisted valid theme", () => {
  localStorage.setItem(STORAGE_KEY, "light");
  expect(getStoredTheme()).toBe("light");
});

test("getStoredTheme ignores a garbage stored value", () => {
  localStorage.setItem(STORAGE_KEY, "solarized");
  expect(getStoredTheme()).toBeNull();
});

test("getSystemTheme reflects the OS light preference", () => {
  mockMatchMedia(true);
  expect(getSystemTheme()).toBe("light");
});

test("getSystemTheme falls back to dark when the OS has no light preference", () => {
  mockMatchMedia(false);
  expect(getSystemTheme()).toBe("dark");
});

test("resolveTheme prefers the stored choice over the OS preference", () => {
  mockMatchMedia(true); // OS says light
  localStorage.setItem(STORAGE_KEY, "dark"); // user chose dark
  expect(resolveTheme()).toBe("dark");
});

test("resolveTheme falls back to the OS preference when nothing is stored", () => {
  mockMatchMedia(true);
  expect(resolveTheme()).toBe("light");
});

test("applyTheme sets data-theme on the document root", () => {
  applyTheme("light");
  expect(document.documentElement.getAttribute("data-theme")).toBe("light");
  applyTheme("dark");
  expect(document.documentElement.getAttribute("data-theme")).toBe("dark");
});

test("setTheme applies AND persists the choice, so it reads back after a reload", () => {
  setTheme("light");
  expect(document.documentElement.getAttribute("data-theme")).toBe("light");
  expect(localStorage.getItem(STORAGE_KEY)).toBe("light");
  // Simulate a fresh load: a new resolveTheme() call reads the persisted value.
  expect(resolveTheme()).toBe("light");
});

test("initTheme applies and returns the resolved theme", () => {
  mockMatchMedia(true);
  const theme = initTheme();
  expect(theme).toBe("light");
  expect(document.documentElement.getAttribute("data-theme")).toBe("light");
});

test("watchSystemTheme invokes the callback on OS preference changes and can unsubscribe", () => {
  const { fire } = mockMatchMedia(false);
  const cb = vi.fn();
  const unsubscribe = watchSystemTheme(cb);

  fire(true);
  expect(cb).toHaveBeenCalledWith("light");

  unsubscribe();
  cb.mockClear();
  fire(false);
  expect(cb).not.toHaveBeenCalled();
});

test("watchSystemTheme falls back to addListener/removeListener when addEventListener is unavailable (Safari < 14)", () => {
  const listeners = new Set<(e: MediaQueryListEvent) => void>();
  const mql = {
    matches: false,
    media: "(prefers-color-scheme: light)",
    onchange: null,
    addListener: (cb: (e: MediaQueryListEvent) => void) => listeners.add(cb),
    removeListener: (cb: (e: MediaQueryListEvent) => void) => listeners.delete(cb),
    dispatchEvent: () => false,
  } as unknown as MediaQueryList;
  window.matchMedia = vi.fn().mockReturnValue(mql);

  const cb = vi.fn();
  const unsubscribe = watchSystemTheme(cb);

  listeners.forEach((l) => l({ matches: true } as MediaQueryListEvent));
  expect(cb).toHaveBeenCalledWith("light");

  unsubscribe();
  cb.mockClear();
  listeners.forEach((l) => l({ matches: false } as MediaQueryListEvent));
  expect(cb).not.toHaveBeenCalled();
});

test("useTheme reads the initial theme and its setter applies + persists", () => {
  mockMatchMedia(false);
  const { result } = renderHook(() => useTheme());
  expect(result.current[0]).toBe("dark");

  act(() => result.current[1]("light"));

  expect(result.current[0]).toBe("light");
  expect(document.documentElement.getAttribute("data-theme")).toBe("light");
  expect(localStorage.getItem(STORAGE_KEY)).toBe("light");
});

test("useTheme tracks live OS changes only until the user makes an explicit choice", () => {
  const { fire } = mockMatchMedia(false);
  const { result } = renderHook(() => useTheme());
  expect(result.current[0]).toBe("dark");

  // No explicit choice yet: OS flipping to light should update the hook AND
  // the DOM attribute the CSS keys off of.
  act(() => fire(true));
  expect(result.current[0]).toBe("light");
  expect(document.documentElement.getAttribute("data-theme")).toBe("light");

  // User makes an explicit choice...
  act(() => result.current[1]("dark"));
  expect(result.current[0]).toBe("dark");

  // ...so a later OS change must NOT override it, in state or in the DOM.
  act(() => fire(true));
  expect(result.current[0]).toBe("dark");
  expect(document.documentElement.getAttribute("data-theme")).toBe("dark");
  expect(localStorage.getItem(STORAGE_KEY)).toBe("dark");
});
