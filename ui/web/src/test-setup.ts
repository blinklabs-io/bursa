import "@testing-library/jest-dom/vitest";

// jsdom doesn't implement matchMedia; src/theme.ts uses it to read the OS
// light/dark preference. Default to "no match" (dark) so any test that
// renders theme-aware UI works without further setup; individual tests can
// still override window.matchMedia to exercise a specific OS preference.
if (typeof window !== "undefined" && !window.matchMedia) {
  window.matchMedia = ((query: string) =>
    ({
      matches: false,
      media: query,
      onchange: null,
      addListener: () => {},
      removeListener: () => {},
      addEventListener: () => {},
      removeEventListener: () => {},
      dispatchEvent: () => false,
    }) as unknown as MediaQueryList) as typeof window.matchMedia;
}
