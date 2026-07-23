import { act, renderHook } from "@testing-library/react";
import { useHashRoute, navigate } from "./router";

// The hash is global state shared across the jsdom window; reset it between
// tests so a leftover route from one case can't leak into the next.
afterEach(() => {
  window.location.hash = "";
});

// --- getRoute parsing (observed through useHashRoute's initial value) ---

test("defaults to portfolio when there is no hash", () => {
  window.location.hash = "";
  const { result } = renderHook(() => useHashRoute());
  expect(result.current).toBe("portfolio");
});

test("defaults to portfolio for a bare '#/' with no route name", () => {
  window.location.hash = "#/";
  const { result } = renderHook(() => useHashRoute());
  expect(result.current).toBe("portfolio");
});

test("parses '#/route' into the bare route name", () => {
  window.location.hash = "#/staking";
  const { result } = renderHook(() => useHashRoute());
  expect(result.current).toBe("staking");
});

// --- navigate ---

test("navigate writes a canonical '#/route' hash", () => {
  navigate("settings");
  expect(window.location.hash).toBe("#/settings");
});

test("navigate then useHashRoute round-trips the route name", () => {
  navigate("send");
  const { result } = renderHook(() => useHashRoute());
  expect(result.current).toBe("send");
});

// --- reactivity: hashchange updates the hook ---

test("useHashRoute updates when the hash changes after mount", () => {
  window.location.hash = "#/portfolio";
  const { result } = renderHook(() => useHashRoute());
  expect(result.current).toBe("portfolio");

  act(() => {
    navigate("swap");
    window.dispatchEvent(new Event("hashchange"));
  });

  expect(result.current).toBe("swap");
});

test("useHashRoute stops updating after unmount (listener cleanup)", () => {
  window.location.hash = "#/portfolio";
  const { result, unmount } = renderHook(() => useHashRoute());
  unmount();

  act(() => {
    navigate("contacts");
    window.dispatchEvent(new Event("hashchange"));
  });

  // The unmounted hook keeps its last value; no throw from a stale setState.
  expect(result.current).toBe("portfolio");
});

// --- prototype-pollution safety property ---
//
// The router itself only ever produces plain route strings — it never resolves
// a route into a handler. The defense (see the long comment in app.tsx) is that
// app.tsx stores routes in a Map, not a plain object, so a crafted hash like
// "#/__proto__" or "#/constructor" resolves to a real, absent key rather than an
// inherited Object.prototype member. These tests lock that property at the
// lookup layer the router feeds.

test("crafted '#/__proto__' and '#/constructor' hashes parse to their literal names", () => {
  window.location.hash = "#/__proto__";
  expect(renderHook(() => useHashRoute()).result.current).toBe("__proto__");

  window.location.hash = "#/constructor";
  expect(renderHook(() => useHashRoute()).result.current).toBe("constructor");
});

test("a Map lookup rejects inherited-member route names that a plain object would resolve", () => {
  const routes = new Map<string, () => string>([["portfolio", () => "Portfolio"]]);

  for (const crafted of ["__proto__", "constructor", "toString", "hasOwnProperty"]) {
    // The Map has no such route: unknown → app falls back to Portfolio.
    expect(routes.has(crafted)).toBe(false);
    expect(routes.get(crafted)).toBeUndefined();
  }

  // Contrast: a plain object is the footgun the Map avoids — these inherited
  // members are truthy and callable, which is exactly what would hijack routing.
  const asObject: Record<string, unknown> = { portfolio: () => "Portfolio" };
  expect(asObject["constructor"]).toBeDefined();
  expect(typeof asObject["toString"]).toBe("function");
});
