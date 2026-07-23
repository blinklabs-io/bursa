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

test("registers a hashchange listener on mount and removes the same one on unmount", () => {
  const add = vi.spyOn(window, "addEventListener");
  const remove = vi.spyOn(window, "removeEventListener");
  window.location.hash = "#/portfolio";

  const { unmount } = renderHook(() => useHashRoute());

  // Mount must register a hashchange listener…
  const registration = add.mock.calls.find(([type]) => type === "hashchange");
  expect(registration).toBeDefined();
  const handler = registration![1];
  expect(remove).not.toHaveBeenCalledWith("hashchange", handler);

  // …and unmount must remove that exact handler (fails if the effect's
  // cleanup omits removeEventListener, unlike a behavioural-only assertion).
  unmount();
  expect(remove).toHaveBeenCalledWith("hashchange", handler);

  add.mockRestore();
  remove.mockRestore();
});

test("useHashRoute stops updating after unmount (no stale setState)", () => {
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
// a route into a handler, so all it can do here is faithfully echo a crafted
// hash as its literal route name (asserted below). The actual defense lives in
// app.tsx, which resolves routes through a Map (not a plain object) so a crafted
// hash like "#/__proto__" or "#/constructor" hits a real, absent key rather than
// an inherited Object.prototype member. That end-to-end property is exercised
// against the production ROUTES lookup by rendering <App /> with those hashes in
// app.test.tsx ("a crafted hash … falls back to Portfolio"); it is verified there
// rather than against a hand-built Map here, so the check is bound to the code
// that ships.

test("crafted '#/__proto__' and '#/constructor' hashes parse to their literal names", () => {
  window.location.hash = "#/__proto__";
  expect(renderHook(() => useHashRoute()).result.current).toBe("__proto__");

  window.location.hash = "#/constructor";
  expect(renderHook(() => useHashRoute()).result.current).toBe("constructor");
});
