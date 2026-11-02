import { afterEach, expect, test, vi } from "vitest";
import { establishControlSession } from "./session";

afterEach(() => {
  vi.unstubAllGlobals();
  window.history.replaceState(null, "", "/");
});

test("exchanges the launch fragment for a server session and removes it", async () => {
  window.history.replaceState(null, "", "/#session=secret-token");
  const fetchMock = vi.fn().mockResolvedValue({ ok: true });
  vi.stubGlobal("fetch", fetchMock);

  await establishControlSession();

  expect(fetchMock).toHaveBeenCalledWith("/session", {
    method: "POST",
    headers: { "X-Bursa-Session": "secret-token" },
  });
  expect(window.location.hash).toBe("#/");
});

test("does not exchange ordinary hash routes", async () => {
  window.history.replaceState(null, "", "/#/settings");
  const fetchMock = vi.fn();
  vi.stubGlobal("fetch", fetchMock);

  await establishControlSession();

  expect(fetchMock).not.toHaveBeenCalled();
  expect(window.location.hash).toBe("#/settings");
});
