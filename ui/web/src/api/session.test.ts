import { afterEach, expect, test, vi } from "vitest";
import { controlSessionHeaders, establishControlSession } from "./session";

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
  expect(controlSessionHeaders()).toEqual({ "X-Bursa-Session": "secret-token" });
});

test("does not exchange ordinary hash routes", async () => {
  window.history.replaceState(null, "", "/#/settings");
  const fetchMock = vi.fn();
  vi.stubGlobal("fetch", fetchMock);

  await establishControlSession();

  expect(fetchMock).not.toHaveBeenCalled();
  expect(window.location.hash).toBe("#/settings");
});

test("does not expose authorization while validation is pending or after it fails", async () => {
  window.history.replaceState(null, "", "/#session=rejected-token");
  let complete!: (value: { ok: boolean }) => void;
  vi.stubGlobal("fetch", vi.fn(() => new Promise(resolve => { complete = resolve; })));
  const pending = establishControlSession();
  expect(controlSessionHeaders()).toEqual({});
  complete({ ok: false });
  await expect(pending).rejects.toThrow("authorization failed");
  expect(window.location.hash).toBe("#/");
  expect(controlSessionHeaders()).toEqual({});
});
