import { act, cleanup, render, waitFor } from "@testing-library/react";
import { afterEach, describe, expect, test, vi } from "vitest";
import { createURAssembler, DEFAULT_UR_LIMITS } from "./ur";
import type { URAssembler } from "./ur";
import { QRScanner } from "./QRScanner";

const { cameraStarts, cameraResult, cameraCallback } = vi.hoisted(() => ({
  cameraStarts: vi.fn(),
  cameraResult: { current: null as Promise<unknown> | null },
  cameraCallback: { current: null as ((result: unknown) => void) | null },
}));

vi.mock("@zxing/browser", () => ({
  BrowserQRCodeReader: class {
    decodeFromVideoDevice(
      _device?: unknown,
      _video?: unknown,
      callback?: (result: unknown) => void,
    ) {
      cameraStarts();
      cameraCallback.current = callback ?? null;
      if (cameraResult.current !== null) return cameraResult.current;
      return Promise.reject(new Error("camera initialization failed"));
    }
  },
}));

vi.mock("./ur", () => ({
  DEFAULT_UR_LIMITS: { maxDurationMs: 10 },
  createURAssembler: vi.fn().mockResolvedValue({
    receivePart: vi.fn(),
    progressPercent: () => 0,
    isError: () => false,
    error: () => "",
    isComplete: () => false,
    isSuccess: () => false,
    result: () => ({ type: "", cborHex: "" }),
  }),
}));

describe("QRScanner", () => {
  afterEach(() => {
    cleanup();
    vi.restoreAllMocks();
    vi.useRealTimers();
    cameraStarts.mockReset();
    cameraResult.current = null;
    cameraCallback.current = null;
  });

  test("clears the timeout and reports initialization failure once", async () => {
    const onError = vi.fn();
    const setTimeoutSpy = vi.spyOn(globalThis, "setTimeout");
    const clearTimeoutSpy = vi.spyOn(globalThis, "clearTimeout");

    const view = render(<QRScanner onResult={vi.fn()} onError={onError} />);
    await waitFor(() => expect(onError).toHaveBeenCalledWith("camera initialization failed"));
    const timeoutIndex = setTimeoutSpy.mock.calls.findIndex(
      ([, delay]) => delay === DEFAULT_UR_LIMITS.maxDurationMs,
    );
    expect(timeoutIndex).toBeGreaterThanOrEqual(0);
    const scannerTimeout = setTimeoutSpy.mock.results[timeoutIndex]?.value;
    expect(clearTimeoutSpy).toHaveBeenCalledWith(scannerTimeout);
    await new Promise((resolve) => setTimeout(resolve, DEFAULT_UR_LIMITS.maxDurationMs + 10));

    expect(onError).toHaveBeenCalledTimes(1);
    view.unmount();
  });

  test("reports timeout when decoder initialization never resolves", async () => {
    vi.useFakeTimers();
    vi.mocked(createURAssembler).mockReturnValueOnce(new Promise(() => {}));
    const onError = vi.fn();

    const view = render(<QRScanner onResult={vi.fn()} onError={onError} />);
    await vi.advanceTimersByTimeAsync(DEFAULT_UR_LIMITS.maxDurationMs + 1);

    expect(onError).toHaveBeenCalledWith("The scanned QR stream took too long to complete.");
    view.unmount();
  });

  test("does not start the camera when decoder initialization resolves after timeout", async () => {
    vi.useFakeTimers();
    let resolveAssembler!: (value: URAssembler) => void;
    vi.mocked(createURAssembler).mockReturnValueOnce(
      new Promise((resolve) => {
        resolveAssembler = resolve;
      }),
    );
    const onError = vi.fn();

    const view = render(<QRScanner onResult={vi.fn()} onError={onError} />);
    await vi.advanceTimersByTimeAsync(DEFAULT_UR_LIMITS.maxDurationMs + 1);
    resolveAssembler({
      receivePart: vi.fn(),
      progressPercent: () => 0,
      isError: () => false,
      error: () => "",
      isComplete: () => false,
      isSuccess: () => false,
      result: () => ({ type: "", cborHex: "" }),
    });
    await vi.runAllTicks();
    await Promise.resolve();

    expect(onError).toHaveBeenCalledTimes(1);
    expect(cameraStarts).not.toHaveBeenCalled();
    view.unmount();
  });

  test("does not start the camera after unmount during decoder initialization", async () => {
    vi.useFakeTimers();
    let resolveAssembler!: (value: URAssembler) => void;
    vi.mocked(createURAssembler).mockReturnValueOnce(
      new Promise((resolve) => {
        resolveAssembler = resolve;
      }),
    );

    const view = render(<QRScanner onResult={vi.fn()} />);
    view.unmount();
    resolveAssembler({
      receivePart: vi.fn(),
      progressPercent: () => 0,
      isError: () => false,
      error: () => "",
      isComplete: () => false,
      isSuccess: () => false,
      result: () => ({ type: "", cborHex: "" }),
    });
    await vi.runAllTicks();
    await Promise.resolve();

    expect(cameraStarts).not.toHaveBeenCalled();
  });

  test("stops a camera handle that resolves after timeout and on unmount", async () => {
    vi.useFakeTimers();
    let resolveCamera!: (value: { stop: () => void }) => void;
    const stop = vi.fn();
    cameraResult.current = new Promise((resolve) => {
      resolveCamera = resolve;
    });
    const onError = vi.fn();

    const view = render(<QRScanner onResult={vi.fn()} onError={onError} />);
    await vi.advanceTimersByTimeAsync(0);
    await vi.runAllTicks();
    await Promise.resolve();
    expect(cameraStarts).toHaveBeenCalledTimes(1);

    await vi.advanceTimersByTimeAsync(DEFAULT_UR_LIMITS.maxDurationMs + 1);
    resolveCamera({ stop });
    await vi.runAllTicks();
    await Promise.resolve();

    expect(onError).toHaveBeenCalledTimes(1);
    expect(stop).toHaveBeenCalledTimes(1);
    view.unmount();
    expect(stop).toHaveBeenCalledTimes(2);
  });

  test("stops camera controls after a successful result and on unmount", async () => {
    vi.useFakeTimers();
    const stop = vi.fn();
    cameraResult.current = Promise.resolve({ stop });
    let complete = false;
    vi.mocked(createURAssembler).mockReturnValueOnce(
      Promise.resolve({
        receivePart: () => {
          complete = true;
        },
        progressPercent: () => 100,
        isError: () => false,
        error: () => "",
        isComplete: () => complete,
        isSuccess: () => complete,
        result: () => ({ type: "test", cborHex: "00" }),
      }),
    );
    const onResult = vi.fn();

    const view = render(<QRScanner onResult={onResult} />);
    await vi.advanceTimersByTimeAsync(0);
    await vi.runAllTicks();
    await Promise.resolve();
    expect(cameraCallback.current).not.toBeNull();
    await act(async () => {
      cameraCallback.current?.({ getText: () => "ur:test/part" });
    });
    expect(onResult).toHaveBeenCalledWith({ type: "test", cborHex: "00" });
    expect(stop).toHaveBeenCalledTimes(1);
    view.unmount();
    expect(stop).toHaveBeenCalledTimes(2);
  });

  test("reports terminal receivePart errors once and stops the camera", async () => {
    vi.useFakeTimers();
    const stop = vi.fn();
    cameraResult.current = Promise.resolve({ stop });
    const onError = vi.fn();
    vi.mocked(createURAssembler).mockReturnValueOnce(
      Promise.resolve({
        receivePart: () => {
          throw new Error("The scanned QR stream contains too many frames.");
        },
        progressPercent: () => 0,
        isError: () => true,
        error: () => "The scanned QR stream contains too many frames.",
        isComplete: () => false,
        isSuccess: () => false,
        result: () => ({ type: "", cborHex: "" }),
      }),
    );

    const view = render(<QRScanner onResult={vi.fn()} onError={onError} />);
    await vi.advanceTimersByTimeAsync(0);
    await vi.runAllTicks();
    await Promise.resolve();

    await act(async () => {
      cameraCallback.current?.({ getText: () => "ur:test/part" });
    });

    expect(onError).toHaveBeenCalledWith("The scanned QR stream contains too many frames.");
    expect(onError).toHaveBeenCalledTimes(1);
    expect(stop).toHaveBeenCalledTimes(1);
    view.unmount();
  });
});
