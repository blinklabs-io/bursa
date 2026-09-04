import { render, waitFor } from "@testing-library/react";
import { afterEach, describe, expect, test, vi } from "vitest";
import { DEFAULT_UR_LIMITS } from "./ur";
import { QRScanner } from "./QRScanner";

vi.mock("@zxing/browser", () => ({
  BrowserQRCodeReader: class {
    decodeFromVideoDevice() {
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
    vi.useRealTimers();
  });

  test("clears the timeout and reports initialization failure once", async () => {
    const onError = vi.fn();

    render(<QRScanner onResult={vi.fn()} onError={onError} />);
    await waitFor(() => expect(onError).toHaveBeenCalledWith("camera initialization failed"));
    await new Promise((resolve) => setTimeout(resolve, DEFAULT_UR_LIMITS.maxDurationMs + 10));

    expect(onError).toHaveBeenCalledTimes(1);
  });
});
