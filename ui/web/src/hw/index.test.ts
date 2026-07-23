import { describe, test, expect, vi, beforeEach } from "vitest";
import type { HardwareSigner } from "./types";

// Mock the concrete connectors so the factory can be exercised without opening
// WebHID or loading connect.trezor.io.
const { mockConnectLedger, mockConnectTrezor } = vi.hoisted(() => ({
  mockConnectLedger: vi.fn(),
  mockConnectTrezor: vi.fn(),
}));

vi.mock("./ledger", () => ({ connectLedger: mockConnectLedger }));
vi.mock("./trezor", () => ({ connectTrezor: mockConnectTrezor }));

import { connectDevice, connectHardware } from "./index";

const fakeLedger = { kind: "ledger" } as unknown as HardwareSigner;
const fakeTrezor = { kind: "trezor" } as unknown as HardwareSigner;

beforeEach(() => {
  vi.clearAllMocks();
  mockConnectLedger.mockResolvedValue(fakeLedger);
  mockConnectTrezor.mockResolvedValue(fakeTrezor);
});

describe("connectDevice factory", () => {
  test("ledger dispatches to connectLedger and takes no consent options", async () => {
    const session = await connectDevice("ledger");
    expect(mockConnectLedger).toHaveBeenCalledOnce();
    expect(mockConnectTrezor).not.toHaveBeenCalled();
    expect(session).toBe(fakeLedger);
  });

  test("trezor dispatches to connectTrezor, forwarding the consent options", async () => {
    const requestExternalConsent = async () => true;
    const session = await connectDevice("trezor", { requestExternalConsent });
    expect(mockConnectTrezor).toHaveBeenCalledWith({ requestExternalConsent });
    expect(mockConnectLedger).not.toHaveBeenCalled();
    expect(session).toBe(fakeTrezor);
  });

  test("keystone is not supported and throws", () => {
    expect(() => connectDevice("keystone")).toThrow(/not yet supported/i);
  });
});

describe("connectDevice option discrimination (compile-time)", () => {
  test("options are tied to the device kind", async () => {
    // Ledger is a LOCAL device: it must NOT accept a cloud-consent callback.
    // @ts-expect-error requestExternalConsent is forbidden for a local device
    await connectDevice("ledger", { requestExternalConsent: async () => true });

    // Trezor is EXTERNAL: the consent options are REQUIRED, not optional.
    // @ts-expect-error ExternalConnectOptions is mandatory for Trezor
    await connectDevice("trezor");

    // A well-typed call for each kind compiles cleanly.
    await connectDevice("ledger");
    await connectDevice("trezor", { requestExternalConsent: async () => true });
  });
});

describe("connectHardware (dynamic kind)", () => {
  test("ledger ignores the consent callback", async () => {
    const consent = vi.fn().mockResolvedValue(true);
    await connectHardware("ledger", consent);
    expect(mockConnectLedger).toHaveBeenCalledOnce();
    expect(mockConnectTrezor).not.toHaveBeenCalled();
    // The consent callback is not consulted for a local device.
    expect(consent).not.toHaveBeenCalled();
  });

  test("trezor wires the consent callback through as ExternalConnectOptions", async () => {
    const consent = async () => true;
    await connectHardware("trezor", consent);
    expect(mockConnectTrezor).toHaveBeenCalledWith({ requestExternalConsent: consent });
    expect(mockConnectLedger).not.toHaveBeenCalled();
  });

  test("keystone throws (unsupported this phase)", () => {
    expect(() => connectHardware("keystone", async () => true)).toThrow(/not yet supported/i);
  });
});
