import { describe, test, expect, vi, beforeEach } from "vitest";

// ── Hoisted mock state (declared before the vi.mock factory runs) ─────────────
const { mockInit, mockGetPublicKey, mockSignTransaction, mockDispose } = vi.hoisted(() => ({
  mockInit: vi.fn().mockResolvedValue(undefined),
  mockGetPublicKey: vi.fn(),
  mockSignTransaction: vi.fn(),
  mockDispose: vi.fn(),
}));

// Fully mock @trezor/connect-web — no real network, iframe, or popup is loaded.
// trezor.ts imports this dynamically, but vi.mock still intercepts the import.
vi.mock("@trezor/connect-web", () => ({
  default: {
    init: mockInit,
    cardanoGetPublicKey: mockGetPublicKey,
    cardanoSignTransaction: mockSignTransaction,
    dispose: mockDispose,
  },
  PROTO: {
    CardanoTxSigningMode: { ORDINARY_TRANSACTION: 0 },
    CardanoAddressType: { BASE: 0 },
  },
}));

import { connectTrezor } from "./trezor";
import type { ExternalConnectOptions } from "./types";
import type { HardwareSignResponse } from "../api/types";

// Xpub parity vector — identical key material to the Ledger canonical vector
// (see ledger.test.ts) so both devices MUST produce the same bech32 string.
const TEST_PUB_KEY_HEX = "beb7e770b3d0f1932b0a2f3a63285bf9ef7d3e461d55446d6a3911d8f0ee55c0";
const TEST_CHAIN_CODE_HEX = "b0e2df16538508046649d0e6d5b32969555a23f2f1ebf2db2819359b0d88bd16";
const TEST_XPUB_BECH32 =
  "root_xvk1h6m7wu9n6rcex2c29uaxx2zml8hh60jxr425gmt28yga3u8w2hqtpcklzefc2zqyveyapek4kv5kj426y0e0r6ljmv5pjdvmpkyt69s8fpd2x";

const HARDENED = 0x80000000;
const ACCT0_PATH = [1852 + HARDENED, 1815 + HARDENED, 0 + HARDENED];

const NEUTRAL_REQ: HardwareSignResponse = {
  network: "mainnet",
  network_id: 1,
  include_network_id: true,
  protocol_magic: 764824073,
  inputs: [{ tx_hash_hex: "deadbeef", output_index: 0, path: "1852'/1815'/0'/0/0" }],
  outputs: [
    { address_hex: "60aabb", address_bech32: "addr1recipient", lovelace: "1000000" },
    {
      address_hex: "60ccdd",
      address_bech32: "addr1change",
      lovelace: "3800000",
      payment_path: "1852'/1815'/0'/0/0",
      stake_path: "1852'/1815'/0'/2/0",
    },
  ],
  fee: "200000",
  required_signers: ["aabbccdd"],
  unsigned_tx_cbor: "84a4deadbeef",
};

// Always-approve consent callback for the tests that exercise past the gate.
const approve = async () => true;

beforeEach(() => {
  vi.clearAllMocks();
  mockInit.mockResolvedValue(undefined);
  mockGetPublicKey.mockResolvedValue({
    success: true,
    payload: { node: { public_key: TEST_PUB_KEY_HEX, chain_code: TEST_CHAIN_CODE_HEX } },
  });
  mockSignTransaction.mockResolvedValue({
    success: true,
    payload: {
      hash: "cafebabe",
      witnesses: [{ type: 1, pubKey: TEST_PUB_KEY_HEX, signature: "aabbccdd".repeat(16) }],
    },
  });
});

describe("connectTrezor consent gate", () => {
  test("does NOT init when consent is denied, and throws", async () => {
    await expect(connectTrezor({ requestExternalConsent: async () => false })).rejects.toThrow(
      /connect\.trezor\.io/i,
    );
    expect(mockInit).not.toHaveBeenCalled();
  });

  test("does NOT init when no consent callback is provided", async () => {
    // The consent callback is mandatory for this external connector; an options
    // object without it (an untyped/legacy caller) must be rejected, not
    // treated as implicit approval. Cast bypasses the compile-time requirement
    // to exercise the runtime guard.
    await expect(connectTrezor({} as ExternalConnectOptions)).rejects.toThrow(
      /connect\.trezor\.io/i,
    );
    expect(mockInit).not.toHaveBeenCalled();
  });

  test("init is not called until approval resolves", async () => {
    let resolveConsent: (ok: boolean) => void = () => {};
    const consent = new Promise<boolean>((resolve) => {
      resolveConsent = resolve;
    });

    const pending = connectTrezor({ requestExternalConsent: () => consent });

    // Approval still pending → the external iframe must not have been loaded.
    await Promise.resolve();
    expect(mockInit).not.toHaveBeenCalled();

    resolveConsent(true);
    const session = await pending;

    expect(mockInit).toHaveBeenCalledOnce();
    // init carries the manifest + lazyLoad settings.
    expect(mockInit).toHaveBeenCalledWith(
      expect.objectContaining({
        manifest: expect.objectContaining({ email: expect.any(String), appUrl: expect.any(String) }),
        lazyLoad: true,
      }),
    );
    await session.close();
  });
});

describe("connectTrezor session", () => {
  test("reports kind 'trezor' and send-only capabilities", async () => {
    const session = await connectTrezor({ requestExternalConsent: approve });
    expect(session.kind).toBe("trezor");
    expect(session.capabilities).toEqual({
      send: true,
      staking: false,
      governance: false,
      multisig: false,
      poolReg: false,
    });
    await session.close();
  });

  test("getAccountXpub produces the SAME bech32 as the Ledger parity vector", async () => {
    const session = await connectTrezor({ requestExternalConsent: approve });
    const xpub = await session.getAccountXpub(0);

    expect(mockGetPublicKey).toHaveBeenCalledWith({ path: ACCT0_PATH, showOnTrezor: false });
    // Byte-for-byte identical to Ledger/Go for the same key material.
    expect(xpub).toBe(TEST_XPUB_BECH32);
    await session.close();
  });

  test("getAccountXpub throws on an unsuccessful device response", async () => {
    mockGetPublicKey.mockResolvedValueOnce({ success: false, payload: { error: "device disconnected" } });
    const session = await connectTrezor({ requestExternalConsent: approve });
    await expect(session.getAccountXpub(0)).rejects.toThrow("device disconnected");
    await session.close();
  });

  test("signTx maps the neutral request to ORDINARY Trezor params and returns witness CBOR", async () => {
    const session = await connectTrezor({ requestExternalConsent: approve });
    const result = await session.signTx(NEUTRAL_REQ);

    expect(mockSignTransaction).toHaveBeenCalledOnce();
    const params = mockSignTransaction.mock.calls[0][0];

    expect(params.signingMode).toBe(0); // ORDINARY_TRANSACTION
    expect(params.protocolMagic).toBe(764824073);
    expect(params.networkId).toBe(1);
    expect(params.includeNetworkId).toBe(true);
    expect(params.fee).toBe("200000");

    expect(params.inputs).toEqual([
      { path: [0x8000073c, 0x80000717, 0x80000000, 0, 0], prev_hash: "deadbeef", prev_index: 0 },
    ]);

    // Third-party recipient by bech32 address; wallet-owned change by path.
    expect(params.outputs[0]).toEqual({ address: "addr1recipient", amount: "1000000" });
    expect(params.outputs[1]).toEqual({
      addressParameters: {
        addressType: 0, // BASE
        path: [0x8000073c, 0x80000717, 0x80000000, 0, 0],
        stakingPath: [0x8000073c, 0x80000717, 0x80000000, 2, 0],
      },
      amount: "3800000",
    });

    // Witness CBOR carries the device's pubkey + signature.
    expect(result).toMatch(/^[0-9a-f]+$/);
    expect(result.startsWith("8182")).toBe(true);
    expect(result).toContain(TEST_PUB_KEY_HEX);
    expect(result).toContain("aabbccdd".repeat(16));
    await session.close();
  });

  test("signTx maps native assets into the token bundle grouped by policy id", async () => {
    // A recipient output carrying two assets under one policy plus one under a
    // second policy. The device MUST receive these so it signs the same tx the
    // backend built — an empty/absent bundle would drop the tokens silently.
    const MULTI_ASSET_REQ: HardwareSignResponse = {
      ...NEUTRAL_REQ,
      outputs: [
        {
          address_hex: "60aabb",
          address_bech32: "addr1recipient",
          lovelace: "1000000",
          assets: [
            { policy_id_hex: "aa".repeat(28), asset_name_hex: "544f4b454e31", amount: "5" },
            { policy_id_hex: "aa".repeat(28), asset_name_hex: "544f4b454e32", amount: "7" },
            { policy_id_hex: "bb".repeat(28), asset_name_hex: "", amount: "3" },
          ],
        },
        NEUTRAL_REQ.outputs[1], // wallet-owned change, ADA-only
      ],
    };

    const session = await connectTrezor({ requestExternalConsent: approve });
    await session.signTx(MULTI_ASSET_REQ);

    const params = mockSignTransaction.mock.calls[0][0];
    expect(params.outputs[0].tokenBundle).toEqual([
      {
        policyId: "aa".repeat(28),
        tokenAmounts: [
          { assetNameBytes: "544f4b454e31", amount: "5" },
          { assetNameBytes: "544f4b454e32", amount: "7" },
        ],
      },
      {
        policyId: "bb".repeat(28),
        tokenAmounts: [{ assetNameBytes: "", amount: "3" }],
      },
    ]);
    // The ADA-only change output carries no bundle key.
    expect(params.outputs[1].tokenBundle).toBeUndefined();
    await session.close();
  });

  test("concurrent connects share a single init()", async () => {
    // Two callers (e.g. a double-click) must not both race into init(); the
    // shared init promise means only one init() call is made.
    const [a, b] = await Promise.all([
      connectTrezor({ requestExternalConsent: approve }),
      connectTrezor({ requestExternalConsent: approve }),
    ]);
    expect(mockInit).toHaveBeenCalledOnce();
    await a.close();
    await b.close();
  });

  test("signTx throws on an unsuccessful device response", async () => {
    mockSignTransaction.mockResolvedValueOnce({ success: false, payload: { error: "user cancelled" } });
    const session = await connectTrezor({ requestExternalConsent: approve });
    await expect(session.signTx(NEUTRAL_REQ)).rejects.toThrow("user cancelled");
    await session.close();
  });

  test("close disposes the Trezor transport", async () => {
    const session = await connectTrezor({ requestExternalConsent: approve });
    await session.close();
    expect(mockDispose).toHaveBeenCalledOnce();
  });
});
