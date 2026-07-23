import { describe, test, expect, vi, beforeEach, afterEach } from "vitest";

// ── Hoisted mock state (must be declared before vi.mock factories run) ────────
const {
  mockTransport,
  mockCreate,
  mockGetExtendedPublicKey,
  mockSignTransaction,
  mockAdaConstructor,
} = vi.hoisted(() => {
  const mockTransport = { close: vi.fn().mockResolvedValue(undefined) };
  const mockCreate = vi.fn().mockResolvedValue(mockTransport);

  const HARDENED = 0x80000000;
  const ACCT0_PATH = [1852 + HARDENED, 1815 + HARDENED, 0 + HARDENED];

  const mockGetExtendedPublicKey = vi.fn().mockResolvedValue({
    publicKeyHex: "beb7e770b3d0f1932b0a2f3a63285bf9ef7d3e461d55446d6a3911d8f0ee55c0",
    chainCodeHex: "b0e2df16538508046649d0e6d5b32969555a23f2f1ebf2db2819359b0d88bd16",
  });

  const mockSignTransaction = vi.fn().mockResolvedValue({
    txHashHex: "cafebabe01020304",
    witnesses: [{ path: ACCT0_PATH, witnessSignatureHex: "aabbccdd".repeat(16) }],
    auxiliaryDataSupplement: null,
  });

  const mockAdaInstance = {
    getExtendedPublicKey: mockGetExtendedPublicKey,
    signTransaction: mockSignTransaction,
  };
  const mockAdaConstructor = vi.fn().mockImplementation(() => mockAdaInstance);

  return { mockTransport, mockCreate, mockGetExtendedPublicKey, mockSignTransaction, mockAdaConstructor };
});

// ── Module mocks ──────────────────────────────────────────────────────────────
vi.mock("@ledgerhq/hw-transport-webhid", () => ({
  default: { create: mockCreate },
}));

vi.mock("@cardano-foundation/ledgerjs-hw-app-cardano", () => ({
  default: mockAdaConstructor,
  Ada: mockAdaConstructor,
}));

// ── Test constants ────────────────────────────────────────────────────────────
//
// Test vector derived from the Go side for mnemonic:
//   "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
// Go: wallet.AccountXpub(mnemonic) at account index 0 (m/1852'/1815'/0')
//
//   publicKey  (32 bytes, hex): beb7e770b3d0f1932b0a2f3a63285bf9ef7d3e461d55446d6a3911d8f0ee55c0
//   chainCode  (32 bytes, hex): b0e2df16538508046649d0e6d5b32969555a23f2f1ebf2db2819359b0d88bd16
//   bech32 xpub (HRP=root_xvk): root_xvk1h6m7wu9n6rcex2c29uaxx2zml8hh60jxr425gmt28yga3u8w2hqtpcklzefc2zqyveyapek4kv5kj426y0e0r6ljmv5pjdvmpkyt69s8fpd2x
//
// Verified: Go bip32.XPub.String() produces the identical encoding from the
// same 64-byte payload (pubkey || chainCode) using bech32 with HRP "root_xvk".
const TEST_PUB_KEY_HEX = "beb7e770b3d0f1932b0a2f3a63285bf9ef7d3e461d55446d6a3911d8f0ee55c0";
const TEST_CHAIN_CODE_HEX = "b0e2df16538508046649d0e6d5b32969555a23f2f1ebf2db2819359b0d88bd16";
const TEST_XPUB_BECH32 =
  "root_xvk1h6m7wu9n6rcex2c29uaxx2zml8hh60jxr425gmt28yga3u8w2hqtpcklzefc2zqyveyapek4kv5kj426y0e0r6ljmv5pjdvmpkyt69s8fpd2x";

const HARDENED = 0x80000000;
// m/1852'/1815'/0'
const ACCT0_PATH = [1852 + HARDENED, 1815 + HARDENED, 0 + HARDENED];

// Mock witness data: one witness with a known pubkey+sig pair
// Raw CBOR vkey-witness array: [[pubkey32, sig64], ...]
// Using 32-byte pubkey and 64-byte sig for test
const MOCK_WITNESS_PUB_HEX = TEST_PUB_KEY_HEX;
const MOCK_WITNESS_SIG_HEX = "aabbccdd".repeat(16); // 64 bytes

// ── Import SUT after mocks ────────────────────────────────────────────────────
import { connectLedger } from "./ledger";
import type { SignTransactionRequest } from "@cardano-foundation/ledgerjs-hw-app-cardano";

// ── Helpers ───────────────────────────────────────────────────────────────────
function setWebHID(available: boolean) {
  Object.defineProperty(globalThis.navigator ?? (globalThis.navigator = {} as Navigator), "hid", {
    value: available ? {} : undefined,
    configurable: true,
    writable: true,
  });
}

describe("connectLedger", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mockCreate.mockResolvedValue(mockTransport);
    mockGetExtendedPublicKey.mockResolvedValue({
      publicKeyHex: TEST_PUB_KEY_HEX,
      chainCodeHex: TEST_CHAIN_CODE_HEX,
    });
    mockSignTransaction.mockResolvedValue({
      txHashHex: "cafebabe01020304",
      witnesses: [{ path: ACCT0_PATH, witnessSignatureHex: MOCK_WITNESS_SIG_HEX }],
      auxiliaryDataSupplement: null,
    });
    mockTransport.close.mockResolvedValue(undefined);
    // mockAdaConstructor still returns the hoisted mockAdaInstance with the
    // now-cleared fns; restore default mock returns set above via the fns.
    mockAdaConstructor.mockImplementation(() => ({
      getExtendedPublicKey: mockGetExtendedPublicKey,
      signTransaction: mockSignTransaction,
    }));
    setWebHID(true);
  });

  afterEach(() => {
    setWebHID(false);
  });

  test("throws clear error when navigator.hid is undefined", async () => {
    setWebHID(false);
    await expect(connectLedger()).rejects.toThrow(
      "WebHID not available — open this in a Chromium browser",
    );
  });

  test("calls TransportWebHID.create() and constructs Ada app", async () => {
    const session = await connectLedger();
    expect(mockCreate).toHaveBeenCalledOnce();
    expect(mockAdaConstructor).toHaveBeenCalledWith(mockTransport);
    await session.close();
  });

  describe("getAccountXpub", () => {
    test("calls getExtendedPublicKey with correct CIP-1852 path for account 0", async () => {
      const session = await connectLedger();
      await session.getAccountXpub(0);
      expect(mockGetExtendedPublicKey).toHaveBeenCalledWith({ path: ACCT0_PATH });
      await session.close();
    });

    test("calls getExtendedPublicKey with correct path for account 2", async () => {
      const session = await connectLedger();
      await session.getAccountXpub(2);
      expect(mockGetExtendedPublicKey).toHaveBeenCalledWith({
        path: [1852 + HARDENED, 1815 + HARDENED, 2 + HARDENED],
      });
      await session.close();
    });

    test("returns parity-correct bech32 xpub matching Go canonical vector", async () => {
      // This is the KEY PARITY TEST.
      // The mock returns the raw {publicKeyHex, chainCodeHex} that the Ledger
      // device would return for the test mnemonic account 0.
      // getAccountXpub MUST produce the IDENTICAL bech32 that Go's
      // bip32.XPub.String() / wallet.AccountXpub() produces.
      const session = await connectLedger();
      const xpub = await session.getAccountXpub(0);
      expect(xpub).toBe(TEST_XPUB_BECH32);
      await session.close();
    });
  });

  describe("signTx", () => {
    test("calls signTransaction with the request and returns a raw CBOR witness array", async () => {
      const session = await connectLedger();

      const txReq: SignTransactionRequest = {
        tx: {
          network: { protocolMagic: 764824073, networkId: 1 },
          inputs: [],
          outputs: [],
          fee: 200000,
        },
        signingMode: "ordinary_transaction" as const,
      } as SignTransactionRequest;

      const result = await session.signTx(txReq);

      expect(mockSignTransaction).toHaveBeenCalledOnce();
      // The request object must be passed through to the device unchanged.
      expect(mockSignTransaction).toHaveBeenCalledWith(txReq);
      // Result is CBOR hex: [[pubkey, sig], ...]
      // Must be a non-empty hex string
      expect(result).toMatch(/^[0-9a-f]+$/);
      // One outer witness array followed by one two-element witness tuple.
      expect(result.startsWith("8182")).toBe(true);
      await session.close();
    });

    test("witness CBOR contains the pubkey and signature bytes from the device", async () => {
      const session = await connectLedger();

      // Prime getExtendedPublicKey to return our test pubkey for the signing path
      mockGetExtendedPublicKey.mockResolvedValue({
        publicKeyHex: MOCK_WITNESS_PUB_HEX,
        chainCodeHex: TEST_CHAIN_CODE_HEX,
      });

      const txReq: SignTransactionRequest = {
        tx: {
          network: { protocolMagic: 764824073, networkId: 1 },
          inputs: [],
          outputs: [],
          fee: 200000,
        },
        signingMode: "ordinary_transaction" as const,
      } as SignTransactionRequest;

      const result = await session.signTx(txReq);

      // The CBOR hex must contain both the pubkey and the sig as substrings
      expect(result).toContain(MOCK_WITNESS_PUB_HEX);
      expect(result).toContain(MOCK_WITNESS_SIG_HEX);
      await session.close();
    });
  });

  describe("close", () => {
    test("close() calls transport.close()", async () => {
      const session = await connectLedger();
      await session.close();
      expect(mockTransport.close).toHaveBeenCalledOnce();
    });
  });
});
