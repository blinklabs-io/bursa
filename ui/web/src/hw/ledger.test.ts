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

// Keep the real enum exports (TxOutputDestinationType, AddressType, …) that the
// neutral→ledgerjs mapping in ledger.ts references; only the Ada class is mocked.
vi.mock("@cardano-foundation/ledgerjs-hw-app-cardano", async (importOriginal) => {
  const actual = await importOriginal<typeof import("@cardano-foundation/ledgerjs-hw-app-cardano")>();
  return { ...actual, default: mockAdaConstructor, Ada: mockAdaConstructor };
});

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
import type { HardwareSignResponse } from "../api/types";

// A neutral backend signing request (device-agnostic). connectLedger's signTx
// maps this to the ledgerjs SignTransactionRequest internally; the mapping
// assertions below used to live in Send.test.tsx and moved here with the code.
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

  test("reports kind 'ledger' and send-only capabilities", async () => {
    const session = await connectLedger();
    expect(session.kind).toBe("ledger");
    expect(session.capabilities).toEqual({
      send: true,
      staking: false,
      governance: false,
      multisig: false,
      poolReg: false,
    });
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
    test("maps the neutral request to a ledgerjs SignTransactionRequest", async () => {
      const session = await connectLedger();

      await session.signTx(NEUTRAL_REQ);

      expect(mockSignTransaction).toHaveBeenCalledOnce();
      const request = mockSignTransaction.mock.calls[0][0];

      // ORDINARY signing with the network + required-signer fields carried over.
      expect(request.signingMode).toBe("ordinary_transaction");
      expect(request.tx.network).toEqual({ protocolMagic: 764824073, networkId: 1 });
      expect(request.tx.includeNetworkId).toBe(true);
      expect(request.tx.requiredSigners).toEqual([
        { type: "required_signer_hash", hashHex: "aabbccdd" },
      ]);

      // Third-party recipient by raw address hex; device-owned change by path.
      expect(request.tx.outputs[0].destination).toEqual({
        type: "third_party",
        params: { addressHex: "60aabb" },
      });
      expect(request.tx.outputs[1].destination).toEqual({
        type: "device_owned",
        params: {
          type: 0,
          params: {
            spendingPath: [0x8000073c, 0x80000717, 0x80000000, 0, 0],
            stakingPath: [0x8000073c, 0x80000717, 0x80000000, 2, 0],
          },
        },
      });
      // ledgerjs iterates tokenBundle even for ADA-only outputs.
      expect(request.tx.outputs.every((o: { tokenBundle: unknown[] }) => Array.isArray(o.tokenBundle))).toBe(
        true,
      );
      await session.close();
    });

    test("maps native assets into the ledger token bundle grouped by policy id", async () => {
      // A recipient output carrying two assets under one policy plus one under a
      // second policy. The device MUST receive these grouped so it signs the
      // same tx the backend built — an empty bundle would drop the tokens.
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

      const session = await connectLedger();
      await session.signTx(MULTI_ASSET_REQ);

      const request = mockSignTransaction.mock.calls[0][0];
      expect(request.tx.outputs[0].tokenBundle).toEqual([
        {
          policyIdHex: "aa".repeat(28),
          tokens: [
            { assetNameHex: "544f4b454e31", amount: 5n },
            { assetNameHex: "544f4b454e32", amount: 7n },
          ],
        },
        {
          policyIdHex: "bb".repeat(28),
          tokens: [{ assetNameHex: "", amount: 3n }],
        },
      ]);
      // The ADA-only change output keeps an empty bundle (ledgerjs iterates it).
      expect(request.tx.outputs[1].tokenBundle).toEqual([]);
      await session.close();
    });

    test("returns a raw CBOR witness array", async () => {
      const session = await connectLedger();
      const result = await session.signTx(NEUTRAL_REQ);
      // Result is CBOR hex: [[pubkey, sig], ...] — a non-empty hex string with
      // one outer array followed by one two-element witness tuple.
      expect(result).toMatch(/^[0-9a-f]+$/);
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

      const result = await session.signTx(NEUTRAL_REQ);

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
