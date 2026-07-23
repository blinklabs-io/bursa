import { describe, test, expect, vi, beforeEach } from "vitest";
import {
  CardanoSignature,
  CryptoMultiAccounts,
  CryptoHDKey,
  CryptoKeypath,
  PathComponent,
  Buffer as URBuffer,
} from "@keystonehq/bc-ur-registry-cardano";

// The @keystonehq CBOR libraries decode against the GLOBAL Buffer, but construct
// with the `buffer`-package Buffer. Under Node those two are different classes,
// so Buffer.isBuffer() rejects the constructed input ("Unsupported input
// format"). Align the global with the package Buffer — exactly what
// keystone.ts's ensureBuffer() does in the browser, where no global exists.
(globalThis as unknown as { Buffer: unknown }).Buffer = URBuffer;

// ── USB transport + app mocks (no real WebUSB in CI) ──────────────────────────
const { mockRequestPermission, mockConnect, mockClose, mockGetAppConfig, mockGetXpubs, mockSignTx } =
  vi.hoisted(() => ({
    mockRequestPermission: vi.fn().mockResolvedValue(undefined),
    mockConnect: vi.fn(),
    mockClose: vi.fn().mockResolvedValue(undefined),
    mockGetAppConfig: vi.fn(),
    mockGetXpubs: vi.fn(),
    mockSignTx: vi.fn(),
  }));

vi.mock("@keystonehq/hw-transport-webusb", () => ({
  TransportWebUSB: {
    requestPermission: mockRequestPermission,
    connect: mockConnect,
  },
}));

vi.mock("@keystonehq/hw-app-ada", () => ({
  // The neutral→SDK mapping references these enums; concrete values are
  // irrelevant to the witness parity we assert, so stand-ins suffice.
  default: vi.fn().mockImplementation(() => ({
    getAppConfig: mockGetAppConfig,
    getExtendedPublicKeys: mockGetXpubs,
    signTransaction: mockSignTx,
  })),
  AddressType: { BASE_PAYMENT_KEY_STAKE_KEY: 0 },
  TransactionSigningMode: { ORDINARY_TRANSACTION: "ordinary_transaction" },
  TxOutputDestinationType: { DEVICE_OWNED: "device_owned", THIRD_PARTY: "third_party" },
  TxOutputFormat: { ARRAY_LEGACY: 0 },
  TxRequiredSignerType: { HASH: "required_signer_hash" },
}));

import { connectKeystoneQR, connectKeystoneUSB, witnessSetToPairs, parseAccountSyncUR } from "./keystone";
import { encodeXpub } from "./xpub";
import { encodeWitnessArray } from "./witness";
import type { KeystoneQRBridge } from "./types";
import type { HardwareSignResponse } from "../api/types";

// Shared parity vector — identical key material to the Ledger/Trezor canonical
// vectors, so every device MUST produce the same bech32 xpub and, for the same
// pubkey/sig, the same witness-array CBOR.
const TEST_PUB_KEY_HEX = "beb7e770b3d0f1932b0a2f3a63285bf9ef7d3e461d55446d6a3911d8f0ee55c0";
const TEST_CHAIN_CODE_HEX = "b0e2df16538508046649d0e6d5b32969555a23f2f1ebf2db2819359b0d88bd16";
const TEST_XPUB_BECH32 =
  "root_xvk1h6m7wu9n6rcex2c29uaxx2zml8hh60jxr425gmt28yga3u8w2hqtpcklzefc2zqyveyapek4kv5kj426y0e0r6ljmv5pjdvmpkyt69s8fpd2x";
const TEST_SIG_HEX = "aabbccdd".repeat(16); // 64 bytes

const HARDENED = 0x80000000;
const ACCT0_PATH = [1852 + HARDENED, 1815 + HARDENED, 0 + HARDENED];

const NEUTRAL_REQ: HardwareSignResponse = {
  network: "mainnet",
  network_id: 1,
  include_network_id: true,
  protocol_magic: 764824073,
  inputs: [{ tx_hash_hex: "deadbeef".repeat(8), output_index: 0, path: "1852'/1815'/0'/0/0" }],
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
  required_signers: [],
  unsigned_tx_cbor: "84a4008182",
};

// ── Helpers to build the URs the device would show ────────────────────────────

// The registry's Buffer (from the `buffer` package) differs from @types/node's
// Buffer in TS though they are identical at runtime; bridge with a cast.
const buf = (hex: string): Buffer => URBuffer.from(hex, "hex") as unknown as Buffer;

// A crypto-multi-accounts UR (the account-sync QR) carrying account 0's key.
function accountSyncCborHex(pubHex: string, ccHex: string, path: number[]): string {
  const components = [];
  const HARD = 0x80000000;
  for (const n of path) {
    const hardened = n >= HARD;
    components.push(new PathComponent({ index: hardened ? n - HARD : n, hardened }));
  }
  const origin = new CryptoKeypath(components);
  const hd = new CryptoHDKey({
    isMaster: false,
    key: buf(pubHex),
    chainCode: buf(ccHex),
    origin,
  });
  const ma = new CryptoMultiAccounts(buf("52744703"), [hd], "Keystone");
  return Buffer.from(ma.toUR().cbor).toString("hex");
}

// A serialized TransactionWitnessSet: map {0: [[pubkey, sig]]}.
function witnessSetHex(pubHex: string, sigHex: string): string {
  return "a10081" + "82" + "5820" + pubHex + "5840" + sigHex;
}

// A cardano-signature UR wrapping the witness set.
function signatureCborHex(pubHex: string, sigHex: string): string {
  const sig = new CardanoSignature(buf(witnessSetHex(pubHex, sigHex)));
  return Buffer.from(sig.toUR().cbor).toString("hex");
}

function makeBridge(): KeystoneQRBridge & {
  displayRequest: ReturnType<typeof vi.fn>;
  scanResponse: ReturnType<typeof vi.fn>;
  close: ReturnType<typeof vi.fn>;
} {
  return {
    displayRequest: vi.fn(),
    scanResponse: vi.fn(),
    close: vi.fn(),
  };
}

// ── QR transport ──────────────────────────────────────────────────────────────

describe("connectKeystoneQR", () => {
  test("reports kind 'keystone' and QR capabilities (send + simple staking only)", async () => {
    const session = await connectKeystoneQR({ transport: "qr", bridge: makeBridge() });
    expect(session.kind).toBe("keystone");
    expect(session.capabilities).toEqual({
      send: true,
      staking: true,
      governance: false,
      multisig: false,
      poolReg: false,
    });
  });

  test("getAccountXpub extracts the account key from the account-sync UR and matches the shared vector", async () => {
    const bridge = makeBridge();
    bridge.scanResponse.mockResolvedValue({
      type: "crypto-multi-accounts",
      cborHex: accountSyncCborHex(TEST_PUB_KEY_HEX, TEST_CHAIN_CODE_HEX, ACCT0_PATH),
    });
    const session = await connectKeystoneQR({ transport: "qr", bridge });
    const xpub = await session.getAccountXpub(0);
    // Byte-for-byte identical to the Ledger/Trezor/Go xpub for the same key.
    expect(xpub).toBe(TEST_XPUB_BECH32);
    expect(bridge.close).toHaveBeenCalled();
  });

  test("getAccountXpub rejects a non-account-sync UR", async () => {
    const bridge = makeBridge();
    bridge.scanResponse.mockResolvedValue({
      type: "cardano-signature",
      cborHex: signatureCborHex(TEST_PUB_KEY_HEX, TEST_SIG_HEX),
    });
    const session = await connectKeystoneQR({ transport: "qr", bridge });
    await expect(session.getAccountXpub(0)).rejects.toThrow(/account-sync/i);
  });

  test("signTx round-trips: shows the request QR, scans the signature, returns the witness-array CBOR", async () => {
    const bridge = makeBridge();
    bridge.scanResponse.mockResolvedValue({
      type: "cardano-signature",
      cborHex: signatureCborHex(TEST_PUB_KEY_HEX, TEST_SIG_HEX),
    });
    const session = await connectKeystoneQR({ transport: "qr", bridge, xfp: "52744703" });

    const result = await session.signTx(NEUTRAL_REQ);

    // The animated request QR was displayed with at least one UR fragment.
    expect(bridge.displayRequest).toHaveBeenCalledOnce();
    const fragments = bridge.displayRequest.mock.calls[0][0] as string[];
    expect(fragments.length).toBeGreaterThan(0);
    expect(fragments[0].toLowerCase()).toMatch(/^ur:cardano-sign-request\//);

    // The assembled witness array is byte-identical to what the shared encoder
    // produces for the same pubkey/sig — i.e. identical to Ledger/Trezor output.
    expect(result).toBe(
      encodeWitnessArray([{ pubKeyHex: TEST_PUB_KEY_HEX, sigHex: TEST_SIG_HEX }]),
    );
    expect(result.startsWith("8182")).toBe(true);
    expect(result).toContain(TEST_PUB_KEY_HEX);
    expect(result).toContain(TEST_SIG_HEX);
    expect(bridge.close).toHaveBeenCalled();
  });

  test("signTx rejects a scanned UR that is not a signature", async () => {
    const bridge = makeBridge();
    bridge.scanResponse.mockResolvedValue({
      type: "crypto-multi-accounts",
      cborHex: accountSyncCborHex(TEST_PUB_KEY_HEX, TEST_CHAIN_CODE_HEX, ACCT0_PATH),
    });
    const session = await connectKeystoneQR({ transport: "qr", bridge });
    await expect(session.signTx(NEUTRAL_REQ)).rejects.toThrow(/cardano-signature/i);
    expect(bridge.close).toHaveBeenCalled();
  });

  test("is fully local: no consent callback is part of the options or invoked", async () => {
    // KeystoneConnectOptions carries NO consent field (unlike Trezor's). This
    // test documents that the whole QR flow connects and signs with only a
    // transport + bridge — there is nothing to gate on external consent.
    const bridge = makeBridge();
    bridge.scanResponse.mockResolvedValue({
      type: "cardano-signature",
      cborHex: signatureCborHex(TEST_PUB_KEY_HEX, TEST_SIG_HEX),
    });
    const opts = { transport: "qr" as const, bridge };
    expect("requestExternalConsent" in opts).toBe(false);
    const session = await connectKeystoneQR(opts);
    await expect(session.signTx(NEUTRAL_REQ)).resolves.toBeTypeOf("string");
  });
});

// ── witnessSetToPairs (shared decoder) ────────────────────────────────────────

describe("witnessSetToPairs", () => {
  test("extracts [pubkey, sig] pairs from a witness-set map (key 0)", () => {
    const bytes = Uint8Array.from(Buffer.from(witnessSetHex(TEST_PUB_KEY_HEX, TEST_SIG_HEX), "hex"));
    expect(witnessSetToPairs(bytes)).toEqual([
      { pubKeyHex: TEST_PUB_KEY_HEX, sigHex: TEST_SIG_HEX },
    ]);
  });

  test("trims an extended (pubkey||chaincode) vkey down to the 32-byte public key", () => {
    // 64-byte vkey: pubkey (32) || chaincode (32). Only the pubkey belongs in a
    // Cardano vkey witness, so parity with the other devices is preserved.
    const extended = TEST_PUB_KEY_HEX + TEST_CHAIN_CODE_HEX;
    const hex = "a10081" + "82" + "5840" + extended + "5840" + TEST_SIG_HEX;
    const bytes = Uint8Array.from(Buffer.from(hex, "hex"));
    expect(witnessSetToPairs(bytes)).toEqual([
      { pubKeyHex: TEST_PUB_KEY_HEX, sigHex: TEST_SIG_HEX },
    ]);
  });

  test("accepts the Conway set-tagged witness array (tag 258)", () => {
    // map {0: 258([[pub,sig]])} — the tag wraps the array; the decoder unwraps it.
    const hex = "a100" + "d90102" + "81" + "82" + "5820" + TEST_PUB_KEY_HEX + "5840" + TEST_SIG_HEX;
    const bytes = Uint8Array.from(Buffer.from(hex, "hex"));
    expect(witnessSetToPairs(bytes)).toEqual([
      { pubKeyHex: TEST_PUB_KEY_HEX, sigHex: TEST_SIG_HEX },
    ]);
  });
});

describe("parseAccountSyncUR", () => {
  test("returns the account xpub + master fingerprint for the requested account", async () => {
    const sync = await parseAccountSyncUR(
      {
        type: "crypto-multi-accounts",
        cborHex: accountSyncCborHex(TEST_PUB_KEY_HEX, TEST_CHAIN_CODE_HEX, ACCT0_PATH),
      },
      0,
    );
    expect(sync.xpub).toBe(TEST_XPUB_BECH32);
    expect(sync.xfp).toBe("52744703");
    expect(sync.account).toBe(0);
  });

  test("rejects when the requested account is absent from the sync UR", async () => {
    await expect(
      parseAccountSyncUR(
        {
          type: "crypto-multi-accounts",
          cborHex: accountSyncCborHex(TEST_PUB_KEY_HEX, TEST_CHAIN_CODE_HEX, ACCT0_PATH),
        },
        5,
      ),
    ).rejects.toThrow(/does not contain account 5/i);
  });
});

// ── USB transport ─────────────────────────────────────────────────────────────

function setWebUSB(available: boolean) {
  Object.defineProperty(globalThis.navigator ?? (globalThis.navigator = {} as Navigator), "usb", {
    value: available ? {} : undefined,
    configurable: true,
    writable: true,
  });
}

describe("connectKeystoneUSB", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    setWebUSB(true);
    const transport = { close: mockClose };
    mockConnect.mockResolvedValue(transport);
    mockGetAppConfig.mockResolvedValue({ version: "1.0.0", mfp: "52744703" });
    mockGetXpubs.mockResolvedValue([
      { publicKeyHex: TEST_PUB_KEY_HEX, chainCodeHex: TEST_CHAIN_CODE_HEX },
    ]);
    mockSignTx.mockResolvedValue({
      txHashHex: "cafebabe",
      witnesses: [{ path: ACCT0_PATH, witnessSignatureHex: TEST_SIG_HEX }],
      auxiliaryDataSupplement: null,
    });
  });

  test("throws a clear error when WebUSB is unavailable", async () => {
    setWebUSB(false);
    await expect(connectKeystoneUSB()).rejects.toThrow(/WebUSB not available/i);
  });

  test("reports kind 'keystone' and conservative USB capabilities (send only)", async () => {
    const session = await connectKeystoneUSB();
    expect(session.kind).toBe("keystone");
    expect(session.capabilities).toEqual({
      send: true,
      staking: false,
      governance: false,
      multisig: false,
      poolReg: false,
    });
    await session.close();
    expect(mockClose).toHaveBeenCalledOnce();
  });

  test("requests permission before connecting (needs live user activation)", async () => {
    await connectKeystoneUSB();
    expect(mockRequestPermission).toHaveBeenCalledOnce();
    expect(mockConnect).toHaveBeenCalledOnce();
    expect(mockRequestPermission.mock.invocationCallOrder[0]).toBeLessThan(
      mockConnect.mock.invocationCallOrder[0],
    );
  });

  test("getAccountXpub reads the account key and matches the shared vector", async () => {
    const session = await connectKeystoneUSB();
    const xpub = await session.getAccountXpub(0);
    expect(mockGetXpubs).toHaveBeenCalledWith({ paths: [ACCT0_PATH] });
    expect(xpub).toBe(TEST_XPUB_BECH32);
  });

  test("signTx returns a witness array identical to the shared encoder output", async () => {
    const session = await connectKeystoneUSB();
    const result = await session.signTx(NEUTRAL_REQ);
    expect(mockSignTx).toHaveBeenCalledOnce();
    expect(result).toBe(
      encodeWitnessArray([{ pubKeyHex: TEST_PUB_KEY_HEX, sigHex: TEST_SIG_HEX }]),
    );
    expect(result.startsWith("8182")).toBe(true);
  });
});

// A sanity check that the shared encoder is the SAME one every device uses:
// re-encoding the parity key here must equal the canonical Ledger/Trezor xpub.
test("shared xpub encoder parity guard", () => {
  expect(encodeXpub(TEST_PUB_KEY_HEX, TEST_CHAIN_CODE_HEX)).toBe(TEST_XPUB_BECH32);
});
