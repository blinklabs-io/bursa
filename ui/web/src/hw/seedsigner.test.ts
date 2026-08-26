import { describe, test, expect, vi } from "vitest";
import {
  connectSeedSigner,
  encodeAccountRequest,
  encodeTxSigRequest,
  buildExtraSigners,
  parseAccountResponse,
  parseAccountXfp,
  parseTxSigResponse,
  importSeedSignerAccount,
  recoverSeedSignerXfp,
} from "./seedsigner";
import { encodeXpub } from "./xpub";
import { encodeWitnessArray } from "./witness";
import { encodeCbor } from "./qr/cbor";
import { bytesToHex, hexToBytes } from "./hex";
import type { SeedSignerQRBridge, SeedSignerScannedUR } from "./types";
import type { HardwareSignResponse } from "../api/types";

// connectSeedSigner generates its own request id internally (not observable from
// outside); pin it to "id" so it matches the fixed request id ("id") every
// fixture below stamps on its reply, without reaching into crypto.randomUUID.
vi.mock("./requestId", async (importOriginal) => {
  const actual = await importOriginal<typeof import("./requestId")>();
  return { ...actual, newRequestId: () => "id" };
});

// Shared parity vector — identical key material to the Ledger/Trezor/Keystone
// canonical vectors, so SeedSigner MUST produce the same bech32 xpub and, for the
// same pubkey/sig, the same witness-array CBOR.
const TEST_PUB_KEY_HEX = "beb7e770b3d0f1932b0a2f3a63285bf9ef7d3e461d55446d6a3911d8f0ee55c0";
const TEST_CHAIN_CODE_HEX = "b0e2df16538508046649d0e6d5b32969555a23f2f1ebf2db2819359b0d88bd16";
const TEST_XPUB_BECH32 =
  "root_xvk1h6m7wu9n6rcex2c29uaxx2zml8hh60jxr425gmt28yga3u8w2hqtpcklzefc2zqyveyapek4kv5kj426y0e0r6ljmv5pjdvmpkyt69s8fpd2x";
const TEST_SIG_HEX = "aabbccdd".repeat(16); // 64 bytes
const TEST_XFP = "52744703";

const NEUTRAL_REQ: HardwareSignResponse = {
  network: "mainnet",
  network_id: 1,
  include_network_id: true,
  protocol_magic: 764824073,
  inputs: [
    {
      tx_hash_hex: "deadbeef".repeat(8),
      output_index: 0,
      path: "1852'/1815'/0'/0/0",
      lovelace: "5000000",
      address_bech32: "addr1input",
    },
  ],
  outputs: [{ address_hex: "60aabb", address_bech32: "addr1recipient", lovelace: "1000000" }],
  change_outputs: [{ index: 1, path: "1852'/1815'/0'/1/0" }],
  fee: "200000",
  required_signers: [],
  unsigned_tx_cbor: "84a4008182",
};

// ── UR fixture builders (what the device would show) ──────────────────────────

const ht = (s: string): string => bytesToHex([...new TextEncoder().encode(s)]);

// CBOR text-string encoding for a short (<24-byte) string: a single-byte
// major-type-3 header (0x60 + length) followed by the UTF-8 bytes.
function cborTextHex(s: string): string {
  const len = new TextEncoder().encode(s).length;
  if (len >= 24) throw new Error("cborTextHex: string too long for a single-byte header");
  return (0x60 + len).toString(16).padStart(2, "0") + ht(s);
}

// A `cardano-account` reply carrying one account record + the master fingerprint.
// `requestId` defaults to "id" — the fixed id every connectSeedSigner call in
// this file sends (newRequestId is mocked above) — so callers only need to
// override it to build a stale/mismatched-id fixture.
function accountCborHex(
  account: number,
  pubHex: string,
  ccHex: string,
  xfpHex: string,
  label = "SeedSigner",
  requestId = "id",
): string {
  const rec = new Map<number, unknown>();
  rec.set(1, account);
  rec.set(2, hexToBytes(pubHex + ccHex));
  rec.set(3, `1852'/1815'/${account}'`);
  const m = new Map<number, unknown>();
  m.set(1, requestId);
  m.set(2, hexToBytes(xfpHex));
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  m.set(3, [rec] as any);
  m.set(4, label);
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  return bytesToHex([...encodeCbor(m as any)]);
}

// A `cardano-tx-sig-res` reply: {1:request_id, 2: tag258([[pub,sig]])}. The set
// tag (d90102) is written by hand since the shared encoder emits no tags.
// `requestId` defaults to "id" for the same reason as accountCborHex above.
function txSigResCborHex(pubHex: string, sigHex: string, requestId = "id"): string {
  const witnessSet = "d90102" + "81" + "82" + "5820" + pubHex + "5840" + sigHex;
  return "a2" + "01" + cborTextHex(requestId) + "02" + witnessSet;
}

function makeBridge(): SeedSignerQRBridge & {
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

// ── Byte-exact request encodings (untagged, integer-keyed CBOR maps) ──────────

describe("encodeAccountRequest — byte-exact cardano-account-req", () => {
  test("emits {1:request_id, 2:origin, 3:account_indices, 4:key_purpose} in order", () => {
    const bytes = encodeAccountRequest({ accounts: [0], origin: "x", keyPurpose: 1852 }, "id");
    const expected =
      "a4" + // map(4)
      "01" + "62" + ht("id") + // 1: "id"
      "02" + "61" + ht("x") + // 2: "x"
      "03" + "81" + "00" + // 3: [0]
      "04" + "19" + "073c"; // 4: 1852
    expect(bytesToHex([...bytes])).toBe(expected);
  });

  test("defaults origin to bursa-wallet and key_purpose to 1852", () => {
    const bytes = encodeAccountRequest({ accounts: [0] }, "id");
    const expected =
      "a4" +
      "01" + "62" + ht("id") +
      "02" + "6c" + ht("bursa-wallet") + // text(12)
      "03" + "81" + "00" +
      "04" + "19" + "073c";
    expect(bytesToHex([...bytes])).toBe(expected);
  });
});

describe("encodeTxSigRequest — byte-exact cardano-tx-sig-req", () => {
  test("emits the 7-key map with a wallet input, change output, and network", () => {
    const req: HardwareSignResponse = {
      network: "mainnet",
      network_id: 1,
      protocol_magic: 764824073,
      inputs: [{ tx_hash_hex: "0011", output_index: 1, path: "1852'/1815'/0'/0/0" }],
      outputs: [],
      change_outputs: [{ index: 0, path: "1852'/1815'/0'/1/0" }],
      fee: "0",
      required_signers: [],
      unsigned_tx_cbor: "a0",
    };
    const bytes = encodeTxSigRequest(req, { xfp: "aabbccdd", requestId: "id", origin: "x" });
    const expected =
      "a7" + // map(7)
      "01" + "62" + ht("id") + // 1: request_id
      "02" + "61" + ht("x") + // 2: origin
      "03" + "41" + "a0" + // 3: sign_data (1 byte)
      "04" + "81" + // 4: inputs[1]
        "a4" +
          "01" + "42" + "0011" + // tx_hash
          "02" + "01" + // index
          "03" + "44" + "aabbccdd" + // xfp
          "04" + "72" + ht("1852'/1815'/0'/0/0") + // path
      "05" + "81" + // 5: change_outputs[1]
        "a2" +
          "01" + "00" + // index
          "02" + "72" + ht("1852'/1815'/0'/1/0") + // path
      "06" + "80" + // 6: extra_signers = []
      "07" + "01"; // 7: network = 1
    expect(bytesToHex([...bytes])).toBe(expected);
  });

  test("script-locked (multisig) inputs carry no xfp/path — only tx_hash + index", () => {
    const req: HardwareSignResponse = {
      ...NEUTRAL_REQ,
      inputs: [{ tx_hash_hex: "0011", output_index: 2 }],
      change_outputs: [],
    };
    const bytes = encodeTxSigRequest(req, { xfp: "aabbccdd", requestId: "id", origin: "x" });
    // Input map has ONLY keys 1 (tx_hash) and 2 (index): a2 01 42 0011 02 02.
    expect(bytesToHex([...bytes])).toContain("81" + "a2" + "01" + "42" + "0011" + "02" + "02");
  });
});

// ── extra_signers aggregation (staking / governance / multisig) ───────────────

describe("buildExtraSigners", () => {
  test("aggregates cert / withdrawal / vote / explicit signer paths as [xfp, path] tuples", () => {
    const req: HardwareSignResponse = {
      ...NEUTRAL_REQ,
      certificate_signers: [
        { cert_kind: "stake_delegation", role: "stake", path: "1852'/1815'/0'/2/0", key_hash_hex: "aa" },
      ],
      withdrawal_signers: [
        { role: "stake", path: "1852'/1815'/0'/2/0", key_hash_hex: "bb" },
      ],
      vote_signers: [{ voter: "drep", role: "drep", path: "1852'/1815'/0'/3/0", key_hash_hex: "cc" }],
      extra_signers: [{ role: "payment", path: "1854'/1815'/0'/0/0", key_hash_hex: "dd", xfp: "11223344" }],
    };
    const signers = buildExtraSigners(req, TEST_XFP);
    expect(signers).toEqual([
      [hexToBytes(TEST_XFP), "1852'/1815'/0'/2/0"],
      [hexToBytes(TEST_XFP), "1852'/1815'/0'/2/0"],
      [hexToBytes(TEST_XFP), "1852'/1815'/0'/3/0"],
      [hexToBytes("11223344"), "1854'/1815'/0'/0/0"], // explicit signer keeps its own xfp
    ]);
  });

  test("is empty for a plain payment tx", () => {
    expect(buildExtraSigners(NEUTRAL_REQ, TEST_XFP)).toEqual([]);
  });
});

// ── account response parsing ──────────────────────────────────────────────────

describe("parseAccountResponse", () => {
  test("splits the 64-byte xpub and matches the shared bech32 vector", () => {
    const scanned: SeedSignerScannedUR = {
      type: "cardano-account",
      cborHex: accountCborHex(0, TEST_PUB_KEY_HEX, TEST_CHAIN_CODE_HEX, TEST_XFP),
    };
    const acct = parseAccountResponse(scanned, 0, "id");
    expect(acct.xpub).toBe(TEST_XPUB_BECH32);
    expect(acct.xfp).toBe(TEST_XFP);
    expect(acct.account).toBe(0);
  });

  test("rejects a non-account UR", () => {
    expect(() =>
      parseAccountResponse({ type: "cardano-tx-sig-res", cborHex: "a0" }, 0, "id"),
    ).toThrow(/cardano-account/i);
  });

  test("rejects when the requested account is absent", () => {
    const scanned: SeedSignerScannedUR = {
      type: "cardano-account",
      cborHex: accountCborHex(0, TEST_PUB_KEY_HEX, TEST_CHAIN_CODE_HEX, TEST_XFP),
    };
    expect(() => parseAccountResponse(scanned, 5, "id")).toThrow(/does not contain account 5/i);
  });

  test("rejects a malformed (non-8-hex) fingerprint", () => {
    // xfp of 3 bytes → 6 hex digits, not a valid 4-byte fingerprint.
    const scanned: SeedSignerScannedUR = {
      type: "cardano-account",
      cborHex: accountCborHex(0, TEST_PUB_KEY_HEX, TEST_CHAIN_CODE_HEX, "aabbcc"),
    };
    expect(() => parseAccountResponse(scanned, 0, "id")).toThrow(/malformed master fingerprint/i);
  });

  // ── request-identifier matching (issue: reject a reply that doesn't answer
  // the active request — a stale scan, or one with no/garbled identifier) ──────

  test("rejects a reply whose request id does not match the active request (stale scan)", () => {
    const scanned: SeedSignerScannedUR = {
      type: "cardano-account",
      cborHex: accountCborHex(0, TEST_PUB_KEY_HEX, TEST_CHAIN_CODE_HEX, TEST_XFP, "SeedSigner", "earlier-request"),
    };
    expect(() => parseAccountResponse(scanned, 0, "id")).toThrow(/does not match the active request/i);
  });

  test("rejects a reply with no request id", () => {
    const m = new Map<number, unknown>();
    m.set(2, hexToBytes(TEST_XFP));
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    m.set(3, [] as any);
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const cborHex = bytesToHex([...encodeCbor(m as any)]);
    expect(() => parseAccountResponse({ type: "cardano-account", cborHex }, 0, "id")).toThrow(
      /no request identifier/i,
    );
  });

  test("rejects a reply whose request id is not a text string (malformed)", () => {
    const m = new Map<number, unknown>();
    m.set(1, 42); // request id must be a string, not an integer
    m.set(2, hexToBytes(TEST_XFP));
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    m.set(3, [] as any);
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const cborHex = bytesToHex([...encodeCbor(m as any)]);
    expect(() => parseAccountResponse({ type: "cardano-account", cborHex }, 0, "id")).toThrow(
      /malformed request identifier/i,
    );
  });
});

describe("parseAccountXfp", () => {
  test("returns just the (account-independent) master fingerprint", () => {
    const scanned: SeedSignerScannedUR = {
      type: "cardano-account",
      cborHex: accountCborHex(3, TEST_PUB_KEY_HEX, TEST_CHAIN_CODE_HEX, TEST_XFP),
    };
    expect(parseAccountXfp(scanned, "id")).toBe(TEST_XFP);
  });

  test("rejects a reply whose request id does not match the active request", () => {
    const scanned: SeedSignerScannedUR = {
      type: "cardano-account",
      cborHex: accountCborHex(3, TEST_PUB_KEY_HEX, TEST_CHAIN_CODE_HEX, TEST_XFP, "SeedSigner", "other-request"),
    };
    expect(() => parseAccountXfp(scanned, "id")).toThrow(/does not match the active request/i);
  });
});

// ── witness-set round-trip ────────────────────────────────────────────────────

describe("parseTxSigResponse", () => {
  test("reads the tag-258 witness set and re-encodes it identically to the shared encoder", () => {
    const scanned: SeedSignerScannedUR = {
      type: "cardano-tx-sig-res",
      cborHex: txSigResCborHex(TEST_PUB_KEY_HEX, TEST_SIG_HEX),
    };
    const result = parseTxSigResponse(scanned, "id");
    expect(result).toBe(encodeWitnessArray([{ pubKeyHex: TEST_PUB_KEY_HEX, sigHex: TEST_SIG_HEX }]));
    expect(result.startsWith("8182")).toBe(true);
    expect(result).toContain(TEST_PUB_KEY_HEX);
    expect(result).toContain(TEST_SIG_HEX);
  });

  test("rejects a non-signature UR", () => {
    expect(() =>
      parseTxSigResponse({ type: "cardano-account", cborHex: "a0" }, "id"),
    ).toThrow(/cardano-tx-sig-res/i);
  });

  test("trims an extended (pubkey||chaincode) vkey to the 32-byte public key", () => {
    const extended = TEST_PUB_KEY_HEX + TEST_CHAIN_CODE_HEX;
    const witnessSet = "d90102" + "81" + "82" + "5840" + extended + "5840" + TEST_SIG_HEX;
    const cborHex = "a2" + "01" + "62" + ht("id") + "02" + witnessSet;
    const result = parseTxSigResponse({ type: "cardano-tx-sig-res", cborHex }, "id");
    expect(result).toBe(encodeWitnessArray([{ pubKeyHex: TEST_PUB_KEY_HEX, sigHex: TEST_SIG_HEX }]));
  });

  // ── request-identifier matching ───────────────────────────────────────────

  test("rejects a reply whose request id does not match the active request (stale scan)", () => {
    const scanned: SeedSignerScannedUR = {
      type: "cardano-tx-sig-res",
      cborHex: txSigResCborHex(TEST_PUB_KEY_HEX, TEST_SIG_HEX, "earlier-request"),
    };
    expect(() => parseTxSigResponse(scanned, "id")).toThrow(/does not match the active request/i);
  });

  test("rejects a reply with no request id", () => {
    const witnessSet = "d90102" + "81" + "82" + "5820" + TEST_PUB_KEY_HEX + "5840" + TEST_SIG_HEX;
    const cborHex = "a1" + "02" + witnessSet; // map with only key 2 (witness set)
    expect(() =>
      parseTxSigResponse({ type: "cardano-tx-sig-res", cborHex }, "id"),
    ).toThrow(/no request identifier/i);
  });

  test("rejects a reply whose request id is not a text string (malformed)", () => {
    const witnessSet = "d90102" + "81" + "82" + "5820" + TEST_PUB_KEY_HEX + "5840" + TEST_SIG_HEX;
    const cborHex = "a2" + "01" + "182a" + "02" + witnessSet; // key 1 = uint(42), not a string
    expect(() =>
      parseTxSigResponse({ type: "cardano-tx-sig-res", cborHex }, "id"),
    ).toThrow(/malformed request identifier/i);
  });
});

// ── connectSeedSigner (session) ───────────────────────────────────────────────

describe("connectSeedSigner", () => {
  test("reports kind 'seedsigner' with send/staking/governance/multisig capabilities", async () => {
    const session = await connectSeedSigner({ bridge: makeBridge() });
    expect(session.kind).toBe("seedsigner");
    expect(session.capabilities).toEqual({
      send: true,
      staking: true,
      governance: true,
      multisig: true,
      poolReg: false,
      signMessage: false,
    });
  });

  test("getAccountXpub shows the account-req QR, scans the reply, returns the shared xpub", async () => {
    const bridge = makeBridge();
    bridge.scanResponse.mockResolvedValue({
      type: "cardano-account",
      cborHex: accountCborHex(0, TEST_PUB_KEY_HEX, TEST_CHAIN_CODE_HEX, TEST_XFP),
    });
    const session = await connectSeedSigner({ bridge });
    const xpub = await session.getAccountXpub(0);
    expect(xpub).toBe(TEST_XPUB_BECH32);
    // The animated request QR was shown first.
    expect(bridge.displayRequest).toHaveBeenCalledOnce();
    const fragments = bridge.displayRequest.mock.calls[0][0] as string[];
    expect(fragments[0].toLowerCase()).toMatch(/^ur:cardano-account-req\//);
    expect(bridge.close).toHaveBeenCalled();
  });

  test("signTx round-trips: shows the tx-sig-req QR, scans the signature, returns witness-array CBOR", async () => {
    const bridge = makeBridge();
    bridge.scanResponse.mockResolvedValue({
      type: "cardano-tx-sig-res",
      cborHex: txSigResCborHex(TEST_PUB_KEY_HEX, TEST_SIG_HEX),
    });
    const session = await connectSeedSigner({ bridge, xfp: TEST_XFP });
    const result = await session.signTx(NEUTRAL_REQ);

    expect(bridge.displayRequest).toHaveBeenCalledOnce();
    const fragments = bridge.displayRequest.mock.calls[0][0] as string[];
    expect(fragments[0].toLowerCase()).toMatch(/^ur:cardano-tx-sig-req\//);

    expect(result).toBe(encodeWitnessArray([{ pubKeyHex: TEST_PUB_KEY_HEX, sigHex: TEST_SIG_HEX }]));
    expect(bridge.close).toHaveBeenCalled();
  });

  test("signTx rejects a reply carrying a different (stale) request id", async () => {
    // A response left over from an EARLIER sign request — e.g. still showing on
    // the device or re-scanned from a screenshot — must not be attached to the
    // current operation just because it happens to be a well-formed signature.
    const bridge = makeBridge();
    bridge.scanResponse.mockResolvedValue({
      type: "cardano-tx-sig-res",
      cborHex: txSigResCborHex(TEST_PUB_KEY_HEX, TEST_SIG_HEX, "earlier-request"),
    });
    const session = await connectSeedSigner({ bridge, xfp: TEST_XFP });
    await expect(session.signTx(NEUTRAL_REQ)).rejects.toThrow(/does not match the active request/i);
    expect(bridge.close).toHaveBeenCalled();
  });

  test("signTx refuses to build a request with a missing fingerprint (no zero fp)", async () => {
    const bridge = makeBridge();
    const session = await connectSeedSigner({ bridge });
    await expect(session.signTx(NEUTRAL_REQ)).rejects.toThrow(/fingerprint is missing/i);
    expect(bridge.displayRequest).not.toHaveBeenCalled();
    expect(bridge.scanResponse).not.toHaveBeenCalled();
  });

  test("signTx refuses a malformed (non-8-hex) fingerprint", async () => {
    const bridge = makeBridge();
    const session = await connectSeedSigner({ bridge, xfp: "xyz" });
    await expect(session.signTx(NEUTRAL_REQ)).rejects.toThrow(/fingerprint is missing/i);
    expect(bridge.displayRequest).not.toHaveBeenCalled();
  });

  test("signTx rejects a scanned UR that is not a signature", async () => {
    const bridge = makeBridge();
    bridge.scanResponse.mockResolvedValue({
      type: "cardano-account",
      cborHex: accountCborHex(0, TEST_PUB_KEY_HEX, TEST_CHAIN_CODE_HEX, TEST_XFP),
    });
    const session = await connectSeedSigner({ bridge, xfp: TEST_XFP });
    await expect(session.signTx(NEUTRAL_REQ)).rejects.toThrow(/cardano-tx-sig-res/i);
    expect(bridge.close).toHaveBeenCalled();
  });

  test("is fully local: options carry no consent callback, and one is never invoked", async () => {
    const bridge = makeBridge();
    bridge.scanResponse.mockResolvedValue({
      type: "cardano-tx-sig-res",
      cborHex: txSigResCborHex(TEST_PUB_KEY_HEX, TEST_SIG_HEX),
    });
    const opts = { bridge, xfp: TEST_XFP };
    expect("requestExternalConsent" in opts).toBe(false);
    const session = await connectSeedSigner(opts);
    await expect(session.signTx(NEUTRAL_REQ)).resolves.toBeTypeOf("string");
  });

  test("signMessage rejects (CIP-8 over the air-gapped QR transport is not implemented yet)", async () => {
    const session = await connectSeedSigner({ bridge: makeBridge() });
    await expect(
      session.signMessage({
        messageHex: "00",
        signingPath: "1852'/1815'/0'/0/0",
        stakePath: "1852'/1815'/0'/2/0",
        networkId: 0,
        protocolMagic: 2,
      }),
    ).rejects.toThrow(/not supported on SeedSigner/i);
  });
});

// ── account import / xfp recovery helpers ─────────────────────────────────────

describe("importSeedSignerAccount", () => {
  test("displays the account-req QR then returns xpub + xfp from the scanned reply", async () => {
    const bridge = makeBridge();
    bridge.scanResponse.mockResolvedValue({
      type: "cardano-account",
      cborHex: accountCborHex(2, TEST_PUB_KEY_HEX, TEST_CHAIN_CODE_HEX, TEST_XFP),
    });
    const acct = await importSeedSignerAccount(bridge, 2);
    expect(acct).toEqual({ xpub: TEST_XPUB_BECH32, xfp: TEST_XFP, account: 2 });
    expect(bridge.displayRequest).toHaveBeenCalledOnce();
    expect(bridge.close).toHaveBeenCalled();
  });
});

describe("recoverSeedSignerXfp", () => {
  test("re-runs the account exchange and returns only the fingerprint", async () => {
    const bridge = makeBridge();
    bridge.scanResponse.mockResolvedValue({
      type: "cardano-account",
      cborHex: accountCborHex(0, TEST_PUB_KEY_HEX, TEST_CHAIN_CODE_HEX, TEST_XFP),
    });
    expect(await recoverSeedSignerXfp(bridge)).toBe(TEST_XFP);
    expect(bridge.close).toHaveBeenCalled();
  });
});

// A sanity check that the shared xpub encoder is the SAME one every device uses.
test("shared xpub encoder parity guard", () => {
  expect(encodeXpub(TEST_PUB_KEY_HEX, TEST_CHAIN_CODE_HEX)).toBe(TEST_XPUB_BECH32);
});
