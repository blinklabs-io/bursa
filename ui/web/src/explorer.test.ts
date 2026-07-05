import { explorerUrl } from "./explorer";
import type { ExplorerKind } from "./explorer";

const NETWORKS = ["mainnet", "preprod", "preview"] as const;
const KINDS: ExplorerKind[] = ["tx", "address", "pool", "drep"];

const EXPECTED_HOST: Record<(typeof NETWORKS)[number], string> = {
  mainnet: "cardanoscan.io",
  preprod: "preprod.cardanoscan.io",
  preview: "preview.cardanoscan.io",
};

const EXPECTED_PATH: Record<ExplorerKind, string> = {
  tx: "transaction",
  address: "address",
  pool: "pool",
  drep: "drep",
};

for (const network of NETWORKS) {
  for (const kind of KINDS) {
    test(`explorerUrl(${network}, ${kind}, id) uses the correct host + path`, () => {
      const url = explorerUrl(network, kind, "some-id-123");
      expect(url).toBe(`https://${EXPECTED_HOST[network]}/${EXPECTED_PATH[kind]}/some-id-123`);
    });
  }
}

test("explorerUrl URL-encodes the id", () => {
  const url = explorerUrl("preview", "tx", "abc def/ghi");
  expect(url).toBe("https://preview.cardanoscan.io/transaction/abc%20def%2Fghi");
});

test("explorerUrl falls back to the mainnet host for an unknown network string", () => {
  const url = explorerUrl("some-unknown-network", "address", "addr1xyz");
  expect(url).toBe("https://cardanoscan.io/address/addr1xyz");
});

test("explorerUrl always produces an https URL (never calls out to it itself)", () => {
  const url = explorerUrl("mainnet", "pool", "pool1abc");
  expect(url.startsWith("https://")).toBe(true);
});
