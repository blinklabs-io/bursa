import { render, screen, fireEvent } from "@testing-library/react";

// Stub the QR encoder so we can assert on exactly what value it was asked to
// encode, independent of the real qrcode.react rendering pipeline (which is
// exercised for real — unmocked — in Receive.test.tsx).
vi.mock("qrcode.react", () => ({
  QRCodeSVG: ({ value, title }: { value: string; title?: string }) => (
    <svg data-testid="qr-mock" data-qr-value={value} role="img">
      {title && <title>{title}</title>}
    </svg>
  ),
}));

import { Receive } from "./Receive";
import * as hooks from "../api/hooks";

const ADDR_A = "addr_test1qpfqpgxzsq8d6l5n5qxkdqqvxqqtd2syvxsw0mkzmq2dzn7y2y5a3uqquasklznf6xvxn0tmxy2cjaslt9yq5ygz4dqsv9r4pk";
const ADDR_B = "addr_test1qqy2j78ks2htj6x5p2xztqpvqxqqtd2syvxsw0mkzmq2dzny0cjaslt9yq5ygz4dqsv9r4pkzuqquasklznf6xvxn0tmxwtest2";

function mockAddresses() {
  vi.spyOn(hooks, "useAddresses").mockReturnValue({
    data: {
      receive: [ADDR_A, ADDR_B],
      used: [ADDR_A],
      next_unused: ADDR_B,
    },
    error: null,
    loading: false,
    refresh: vi.fn(),
    setData: vi.fn(),
  });
}

afterEach(() => {
  vi.restoreAllMocks();
});

test("hero QR encodes the exact next-unused address, not the truncated display string", () => {
  mockAddresses();
  render(<Receive />);

  // No row QR is expanded yet, so the hero's is the only QR mock rendered —
  // asserting the count keeps this from silently depending on render order.
  const qrCodes = screen.getAllByTestId("qr-mock");
  expect(qrCodes).toHaveLength(1);
  expect(qrCodes[0]).toHaveAttribute("data-qr-value", ADDR_B);
});

test("per-row QR toggle reveals a code encoding the exact full row address", () => {
  mockAddresses();
  render(<Receive />);

  // No row QR is shown until requested.
  expect(
    screen.queryAllByTestId("qr-mock").some((el) => el.getAttribute("data-qr-value") === ADDR_A),
  ).toBe(false);

  fireEvent.click(screen.getByRole("button", { name: `Show QR code for ${ADDR_A}` }));

  const rowQr = screen
    .getAllByTestId("qr-mock")
    .find((el) => el.getAttribute("data-qr-value") === ADDR_A);
  expect(rowQr).toBeDefined();

  // Toggling again hides it.
  fireEvent.click(screen.getByRole("button", { name: `Hide QR code for ${ADDR_A}` }));
  expect(
    screen.queryAllByTestId("qr-mock").some((el) => el.getAttribute("data-qr-value") === ADDR_A),
  ).toBe(false);
});

test("QR regenerates when the next-unused address changes", () => {
  mockAddresses();
  const { rerender } = render(<Receive />);
  let qrCodes = screen.getAllByTestId("qr-mock");
  expect(qrCodes).toHaveLength(1);
  expect(qrCodes[0]).toHaveAttribute("data-qr-value", ADDR_B);

  vi.spyOn(hooks, "useAddresses").mockReturnValue({
    data: { receive: [ADDR_A, ADDR_B], used: [ADDR_A, ADDR_B], next_unused: ADDR_A },
    error: null,
    loading: false,
    refresh: vi.fn(),
    setData: vi.fn(),
  });
  rerender(<Receive />);

  qrCodes = screen.getAllByTestId("qr-mock");
  expect(qrCodes).toHaveLength(1);
  expect(qrCodes[0]).toHaveAttribute("data-qr-value", ADDR_A);
});
