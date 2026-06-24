import { render, screen, fireEvent } from "@testing-library/react";
import { Receive } from "./Receive";
import * as hooks from "../api/hooks";

const ADDR_A = "addr_test1qpfqpgxzsq8d6l5n5qxkdqqvxqqtd2syvxsw0mkzmq2dzn7y2y5a3uqquasklznf6xvxn0tmxy2cjaslt9yq5ygz4dqsv9r4pk";
const ADDR_B = "addr_test1qqy2j78ks2htj6x5p2xztqpvqxqqtd2syvxsw0mkzmq2dzny0cjaslt9yq5ygz4dqsv9r4pkzuqquasklznf6xvxn0tmxwtest2";

function mockAddresses(overrides?: Partial<{ receive: string[]; used: string[]; next_unused: string }>) {
  vi.spyOn(hooks, "useAddresses").mockReturnValue({
    data: {
      receive: [ADDR_A, ADDR_B],
      used: [ADDR_A],
      next_unused: ADDR_B,
      ...overrides,
    },
    error: null,
    loading: false,
    refresh: vi.fn(),
  } as never);
}

afterEach(() => {
  vi.restoreAllMocks();
});

test("(a) next unused address card copies the FULL address", () => {
  const writeText = vi.fn().mockResolvedValue(undefined);
  Object.assign(navigator, { clipboard: { writeText } });
  mockAddresses();
  render(<Receive />);

  // next_unused address appears on screen
  expect(screen.getByText(ADDR_B)).toBeInTheDocument();

  // The first copy button is the next-unused card's; it must copy the FULL
  // address, not the truncated display value.
  const copyButtons = screen.getAllByRole("button", { name: /copy/i });
  expect(copyButtons.length).toBeGreaterThanOrEqual(1);
  fireEvent.click(copyButtons[0]);
  expect(writeText).toHaveBeenCalledWith(ADDR_B);
});

test("(b) renders a table listing all receive addresses", () => {
  mockAddresses();
  render(<Receive />);

  // Addresses appear truncated in the table; check by the start of each address.
  // ADDR_A starts with "addr_test1qp" — the truncated form includes that prefix.
  expect(screen.getAllByText((_, el) =>
    el?.tagName !== "SCRIPT" && (el?.textContent ?? "").includes(ADDR_A.slice(0, 8))
  ).length).toBeGreaterThanOrEqual(1);

  // ADDR_B appears fully in the next_unused card and truncated in the table.
  expect(screen.getAllByText((_, el) =>
    el?.tagName !== "SCRIPT" && (el?.textContent ?? "").includes(ADDR_B.slice(0, 8))
  ).length).toBeGreaterThanOrEqual(1);
});

test("(c) used addresses are visually marked as used", () => {
  mockAddresses();
  render(<Receive />);

  // ADDR_A is in the used list — there should be a 'Used' label or badge in the table.
  // Use getAllByText since 'Used' is a substring of 'Unused' — check for exact 'Used' cell.
  expect(screen.getAllByText("Used").length).toBeGreaterThanOrEqual(1);
});

test("(d) unused addresses show an 'Unused' or empty status in the table", () => {
  mockAddresses();
  render(<Receive />);

  // ADDR_B is not used — there should be an 'Unused' cell in the table.
  expect(screen.getAllByText("Unused").length).toBeGreaterThanOrEqual(1);
});

test("(e) loading state renders a loading indicator", () => {
  vi.spyOn(hooks, "useAddresses").mockReturnValue({
    data: null,
    error: null,
    loading: true,
    refresh: vi.fn(),
  } as never);

  render(<Receive />);

  expect(screen.getByText(/loading/i)).toBeInTheDocument();
});

test("(f) error state renders inline error message", () => {
  vi.spyOn(hooks, "useAddresses").mockReturnValue({
    data: null,
    error: new Error("fetch failed"),
    loading: false,
    refresh: vi.fn(),
  } as never);

  render(<Receive />);

  expect(screen.getByText(/fetch failed/i)).toBeInTheDocument();
});

test("(g) empty receive list renders gracefully (fresh wallet)", () => {
  mockAddresses({ receive: [], used: [], next_unused: ADDR_A });
  render(<Receive />);

  // Card with next_unused still visible
  expect(screen.getByText(ADDR_A)).toBeInTheDocument();
});
