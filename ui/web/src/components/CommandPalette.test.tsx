import { render, screen, fireEvent } from "@testing-library/react";
import { CommandPalette } from "./CommandPalette";
import type { Command } from "./CommandPalette";

function cmds(overrides: Partial<Command>[] = []): Command[] {
  const base: Command[] = [
    { id: "send", label: "Send", group: "Move funds", keywords: "pay transfer", run: vi.fn() },
    { id: "offline", label: "Sign a transaction offline", group: "Move funds", keywords: "air gap", run: vi.fn() },
    { id: "stake", label: "Stake", group: "Go", run: vi.fn() },
  ];
  return base.map((c, i) => ({ ...c, ...(overrides[i] ?? {}) }));
}

test("renders nothing when closed", () => {
  const { container } = render(<CommandPalette open={false} commands={cmds()} onClose={vi.fn()} />);
  expect(container).toBeEmptyDOMElement();
});

test("finds a command by words that are not in its label", () => {
  render(<CommandPalette open commands={cmds()} onClose={vi.fn()} />);

  // "air gap" appears only in the keywords — the terms someone actually types.
  fireEvent.change(screen.getByRole("combobox"), { target: { value: "air gap" } });

  const options = screen.getAllByRole("option");
  expect(options).toHaveLength(1);
  expect(options[0]).toHaveTextContent("Sign a transaction offline");
});

test("matches terms in any order, not just as a prefix", () => {
  render(<CommandPalette open commands={cmds()} onClose={vi.fn()} />);

  fireEvent.change(screen.getByRole("combobox"), { target: { value: "funds send" } });

  expect(screen.getAllByRole("option")).toHaveLength(1);
});

test("running a command closes the palette", () => {
  const list = cmds();
  const onClose = vi.fn();
  render(<CommandPalette open commands={list} onClose={onClose} />);

  fireEvent.click(screen.getByRole("option", { name: /Send/ }));

  expect(list[0].run).toHaveBeenCalled();
  expect(onClose).toHaveBeenCalled();
});

test("arrow keys move the selection and Enter runs it", () => {
  const list = cmds();
  render(<CommandPalette open commands={list} onClose={vi.fn()} />);

  const input = screen.getByRole("combobox");
  fireEvent.keyDown(input, { key: "ArrowDown" });
  fireEvent.keyDown(input, { key: "Enter" });

  expect(list[1].run).toHaveBeenCalled();
  expect(list[0].run).not.toHaveBeenCalled();
});

test("Escape closes without running anything", () => {
  const list = cmds();
  const onClose = vi.fn();
  render(<CommandPalette open commands={list} onClose={onClose} />);

  fireEvent.keyDown(screen.getByRole("combobox"), { key: "Escape" });

  expect(onClose).toHaveBeenCalled();
  for (const c of list) expect(c.run).not.toHaveBeenCalled();
});

test("an unavailable command says why and cannot be run", () => {
  const list = cmds([{ disabled: true, disabledReason: "Needs a synced node" }]);
  render(<CommandPalette open commands={list} onClose={vi.fn()} />);

  const option = screen.getByRole("option", { name: /Send/ });
  expect(option).toBeDisabled();
  // The reason takes the group's place rather than leaving the user guessing.
  expect(option).toHaveTextContent("Needs a synced node");

  fireEvent.click(option);
  expect(list[0].run).not.toHaveBeenCalled();
});

test("says so when nothing matches", () => {
  render(<CommandPalette open commands={cmds()} onClose={vi.fn()} />);

  fireEvent.change(screen.getByRole("combobox"), { target: { value: "zzzz" } });

  expect(screen.queryAllByRole("option")).toHaveLength(0);
  expect(screen.getByText(/nothing matches/i)).toBeInTheDocument();
});

test("a shrinking result list does not strand the cursor past the end", () => {
  const list = cmds();
  render(<CommandPalette open commands={list} onClose={vi.fn()} />);

  const input = screen.getByRole("combobox");
  fireEvent.keyDown(input, { key: "ArrowDown" });
  fireEvent.keyDown(input, { key: "ArrowDown" }); // third item
  fireEvent.change(input, { target: { value: "send" } }); // now only one

  fireEvent.keyDown(input, { key: "Enter" });
  expect(list[0].run).toHaveBeenCalled();
});
