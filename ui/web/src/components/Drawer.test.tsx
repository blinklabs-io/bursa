import { render, screen, fireEvent } from "@testing-library/react";
import { Drawer } from "./Drawer";

afterEach(() => {
  document.body.replaceChildren();
});

// --- structure / rendering ---

test("renders a modal dialog labelled by its title with its children", () => {
  render(
    <Drawer title="Transaction detail" onClose={vi.fn()}>
      <p>Body content</p>
    </Drawer>,
  );

  const dialog = screen.getByRole("dialog");
  expect(dialog).toHaveAttribute("aria-modal", "true");
  expect(dialog).toHaveAttribute("aria-label", "Transaction detail");
  expect(screen.getByText("Body content")).toBeInTheDocument();
  expect(screen.getByText("Transaction detail")).toBeInTheDocument();
});

// --- close affordances ---

test("the close button calls onClose", () => {
  const onClose = vi.fn();
  render(<Drawer title="Detail" onClose={onClose} />);

  fireEvent.click(screen.getByRole("button", { name: /close/i }));
  expect(onClose).toHaveBeenCalledTimes(1);
});

test("clicking the backdrop calls onClose", () => {
  const onClose = vi.fn();
  const { container } = render(<Drawer title="Detail" onClose={onClose} />);

  fireEvent.click(container.querySelector(".drawer-overlay")!);
  expect(onClose).toHaveBeenCalledTimes(1);
});

test("clicking inside the drawer panel does NOT close it (click does not bubble to the backdrop)", () => {
  const onClose = vi.fn();
  render(
    <Drawer title="Detail" onClose={onClose}>
      <button>Inner</button>
    </Drawer>,
  );

  fireEvent.click(screen.getByRole("dialog"));
  expect(onClose).not.toHaveBeenCalled();
});

test("Escape closes the drawer", () => {
  const onClose = vi.fn();
  render(<Drawer title="Detail" onClose={onClose} />);

  fireEvent.keyDown(document, { key: "Escape" });
  expect(onClose).toHaveBeenCalledTimes(1);
});

test("a non-trap, non-Escape key does not close the drawer", () => {
  const onClose = vi.fn();
  render(
    <Drawer title="Detail" onClose={onClose}>
      <button>Inner</button>
    </Drawer>,
  );

  fireEvent.keyDown(document, { key: "a" });
  expect(onClose).not.toHaveBeenCalled();
});

// --- focus management ---

test("moves focus into the drawer on open (the header Close is the first focusable)", () => {
  render(
    <Drawer title="Detail" onClose={vi.fn()}>
      <a href="#x">First link</a>
      <button>Second</button>
    </Drawer>,
  );

  // The header Close button precedes the children in DOM order, so it is the
  // first focusable element the trap lands on.
  expect(screen.getByRole("button", { name: /close/i })).toHaveFocus();
});

test("focuses the header Close button even when the drawer has no children", () => {
  render(<Drawer title="Detail" onClose={vi.fn()} />);
  expect(screen.getByRole("button", { name: /close/i })).toHaveFocus();
});

test("restores focus to the previously focused element on unmount", () => {
  const trigger = document.createElement("button");
  trigger.textContent = "Open";
  document.body.append(trigger);
  trigger.focus();
  expect(trigger).toHaveFocus();

  const { unmount } = render(
    <Drawer title="Detail" onClose={vi.fn()}>
      <button>Inner</button>
    </Drawer>,
  );
  // Focus moved off the trigger into the drawer (the header Close button).
  expect(trigger).not.toHaveFocus();
  expect(screen.getByRole("button", { name: /close/i })).toHaveFocus();

  unmount();
  expect(trigger).toHaveFocus();
});

// --- focus trap ---

test("Tab from the last focusable element wraps to the first", () => {
  render(
    <Drawer title="Detail" onClose={vi.fn()}>
      <button>Alpha</button>
      <button>Omega</button>
    </Drawer>,
  );

  // Focus order: Close (header), Alpha, Omega. Move to the last.
  const omega = screen.getByRole("button", { name: /omega/i });
  omega.focus();
  fireEvent.keyDown(document, { key: "Tab" });

  const close = screen.getByRole("button", { name: /close/i });
  expect(close).toHaveFocus();
});

test("Shift+Tab from the first focusable element wraps to the last", () => {
  render(
    <Drawer title="Detail" onClose={vi.fn()}>
      <button>Alpha</button>
      <button>Omega</button>
    </Drawer>,
  );

  const close = screen.getByRole("button", { name: /close/i });
  close.focus();
  fireEvent.keyDown(document, { key: "Tab", shiftKey: true });

  expect(screen.getByRole("button", { name: /omega/i })).toHaveFocus();
});

test("Tab from the middle does not force-wrap (browser handles the move)", () => {
  render(
    <Drawer title="Detail" onClose={vi.fn()}>
      <button>Alpha</button>
      <button>Omega</button>
    </Drawer>,
  );

  const alpha = screen.getByRole("button", { name: /alpha/i });
  alpha.focus();
  // Alpha is neither first (Close) nor last (Omega): the trap does not move focus.
  fireEvent.keyDown(document, { key: "Tab" });
  expect(alpha).toHaveFocus();
});
