import { render, screen, fireEvent } from "@testing-library/react";
import { Button } from "./Button";
import { StatusPill } from "./StatusPill";
import { CopyButton } from "./CopyButton";

const originalClipboard = navigator.clipboard;
afterEach(() => {
  // Restore the global clipboard the CopyButton test stubs, to avoid leakage.
  Object.assign(navigator, { clipboard: originalClipboard });
});

test("Button fires onClick", () => {
  let clicked = false;
  render(<Button onClick={() => (clicked = true)}>Go</Button>);
  fireEvent.click(screen.getByText("Go"));
  expect(clicked).toBe(true);
});

test("StatusPill shows its tone + label", () => {
  render(<StatusPill tone="ok">ready</StatusPill>);
  expect(screen.getByText("ready")).toBeInTheDocument();
});

test("CopyButton copies its value and shows feedback on success", async () => {
  const writeText = vi.fn().mockResolvedValue(undefined);
  Object.assign(navigator, { clipboard: { writeText } });
  render(<CopyButton value="addr_test1abc" />);
  fireEvent.click(screen.getByRole("button"));
  expect(writeText).toHaveBeenCalledWith("addr_test1abc");
  // "Copied" appears only after the async write resolves.
  expect(await screen.findByText("Copied")).toBeInTheDocument();
});
