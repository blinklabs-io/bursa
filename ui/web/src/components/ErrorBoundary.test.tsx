import { render, screen, fireEvent } from "@testing-library/react";
import { useState } from "react";
import { ErrorBoundary } from "./ErrorBoundary";

function Boom({ explode }: { explode: boolean }): React.ReactElement {
  if (explode) throw new Error("price_impact_pct is undefined");
  return <p>screen content</p>;
}

// React logs caught render errors; silence it so the output stays readable.
beforeEach(() => {
  vi.spyOn(console, "error").mockImplementation(() => {});
});
afterEach(() => {
  vi.restoreAllMocks();
});

test("a throwing screen shows a recoverable panel instead of a blank page", () => {
  render(
    <ErrorBoundary label="swap">
      <Boom explode />
    </ErrorBoundary>,
  );

  expect(screen.getByRole("alert")).toHaveTextContent(/something went wrong/i);
  // Names the screen, and reassures about funds — this is a wallet.
  expect(screen.getByText(/the swap screen could not be displayed/i)).toBeInTheDocument();
  expect(screen.getByText(/funds are unaffected/i)).toBeInTheDocument();
  // The underlying message is kept, so a bug report can carry it.
  expect(screen.getByText(/price_impact_pct is undefined/)).toBeInTheDocument();
});

test("children render untouched when nothing throws", () => {
  render(
    <ErrorBoundary label="swap">
      <Boom explode={false} />
    </ErrorBoundary>,
  );
  expect(screen.getByText("screen content")).toBeInTheDocument();
  expect(screen.queryByRole("alert")).not.toBeInTheDocument();
});

test("navigating to another screen clears the error", () => {
  function Harness() {
    const [route, setRoute] = useState("swap");
    return (
      <>
        <button onClick={() => setRoute("portfolio")}>go portfolio</button>
        <ErrorBoundary label={route} resetKey={route}>
          <Boom explode={route === "swap"} />
        </ErrorBoundary>
      </>
    );
  }
  render(<Harness />);
  expect(screen.getByRole("alert")).toBeInTheDocument();

  fireEvent.click(screen.getByText("go portfolio"));

  // Without the resetKey the user would be pinned to the failed screen.
  expect(screen.queryByRole("alert")).not.toBeInTheDocument();
  expect(screen.getByText("screen content")).toBeInTheDocument();
});
