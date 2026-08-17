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
  expect(screen.getByText(/keys are safe/i)).toBeInTheDocument();
  // Must NOT claim nothing was submitted: a throw can land after a submission,
  // and a false all-clear invites a duplicate send.
  expect(screen.queryByText(/nothing was submitted/i)).not.toBeInTheDocument();
  expect(screen.getByText(/check Activity before trying again/i)).toBeInTheDocument();
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

test("a non-Error throw does not crash the fallback itself", () => {
  function ThrowsString(): React.ReactElement {
    // Nothing guarantees a child throws an Error; reading .message off a
    // string, null or undefined in the fallback would re-throw and restore the
    // blank page this component exists to prevent.
    throw "boom";
  }
  render(
    <ErrorBoundary label="swap">
      <ThrowsString />
    </ErrorBoundary>,
  );
  expect(screen.getByRole("alert")).toHaveTextContent(/something went wrong/i);
  expect(screen.getByText("boom")).toBeInTheDocument();
});

test("a thrown null still renders a readable message", () => {
  function ThrowsNull(): React.ReactElement {
    throw null;
  }
  render(
    <ErrorBoundary label="swap">
      <ThrowsNull />
    </ErrorBoundary>,
  );
  expect(screen.getByRole("alert")).toHaveTextContent(/an unexpected error occurred/i);
});

test("an error thrown by the destination survives the reset", () => {
  // Navigating changes resetKey in the same commit that the destination
  // throws. Clearing on any key change would discard that fresh error,
  // remount, throw again and log the same fault twice.
  function Harness() {
    const [route, setRoute] = useState("swap");
    return (
      <>
        <button onClick={() => setRoute("portfolio")}>go portfolio</button>
        <ErrorBoundary label={route} resetKey={route}>
          <Boom explode />
        </ErrorBoundary>
      </>
    );
  }
  render(<Harness />);
  expect(screen.getByRole("alert")).toBeInTheDocument();

  fireEvent.click(screen.getByText("go portfolio"));

  // Still showing a fallback, now for the destination, rather than flickering
  // through a cleared state.
  expect(screen.getByRole("alert")).toBeInTheDocument();
  expect(screen.getByText(/the portfolio screen could not be displayed/i)).toBeInTheDocument();
});
