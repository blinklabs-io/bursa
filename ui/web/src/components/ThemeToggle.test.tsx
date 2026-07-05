import { render, screen, fireEvent } from "@testing-library/react";
import { ThemeToggle } from "./ThemeToggle";

const STORAGE_KEY = "bursa:theme";

afterEach(() => {
  localStorage.clear();
  document.documentElement.removeAttribute("data-theme");
});

test("renders a Dark/Light group with the current theme marked pressed", () => {
  render(<ThemeToggle />);
  const dark = screen.getByRole("button", { name: "Dark" });
  const light = screen.getByRole("button", { name: "Light" });
  // No stored choice and the mocked matchMedia (test-setup.ts) reports no
  // light preference, so dark is the resolved default.
  expect(dark).toHaveAttribute("aria-pressed", "true");
  expect(light).toHaveAttribute("aria-pressed", "false");
});

test("clicking Light sets data-theme=light on the document root and persists it", () => {
  render(<ThemeToggle />);
  fireEvent.click(screen.getByRole("button", { name: "Light" }));

  expect(document.documentElement.getAttribute("data-theme")).toBe("light");
  expect(localStorage.getItem(STORAGE_KEY)).toBe("light");
  expect(screen.getByRole("button", { name: "Light" })).toHaveAttribute("aria-pressed", "true");
  expect(screen.getByRole("button", { name: "Dark" })).toHaveAttribute("aria-pressed", "false");
});

test("clicking Dark after Light sets data-theme=dark and persists it", () => {
  render(<ThemeToggle />);
  fireEvent.click(screen.getByRole("button", { name: "Light" }));
  fireEvent.click(screen.getByRole("button", { name: "Dark" }));

  expect(document.documentElement.getAttribute("data-theme")).toBe("dark");
  expect(localStorage.getItem(STORAGE_KEY)).toBe("dark");
});

test("a persisted choice is read back on the next mount (simulated reload)", () => {
  localStorage.setItem(STORAGE_KEY, "light");

  render(<ThemeToggle />);

  expect(screen.getByRole("button", { name: "Light" })).toHaveAttribute("aria-pressed", "true");
  expect(screen.getByRole("button", { name: "Dark" })).toHaveAttribute("aria-pressed", "false");
});

test("two mounted instances stay in sync: clicking one updates the other", () => {
  // Mirrors the real app: the sidebar ThemeToggle and the Settings >
  // Appearance ThemeToggle are mounted at the same time.
  render(
    <>
      <ThemeToggle />
      <ThemeToggle />
    </>,
  );
  const [firstDark, secondDark] = screen.getAllByRole("button", { name: "Dark" });
  const [firstLight, secondLight] = screen.getAllByRole("button", { name: "Light" });

  fireEvent.click(firstLight);

  // The clicked instance updates...
  expect(firstLight).toHaveAttribute("aria-pressed", "true");
  expect(firstDark).toHaveAttribute("aria-pressed", "false");
  // ...and so does the OTHER, untouched instance.
  expect(secondLight).toHaveAttribute("aria-pressed", "true");
  expect(secondDark).toHaveAttribute("aria-pressed", "false");

  fireEvent.click(secondDark);

  expect(firstDark).toHaveAttribute("aria-pressed", "true");
  expect(firstLight).toHaveAttribute("aria-pressed", "false");
  expect(secondDark).toHaveAttribute("aria-pressed", "true");
  expect(secondLight).toHaveAttribute("aria-pressed", "false");
});
