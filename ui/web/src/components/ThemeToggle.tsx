import { useTheme } from "../theme";

// ThemeToggle is a compact two-way segmented control (the same instrument-tab
// styling as the Operate screen's mode switch) for picking the dark cockpit
// theme or its light counterpart. It's rendered both in the sidebar (a
// header-level control, visible on every unlocked screen) and in
// Settings > Appearance.
export function ThemeToggle() {
  const [theme, setTheme] = useTheme();

  return (
    <div className="theme-toggle" role="group" aria-label="Theme">
      <button
        type="button"
        className={theme === "dark" ? "operate-tab active" : "operate-tab"}
        aria-pressed={theme === "dark"}
        onClick={() => setTheme("dark")}
      >
        Dark
      </button>
      <button
        type="button"
        className={theme === "light" ? "operate-tab active" : "operate-tab"}
        aria-pressed={theme === "light"}
        onClick={() => setTheme("light")}
      >
        Light
      </button>
    </div>
  );
}
