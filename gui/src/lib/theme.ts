// Applies the appearance prefs (theme, reduce_motion) to the document. The
// palettes live in styles.css under `[data-theme=...]`; this module just keeps
// the <html> attributes in sync with the prefs JSON. "system" resolves via
// prefers-color-scheme and re-resolves live when the OS theme flips.

import { getPrefs } from "./api";

export type Prefs = Record<string, unknown>;

const media = window.matchMedia("(prefers-color-scheme: light)");
let currentTheme = "system";

function resolve(theme: string): "dark" | "light" | "hicontrast" {
  if (theme === "light" || theme === "hicontrast") return theme;
  if (theme === "system") return media.matches ? "light" : "dark";
  return "dark";
}

/** Apply theme + reduce-motion from a prefs object to <html>. */
export function applyAppearance(prefs: Prefs) {
  currentTheme = String(prefs.theme ?? "system");
  const el = document.documentElement;
  el.dataset.theme = resolve(currentTheme);
  el.dataset.reduceMotion = String(Boolean(prefs.reduce_motion));
}

// Follow the OS when the pref is "system".
media.addEventListener("change", () => {
  if (currentTheme === "system") {
    document.documentElement.dataset.theme = resolve(currentTheme);
  }
});

/** Load prefs once at startup and apply them (main window and tray popover). */
export async function initAppearance() {
  try {
    applyAppearance(await getPrefs());
  } catch {
    // No prefs yet (first run) — the dark default in styles.css stands.
  }
}
