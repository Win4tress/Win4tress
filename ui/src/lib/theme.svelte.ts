// The colour theme: the user's choice of colours (win4tress or indigo) and of
// light or dark (match Windows, light or dark), applied as `data-palette` and
// `data-theme` on <html>, where app.css picks its tokens. public/theme-init.js
// applies the saved choice before the first paint; this keeps it up to date.

import { getCurrentWindow } from "@tauri-apps/api/window";

export type ThemeChoice = "system" | "light" | "dark";
export type Palette = "win4tress" | "indigo";
type Resolved = "light" | "dark";

const KEY = "w4.theme";
const PALETTE_KEY = "w4.palette";
const media = matchMedia("(prefers-color-scheme: dark)");

// Until the user picks: Indigo, dark.
function saved(): ThemeChoice {
  try {
    const v = localStorage.getItem(KEY);
    return v === "light" || v === "system" ? v : "dark";
  } catch {
    return "dark";
  }
}

function savedPalette(): Palette {
  try {
    return localStorage.getItem(PALETTE_KEY) === "win4tress" ? "win4tress" : "indigo";
  } catch {
    return "indigo";
  }
}

function keep(key: string, value: string) {
  try {
    localStorage.setItem(key, value);
  } catch {
    // Not saved: the choice lasts until the app closes.
  }
}

class Theme {
  choice = $state<ThemeChoice>(saved());
  palette = $state<Palette>(savedPalette());
  #windows = $state<Resolved>(media.matches ? "dark" : "light");
  /** Light or dark, as showing. */
  readonly resolved: Resolved = $derived(this.choice === "system" ? this.#windows : this.choice);
  /** What's showing. Canvas charts redraw when it changes: their colours are baked in. */
  readonly look: string = $derived(`${this.palette} ${this.resolved}`);

  constructor() {
    media.addEventListener("change", (e) => {
      this.#windows = e.matches ? "dark" : "light";
      this.#apply();
    });
    this.#apply();
  }

  set(choice: ThemeChoice) {
    this.choice = choice;
    keep(KEY, choice);
    this.#apply();
  }

  setPalette(palette: Palette) {
    this.palette = palette;
    keep(PALETTE_KEY, palette);
    this.#apply();
  }

  /** On <html> at once (not in an effect), so anything reading the tokens next sees the new ones. */
  #apply() {
    const root = document.documentElement;
    root.dataset.theme = this.choice === "system" ? this.#windows : this.choice;
    root.dataset.palette = this.palette;
    // The title bar follows Windows, or the choice.
    getCurrentWindow()
      .setTheme(this.choice === "system" ? null : this.choice)
      .catch(() => {});
  }
}

export const theme = new Theme();
