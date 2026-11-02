// Applies the saved theme before the first paint, so a dark window never flashes
// light. A file, not inline: the page's content security policy allows no inline
// script. src/lib/theme.svelte.ts takes over once the app starts.
(function () {
  // Until the user picks: Indigo, dark (as in src/lib/theme.svelte.ts).
  var choice = "dark";
  var palette = "indigo";
  try {
    choice = localStorage.getItem("w4.theme") || "dark";
    if (localStorage.getItem("w4.palette") === "win4tress") palette = "win4tress";
  } catch (e) {
    // No storage: the defaults.
  }
  var dark =
    choice !== "light" && (choice !== "system" || matchMedia("(prefers-color-scheme: dark)").matches);
  document.documentElement.dataset.theme = dark ? "dark" : "light";
  document.documentElement.dataset.palette = palette;
})();
