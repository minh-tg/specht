// Applies the saved or system colour theme before the first paint so a dark-mode
// user never sees a white flash. Kept as an external classic script (not inline)
// so a strict Content-Security-Policy with script-src 'self' keeps working. The
// storage key, the three values and the theme-color hex values mirror src/lib/theme.ts and
// src/lib/themeColour.ts (themeColour.test.ts checks them).
(function () {
  try {
    const stored = window.localStorage.getItem("specht.theme");
    const theme = stored === "light" || stored === "dark" ? stored : "system";
    const systemDark = typeof window.matchMedia === "function"
      && window.matchMedia("(prefers-color-scheme: dark)").matches;
    const dark = theme === "dark" || (theme === "system" && systemDark);
    const root = document.documentElement;
    root.classList.toggle("dark", dark);
    root.style.colorScheme = dark ? "dark" : "light";
    // The metas in index.html follow the operating system. A manual choice can differ from it, so
    // both take the chosen surface colour; "system" leaves them as shipped.
    if (theme !== "system") {
      const colour = theme === "dark" ? "#110e0b" : "#f6f4ef";
      document.querySelectorAll("meta[name=\"theme-color\"]").forEach(function (meta) {
        meta.setAttribute("content", colour);
      });
    }
  } catch {
    // Storage or matchMedia unavailable: keep the default light theme.
  }
})();
