// Applies the saved or system colour theme before the first paint so a dark-mode
// user never sees a white flash. Kept as an external classic script (not inline)
// so a strict Content-Security-Policy with script-src 'self' keeps working. The
// storage key and the three values mirror src/lib/theme.ts.
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
  } catch {
    // Storage or matchMedia unavailable: keep the default light theme.
  }
})();
