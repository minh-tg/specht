/**
 * The one treatment for a link inside running text or a standalone text link: action colour,
 * underlined at rest, thicker underline on hover. Keyboard focus comes from the global
 * :focus-visible outline. Size, margin and display stay at the call site.
 */
export const INLINE_LINK =
  "text-action rounded-sm underline underline-offset-3 transition-[text-decoration-thickness] duration-(--dur-instant) ease-entering hover:decoration-2";

/**
 * Makes a standalone text link at least 24px tall on a touch screen, the WCAG 2.2 minimum. A link in
 * running text is exempt and does not need it. It changes nothing for a mouse.
 */
export const TOUCH_TARGET =
  "pointer-coarse:inline-flex pointer-coarse:min-h-6 pointer-coarse:items-center";
