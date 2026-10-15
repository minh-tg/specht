/**
 * The one treatment for a link inside running text or a standalone text link: action colour,
 * underlined at rest, thicker underline on hover. Keyboard focus comes from the global
 * :focus-visible outline. Size, margin and display stay at the call site.
 */
export const INLINE_LINK =
  "text-action rounded-sm underline underline-offset-3 transition-[text-decoration-thickness] duration-(--dur-instant) ease-entering hover:decoration-2";
