/**
 * Focusable-element discovery for focus management.
 *
 * Split out of the FocusScope component so the module keeps a single component
 * export — a mixed export breaks Fast Refresh.
 */

const FOCUSABLE = [
  "a[href]",
  "button:not([disabled])",
  "input:not([disabled]):not([type='hidden'])",
  "select:not([disabled])",
  "textarea:not([disabled])",
  "[tabindex]:not([tabindex='-1'])",
].join(",");

/** True when an element is not hidden from the accessibility tree or by style. */
export function isVisible(node: HTMLElement): boolean {
  if (node.hasAttribute("hidden")) return false;
  if (node.getAttribute("aria-hidden") === "true") return false;
  // Deliberately not `offsetParent`: it is always null in jsdom, which would drop
  // every candidate and silently disable a focus trap under test.
  const style = window.getComputedStyle(node);
  return style.display !== "none" && style.visibility !== "hidden";
}

/** Everything focusable inside `root`, in DOM order, excluding hidden elements. */
export function getFocusable(root: HTMLElement): HTMLElement[] {
  return Array.from(root.querySelectorAll<HTMLElement>(FOCUSABLE)).filter(isVisible);
}
