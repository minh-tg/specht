import { type ClassValue, clsx } from "clsx";
import { extendTailwindMerge } from "tailwind-merge";

// The type roles in index.css are font sizes; without this, tailwind-merge reads text-body as a colour.
const twMerge = extendTailwindMerge({
  extend: {
    classGroups: {
      "font-size": [{ text: ["title", "section", "body", "meta", "label", "code", "control"] }],
    },
  },
});

export function cn(...inputs: ClassValue[]) {
  return twMerge(clsx(inputs));
}

/**
 * Truncates text to at most `max` characters (ellipsis included) for inline
 * display. Operates on code points rather than UTF-16 code units so
 * multi-byte characters are never split mid-character. Returns the input
 * unchanged when it already fits.
 */
export function truncateText(value: string, max = 240): string {
  if ([...value].length <= max) return value;
  const keep = Math.max(0, max - 1);
  return `${[...value].slice(0, keep).join("")}…`;
}
