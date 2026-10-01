/** Longest slug the API accepts; kept in sync with isValidSlug. */
export const MAX_SLUG_LENGTH = 48;

/** Shortest slug the API accepts. */
export const MIN_SLUG_LENGTH = 3;

const SLUG_PATTERN = /^[a-z0-9]+(-[a-z0-9]+)*$/;

/**
 * Turns a display name into a URL- and CI-safe slug: lowercase, every run of
 * characters outside [a-z0-9] collapsed into a single hyphen, no leading or
 * trailing hyphen. Input longer than MAX_SLUG_LENGTH is cut at the limit; a
 * hyphen left dangling by the cut is dropped so the result stays valid.
 */
export function slugify(name: string): string {
  const slug = name
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-+|-+$/g, "");

  if (slug.length <= MAX_SLUG_LENGTH) return slug;
  return slug.slice(0, MAX_SLUG_LENGTH).replace(/-+$/, "");
}

/** True when `slug` is a valid project slug: 3-48 chars, `a-z0-9` groups
 * separated by single hyphens, no leading or trailing hyphen. */
export function isValidSlug(slug: string): boolean {
  if (slug.length < MIN_SLUG_LENGTH || slug.length > MAX_SLUG_LENGTH) return false;
  return SLUG_PATTERN.test(slug);
}
