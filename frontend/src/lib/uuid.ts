const UUID_PATTERN = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

/** True when `value` is a UUID in the canonical 8-4-4-4-12 hex form. */
export function isUuid(value: string): boolean {
  return UUID_PATTERN.test(value);
}
