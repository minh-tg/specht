/** A plain address check for forms; the server has the final say on whether an account exists. */
export function looksLikeEmail(value: string): boolean {
  return /^[^\s@<>]+@[^\s@<>]+\.[^\s@<>]+$/.test(value);
}
