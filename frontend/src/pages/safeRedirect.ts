// ASCII control characters (0x00-0x1f, 0x7f) and backslash. The URL parser removes tab, CR and LF
// anywhere in its input, so "/\t/host" would resolve to the protocol-relative "//host".
// eslint-disable-next-line no-control-regex
const CONTROL_OR_BACKSLASH = /[\u0000-\u001f\u007f\\]/;

export function safeRedirect(redirect: string | null): string {
  if (!redirect) return "/";
  if (!redirect.startsWith("/")) return "/";
  // Block "//evil.com" (protocol-relative).
  if (redirect[1] === "/") return "/";
  // Block "/\\evil.com" and any control character, wherever it sits in the value.
  if (CONTROL_OR_BACKSLASH.test(redirect)) return "/";
  return redirect;
}
