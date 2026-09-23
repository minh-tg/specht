export function safeRedirect(redirect: string | null): string {
  if (!redirect) return "/";
  if (!redirect.startsWith("/")) return "/";
  const second = redirect[1];
  // Block "//evil.com" (protocol-relative) and "/\\evil.com" (backslash trick).
  if (second === "/" || second === "\\") return "/";
  return redirect;
}
