import type { Finding } from "@/types/api";

/**
 * Says so when the scanner behind an open finding cannot prove a fix. The server decides: the
 * finding carries its scanner's `supports_auto_close`, so no scanner list lives here.
 */
export function AutoCloseNote({ finding }: { readonly finding: Finding; }) {
  const scanner = finding.scanner;
  if (!scanner || scanner.supports_auto_close) return null;
  if (finding.state !== "open" && finding.state !== "reopened") return null;
  return (
    <p className="text-muted-foreground mt-4 text-sm">
      {scanner.display_name}{" "}
      reports cannot prove a fix, so a later scan will not close this finding. Once you have dealt
      with it, use a triage decision to stop it blocking.
    </p>
  );
}
