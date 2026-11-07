import type { Finding } from "@/types/api";

/**
 * Says so when a clean scan will not close an open finding. The server decides: the finding carries
 * its scanner's `supports_auto_close`, which is false when the project keeps that scanner manual.
 */
export function AutoCloseNote({ finding }: { readonly finding: Finding; }) {
  const scanner = finding.scanner;
  if (!scanner || scanner.supports_auto_close) return null;
  if (finding.state !== "open" && finding.state !== "reopened") return null;
  return (
    <p className="text-muted-foreground mt-4 text-body">
      This project closes {scanner.display_name}{" "}
      findings by hand, so a later scan will not close this one. Once it is fixed, ask a project
      manager to record the decision.
    </p>
  );
}
