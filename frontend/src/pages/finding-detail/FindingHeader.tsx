import { SeverityBadge } from "@/components/ui/severity-badge";
import { findingKindLabel } from "@/lib/enums";
import { type BlocksGateResult, blocksGateSentence } from "@/lib/gate";
import type { Finding } from "@/types/api";
import { ShieldCheck } from "lucide-react";
import type { ReactNode } from "react";

/** Severity, kind, gate verdict and title for one finding. */
export function FindingHeader({
  finding,
  gateResult,
}: {
  readonly finding: Finding;
  readonly gateResult: BlocksGateResult | null;
}) {
  let gateChip: ReactNode = null;
  if (gateResult?.blocks) {
    gateChip = (
      <span className="bg-sev-critical-bg text-sev-critical-fg rounded-sm px-1.5 py-0.5 text-xs font-medium">
        {blocksGateSentence(gateResult)}
      </span>
    );
  } else if (gateResult?.reason === "waived") {
    gateChip = (
      <span className="inline-flex items-center gap-1 rounded-sm border px-1.5 py-0.5 text-xs font-medium text-foreground">
        <ShieldCheck className="size-3" aria-hidden="true" />
        {blocksGateSentence(gateResult)}
      </span>
    );
  } else if (gateResult) {
    gateChip = (
      <span className="inline-flex items-center rounded-sm border px-1.5 py-0.5 text-xs font-medium text-muted-foreground">
        {blocksGateSentence(gateResult)}
      </span>
    );
  }

  return (
    <div className="mb-6">
      <div className="mb-2 flex items-center gap-3">
        <SeverityBadge severity={finding.current_severity} />
        <span className="text-muted-foreground text-xs">
          {findingKindLabel(finding.finding_kind) ?? "–"}
        </span>
        {gateChip}
      </div>
      <h1 className="text-2xl font-bold break-words">{finding.current_title}</h1>
    </div>
  );
}
