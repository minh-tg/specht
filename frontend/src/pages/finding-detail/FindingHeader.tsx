import { SeverityBadge } from "@/components/ui/severity-badge";
import { findingKindLabel, technicalStateLabel } from "@/lib/enums";
import { formatAge } from "@/lib/format";
import { type BlocksGateResult } from "@/lib/gate";
import type { Finding } from "@/types/api";
import { WhyItBlocks } from "./WhyItBlocks";

const DAY_MS = 24 * 60 * 60 * 1000;

/** "Open for 4 days", or the state in words once a scan or a deleted report has closed it. */
function openFor(finding: Finding, now: Date = new Date()): string {
  if (finding.state !== "open" && finding.state !== "reopened") {
    return technicalStateLabel(finding.state) ?? "–";
  }
  const days = Math.floor((now.getTime() - new Date(finding.first_seen_at).getTime()) / DAY_MS);
  if (Number.isNaN(days) || days < 1) return "Open since today";
  return `Open for ${days} ${days === 1 ? "day" : "days"}`;
}

/** The kind and age line, the severity and title, and the gate's reason, for one finding. */
export function FindingHeader({
  finding,
  gateResult,
  floor,
}: {
  readonly finding: Finding;
  readonly gateResult: BlocksGateResult | null;
  readonly floor?: string;
}) {
  return (
    <header>
      <p className="font-label text-muted-foreground mb-3 flex flex-wrap items-center gap-x-2.5 text-xs">
        <span>{findingKindLabel(finding.finding_kind) ?? "–"}</span>
        <span aria-hidden="true">·</span>
        <span title={`First seen ${formatAge(finding.first_seen_at)} ago`}>{openFor(finding)}</span>
      </p>
      <div className="flex flex-wrap items-center gap-x-4 gap-y-2">
        <SeverityBadge severity={finding.current_severity} />
        <h1 className="text-[1.625rem] leading-[1.1] font-bold tracking-tight break-words sm:text-3xl">
          {finding.current_title}
        </h1>
      </div>
      <WhyItBlocks
        severity={finding.current_severity}
        gateResult={gateResult}
        floor={floor}
      />
      <div aria-hidden="true" className="page-rule" />
    </header>
  );
}
