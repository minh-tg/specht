import { InfoTip } from "@/components/InfoTip";
import { Skeleton } from "@/components/ui/skeleton";
import { VerdictBadge } from "@/components/VerdictBadge";
import { formatDateTime, formatRelativeTime, pluralize } from "@/lib/format";
import { floorSourceLabel, shortCommit } from "@/pages/change-view/resolve";
import type { PolicyEffective, Report } from "@/types/api";
import type { ReactNode } from "react";

/**
 * What the header says about the change. `scanning` is a newer push being scanned while the page
 * waits; `processing` and `failed` describe the scan this page is about. None of them claims a
 * verdict the evidence does not support.
 */
export type ChangeState = "blocked" | "passing" | "scanning" | "processing" | "failed";

export interface ChangeHeroProps {
  readonly commit: string;
  readonly report: Report | null;
  readonly state: ChangeState;
  /** Findings this change introduced that block it. */
  readonly blockers: number;
  /** Findings that block the project but not through this change. */
  readonly existing: number;
  readonly waived: number;
  readonly policy?: PolicyEffective;
}

function headline(state: ChangeState, blockers: number): string {
  switch (state) {
    case "blocked":
      return `${pluralize(blockers, "finding")} ${
        blockers === 1 ? "blocks" : "block"
      } this change.`;
    case "passing":
      return "This change introduces no blocking findings.";
    case "scanning":
      return "Scanning your push.";
    case "processing":
      return "This scan is still processing.";
    case "failed":
      return "This scan did not complete.";
  }
}

function subline(state: ChangeState, report: Report | null): string {
  switch (state) {
    case "blocked":
      return "Fix them or request a waiver, then push. Specht re-scans on its own.";
    case "passing":
      return "Nothing in it stops the merge. Only a scan can change that.";
    case "scanning":
      return "The verdict updates when the scan finishes.";
    case "processing":
      return "There is no verdict until it finishes.";
    case "failed":
      return report?.error_message ?? "Check the CI job, then push again.";
  }
}

/** Verdict of the stamp for a header state. */
function stampFor(
  state: ChangeState,
): { verdict: "blocked" | "passing" | "unknown"; scanning: boolean; } {
  switch (state) {
    case "blocked":
      return { verdict: "blocked", scanning: false };
    case "passing":
      return { verdict: "passing", scanning: false };
    case "scanning":
    case "processing":
      return { verdict: "unknown", scanning: true };
    case "failed":
      return { verdict: "unknown", scanning: false };
  }
}

/**
 * The header of the change page: the verdict stamp beside one sentence, one quiet line of facts, and
 * the page rule. The stamp is the only solid block on the page, so the verdict is the first thing seen.
 */
export function ChangeHero(
  { commit, report, state, blockers, existing, waived, policy }: ChangeHeroProps,
) {
  const stamp = stampFor(state);
  const branch = report?.branch;
  return (
    <section aria-label="Change verdict" aria-live="polite">
      <p className="font-label text-muted-foreground mb-3.5 flex flex-wrap items-center gap-x-2.5 text-xs">
        <span>Change</span>
        <code className="text-foreground text-[13px]">{shortCommit(commit)}</code>
        {branch && (
          <>
            <span aria-hidden="true">·</span>
            <code className="text-foreground text-[13px]">{branch}</code>
          </>
        )}
      </p>
      <div className="grid items-center gap-x-6 gap-y-2 max-md:justify-items-start md:grid-cols-[auto_minmax(0,1fr)]">
        <VerdictBadge verdict={stamp.verdict} scanning={stamp.scanning} size="lg" />
        <div className="grid min-w-0 gap-1.5">
          <h1 className="text-[1.625rem] leading-[1.1] font-bold tracking-tight text-balance sm:text-3xl">
            {headline(state, blockers)}
          </h1>
          <p className="max-w-[58ch] text-lg leading-snug">{subline(state, report)}</p>
        </div>
      </div>
      <p className="text-muted-foreground mt-4 flex flex-wrap items-center gap-x-0 gap-y-1 text-[13px] max-sm:grid max-sm:gap-0.5">
        {policy && (
          <FactItem>
            Severity floor{" "}
            <span className="text-foreground font-medium">{policy.severity_floor}</span>{" "}
            <span className="text-muted-foreground">
              (from {floorSourceLabel(policy.severity_source)})
            </span>
            <InfoTip term="severityFloor" className="ml-1" />
          </FactItem>
        )}
        {state === "blocked" && (
          <FactItem>
            <strong className="text-foreground font-semibold">{blockers}</strong> blocking
            {existing > 0 && <>, {existing} existing</>}
          </FactItem>
        )}
        {waived > 0 && <FactItem>{waived} waived</FactItem>}
        {report && (
          <FactItem>
            <span title={formatDateTime(report.created_at)}>
              Scanned {formatRelativeTime(report.created_at)}
            </span>
            {report.tool_name ? ` from a ${report.tool_name} report` : ""}
          </FactItem>
        )}
      </p>
      <div aria-hidden="true" className="page-rule" />
    </section>
  );
}

function FactItem({ children }: { readonly children: ReactNode; }) {
  return (
    <span className="after:text-muted-foreground after:mx-2.5 after:content-['·'] last:after:content-none max-sm:after:content-none">
      {children}
    </span>
  );
}

/** The header while the page waits for the report or the gate. */
export function ChangeHeroSkeleton({ commit }: { readonly commit: string; }) {
  return (
    <section aria-label="Change verdict" aria-busy="true">
      <p className="font-label text-muted-foreground mb-3.5 text-xs">
        Change <code className="text-foreground text-[13px]">{shortCommit(commit)}</code>
      </p>
      <div className="flex items-center gap-6">
        <Skeleton className="h-10 w-28 rounded-lg" />
        <Skeleton className="h-8 w-72 max-w-full rounded" />
      </div>
      <div aria-hidden="true" className="page-rule" />
    </section>
  );
}
