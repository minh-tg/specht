import { InfoTip } from "@/components/InfoTip";
import { RelativeTime } from "@/components/RelativeTime";
import { Skeleton } from "@/components/ui/skeleton";
import { VerdictBadge } from "@/components/VerdictBadge";
import { pluralize } from "@/lib/format";
import { useDelayedFlag } from "@/lib/useDelayedFlag";
import { floorSourceLabel, shortCommit } from "@/pages/change-view/resolve";
import type { PolicyEffective, Report } from "@/types/api";
import type { ReactNode } from "react";

/**
 * What the header says about the change. `scanning` is a newer report being processed while the page
 * waits; `processing` and `failed` describe the scan this page is about. `unblocked` is a passing
 * scan after one that blocked, with every earlier blocker accounted for; `unconfirmed` is a passing
 * scan while some earlier blocker is still open. None of them claims a verdict the evidence does
 * not support.
 */
export type ChangeState =
  | "blocked"
  | "passing"
  | "unblocked"
  | "unconfirmed"
  | "scanning"
  | "processing"
  | "failed";

export interface ChangeHeroProps {
  readonly commit: string;
  readonly report: Report | null;
  readonly state: ChangeState;
  /** Findings this change introduced that block it. */
  readonly blockers: number;
  /** Findings that block the project but not through this change. */
  readonly existing: number;
  readonly waived: number;
  /** For `unconfirmed`: how many earlier blockers are still open. */
  readonly earlierOpen?: number;
  readonly policy?: PolicyEffective;
  readonly projectWide?: boolean;
  /** The project's gate mode keeps this breach from failing CI. */
  readonly reportOnly?: boolean;
  /** Under the verdict sentence: the strip that says the page is watching for the scan. */
  readonly watch?: ReactNode;
  /** Between the verdict and the facts: why the verdict may not be current. */
  readonly notice?: ReactNode;
}

/** "high" as "High", for a sentence that names the severity floor. */
function floorWord(policy: PolicyEffective | undefined): string | null {
  const floor = policy?.severity_floor;
  return floor ? floor.charAt(0).toUpperCase() + floor.slice(1) : null;
}

function headline(
  state: ChangeState,
  blockers: number,
  projectWide: boolean,
  commit: string,
  earlierOpen: number,
  reportOnly: boolean,
): string {
  switch (state) {
    case "blocked":
      if (reportOnly) {
        return `${pluralize(blockers, "finding")} would block this ${
          projectWide ? "project" : "change"
        }.`;
      }
      return `${pluralize(blockers, "finding")} ${blockers === 1 ? "blocks" : "block"} this ${
        projectWide ? "project" : "change"
      }.`;
    case "passing":
      return projectWide
        ? "Project gate passed."
        : "Nothing new in this commit blocks this change.";
    case "unblocked":
      return "Unblocked. Nothing blocks this change now.";
    case "unconfirmed":
      return `Passed, but ${pluralize(earlierOpen, "earlier blocker")} ${
        earlierOpen === 1 ? "is" : "are"
      } still open.`;
    case "scanning":
      return "A newer report is processing.";
    case "processing":
      return `The scan of ${shortCommit(commit)} is still being processed.`;
    case "failed":
      return "This scan did not complete.";
  }
}

function subline(
  state: ChangeState,
  report: Report | null,
  projectWide: boolean,
  commit: string,
  policy: PolicyEffective | undefined,
  waived: number,
  reportOnly: boolean,
): string {
  switch (state) {
    case "blocked":
      return reportOnly
        ? "This project only reports for now, so CI is not failing. A project admin can turn blocking on in Policy."
        : "Fix the findings and send a fresh scanner report, or request a waiver.";
    case "passing":
      if (projectWide) return "No project findings block this gate at the selected severity floor.";
      return `No new finding at ${
        floorWord(policy) ?? "the severity floor"
      } or above is left blocking this change in the scan of ${shortCommit(commit)}.${
        waived > 0
          ? ` The ${pluralize(waived, "waived finding")} ${waived === 1 ? "does" : "do"} not count.`
          : ""
      } Nothing to do here.`;
    case "unblocked":
      return "Specht works out this verdict now, from the report on this page and today's findings and waivers, so it counts anything waived or decided since the scan uploaded. The check CI posted for an older run does not update; re-run the job if it still shows failed.";
    case "unconfirmed":
      return "This verdict counts only the findings this scan introduced. The findings below blocked the earlier scan and are still open.";
    case "scanning":
      return "The verdict updates when the scan finishes.";
    case "processing":
      return "There is no verdict until it finishes. This page shows it as soon as it does; you do not need to reload.";
    case "failed":
      return report?.error_message ?? "Check your scanner or CI job, then send a fresh report.";
  }
}

/** Verdict of the stamp for a header state. */
function stampFor(
  state: ChangeState,
  reportOnly: boolean,
): { verdict: "blocked" | "would_block" | "passing" | "unknown"; scanning: boolean; } {
  switch (state) {
    case "blocked":
      return { verdict: reportOnly ? "would_block" : "blocked", scanning: false };
    case "passing":
    case "unblocked":
    case "unconfirmed":
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
  {
    commit,
    report,
    state,
    blockers,
    existing,
    waived,
    earlierOpen = 0,
    policy,
    projectWide = false,
    reportOnly = false,
    watch,
    notice,
  }: ChangeHeroProps,
) {
  const stamp = stampFor(state, reportOnly);
  const branch = report?.branch;
  return (
    <section aria-label="Change verdict" aria-live="polite">
      <p className="font-label text-muted-foreground mb-3.5 flex flex-wrap items-center gap-x-2.5 text-label">
        <span>Change</span>
        <code className="text-foreground text-code normal-case">{shortCommit(commit)}</code>
        {branch && (
          <>
            <span aria-hidden="true">·</span>
            <code className="text-foreground min-w-0 text-code normal-case [overflow-wrap:anywhere]">
              {branch}
            </code>
          </>
        )}
      </p>
      <div className="grid items-center gap-x-6 gap-y-2 max-md:justify-items-start md:grid-cols-[auto_minmax(0,1fr)]">
        <VerdictBadge verdict={stamp.verdict} scanning={stamp.scanning} size="lg" />
        <div className="grid min-w-0 gap-1.5">
          <h1 className="text-title font-bold text-balance">
            {headline(state, blockers, projectWide, commit, earlierOpen, reportOnly)}
          </h1>
          <p className="max-w-[58ch] text-section font-normal leading-snug">
            {subline(state, report, projectWide, commit, policy, waived, reportOnly)}
          </p>
          {watch}
        </div>
      </div>
      {notice}
      <p className="text-muted-foreground mt-4 flex flex-wrap items-center gap-x-0 gap-y-1 text-meta tabular-nums max-sm:grid max-sm:gap-0.5">
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
            {existing > 0 && <>, {existing} already on the default branch</>}
          </FactItem>
        )}
        {waived > 0 && <FactItem>{waived} waived</FactItem>}
        {report && (
          <FactItem>
            <span>
              Report received <RelativeTime iso={report.created_at} frozen />
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

/**
 * The header while the page waits for the report or the gate. It stays empty for the first 300 ms,
 * so a quick answer never flashes a skeleton, and then says what it is loading.
 */
export function ChangeHeroSkeleton({ commit }: { readonly commit: string; }) {
  const visible = useDelayedFlag(LOADING_DELAY_MS);
  if (!visible) return null;
  return (
    <section aria-label="Change verdict" aria-busy="true">
      <p className="font-label text-muted-foreground mb-3.5 text-label">
        Change <code className="text-foreground text-code">{shortCommit(commit)}</code>
      </p>
      <div className="flex items-center gap-6">
        <Skeleton className="h-10 w-28 rounded-lg" />
        <Skeleton className="h-8 w-72 max-w-full rounded" />
      </div>
      <p role="status" className="text-muted-foreground mt-3 text-meta">
        Loading the verdict for {shortCommit(commit)}…
      </p>
      <div aria-hidden="true" className="page-rule" />
    </section>
  );
}

/** How long the page shows nothing before it shows a loading skeleton. */
export const LOADING_DELAY_MS = 300;
