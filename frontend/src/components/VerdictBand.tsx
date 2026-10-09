import { useGateStatus, useMe, useProjectStats } from "@/api/hooks";
import { InfoTip } from "@/components/InfoTip";
import { SeverityBadge } from "@/components/ui/severity-badge";
import { Skeleton } from "@/components/ui/skeleton";
import { VerdictBadge } from "@/components/VerdictBadge";
import { SEVERITIES, severityLabel } from "@/lib/enums";
import { formatDateTime, formatRelativeTime, pluralize } from "@/lib/format";
import {
  blockerCount,
  degradedMessage,
  isDegraded,
  projectVerdict,
  triageBuckets,
  type Verdict,
} from "@/lib/verdict";
import { Link } from "react-router-dom";

/** Plain-language verdict line; unknown is resolved before this point. */
function verdictSentence(verdict: Verdict, blockers: number): string {
  switch (verdict) {
    case "blocked":
      return `${pluralize(blockers, "finding")} ${
        blockers === 1 ? "blocks" : "block"
      } this project`;
    case "passing":
      return "Nothing blocks this project";
    case "no_scans":
      return "No scans yet";
    case "unknown":
      return "";
  }
}

/**
 * Project header band: verdict, policy floor, last scan and finding counters.
 *
 * The container reserves the same vertical rhythm while the gate and stats
 * load, so the tab nav below never jumps when the verdict resolves.
 */
export function VerdictBand({ slug }: { readonly slug: string; }) {
  const gateQuery = useGateStatus(slug);
  const statsQuery = useProjectStats(slug);
  const { data: me } = useMe();

  const gate = gateQuery.data;
  const stats = statsQuery.data;
  const verdict = projectVerdict({ gate, stats });
  const isAdmin = me?.role === "admin";
  const blockers = blockerCount(gate);
  const waived = gate?.waived_count ?? 0;
  const policy = gate?.policy;
  const latest = stats?.latest_report;

  // A failed request never delivers data, so `unknown` must not animate a
  // skeleton forever: an errored, still-empty query is the error state.
  const gateFailed = gateQuery.isError && gate === undefined;
  const statsFailed = statsQuery.isError && stats === undefined;
  const gatePending = gateQuery.isPending && gate === undefined;
  const statsPending = statsQuery.isPending && stats === undefined;

  if (gateFailed || statsFailed) {
    return (
      <section aria-label="Gate verdict" className="rounded-lg border p-4">
        <div className="flex flex-wrap items-center gap-2">
          <VerdictBadge verdict="unknown" />
          <p role="alert">{"Couldn't load the verdict."}</p>
          <button
            type="button"
            className="text-action text-sm underline underline-offset-2 hover:no-underline"
            onClick={() => {
              if (gateQuery.isError) void gateQuery.refetch();
              if (statsQuery.isError) void statsQuery.refetch();
            }}
          >
            Retry
          </button>
        </div>
      </section>
    );
  }

  // Only a query that is still pending without an error earns the skeleton.
  if (verdict === "unknown" && (gatePending || statsPending)) {
    return (
      <section aria-label="Gate verdict" aria-busy="true" className="rounded-lg border p-4">
        <div className="flex items-center gap-2">
          <VerdictBadge verdict="unknown" />
          <Skeleton className="h-4 w-48 rounded" />
        </div>
        <Skeleton className="mt-2 h-4 w-72 max-w-full rounded" />
        <div className="mt-3 flex gap-2">
          <Skeleton className="h-5 w-16 rounded" />
          <Skeleton className="h-5 w-16 rounded" />
          <Skeleton className="h-5 w-16 rounded" />
        </div>
      </section>
    );
  }

  const severityCounts = new Map((stats?.by_severity ?? []).map((s) => [s.severity, s.count]));
  const severityChips = SEVERITIES
    .map((severity) => ({ severity, count: severityCounts.get(severity) ?? 0 }))
    .filter(({ count }) => count > 0);

  const buckets = triageBuckets(stats?.by_analysis_state);
  const triageCounts = buckets
    ? [
      { label: "Needs triage", count: buckets.needsTriage },
      { label: "Exploitable", count: buckets.exploitable },
      { label: "Dismissed", count: buckets.dismissed },
    ].filter(({ count }) => count > 0)
    : [];
  const hasCounters = severityChips.length > 0 || triageCounts.length > 0;

  const showFloor = policy !== undefined;
  const showScan = latest !== undefined;

  return (
    <section aria-label="Gate verdict" className="rounded-lg border p-4">
      {isDegraded(stats) && (
        <p
          role="alert"
          className="border-destructive text-destructive mb-3 rounded border px-3 py-2 text-sm"
        >
          {degradedMessage(stats)}
        </p>
      )}

      <div className="flex flex-wrap items-center gap-2">
        <VerdictBadge verdict={verdict} />
        <p role="status">{verdictSentence(verdict, blockers)}</p>
        {waived > 0 && <span className="text-muted-foreground text-sm">· {waived} waived</span>}
        {isAdmin && (
          <Link
            to={`/${slug}/setup`}
            className="text-muted-foreground hover:text-foreground ml-auto text-xs"
          >
            CI setup
          </Link>
        )}
      </div>

      {(showFloor || showScan) && (
        <p className="text-muted-foreground mt-1 text-sm">
          {policy && (
            <span>
              Floor: {policy.severity_floor} ({policy.severity_source})
              <InfoTip term="severityFloor" className="ml-1" />
            </span>
          )}
          {policy && showScan && " · "}
          {latest && (
            <span title={formatDateTime(latest.created_at)}>
              Last scan {formatRelativeTime(latest.created_at)}
              {latest.tool_name ? ` · ${latest.tool_name}` : ""}
            </span>
          )}
        </p>
      )}

      {verdict === "no_scans" && (
        <p className="text-muted-foreground mt-2 text-sm">
          Upload a report or send one from CI.{" "}
          <Link
            to={`/${slug}/reports/upload`}
            className="text-action underline underline-offset-2 hover:no-underline"
          >
            Upload a report
          </Link>
          {isAdmin && (
            <>
              {" · "}
              <Link
                to={`/${slug}/setup`}
                className="text-action underline underline-offset-2 hover:no-underline"
              >
                Set up CI
              </Link>
            </>
          )}
        </p>
      )}

      {hasCounters && (
        <div className="mt-3 flex flex-wrap items-center gap-x-3 gap-y-2">
          {severityChips.map(({ severity, count }) => (
            <Link
              key={severity}
              to={`/${slug}/findings?severity=${severity}`}
              aria-label={pluralize(count, `${severityLabel(severity)?.toLowerCase()} finding`)}
              className="inline-flex items-center gap-1"
            >
              <SeverityBadge severity={severity} />
              <span className="text-sm">{count}</span>
            </Link>
          ))}
          {triageCounts.map(({ label, count }) => (
            <span key={label} className="text-muted-foreground text-sm">
              {label} {count}
            </span>
          ))}
        </div>
      )}
    </section>
  );
}
