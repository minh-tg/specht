import { useProjectAging, useProjectStats } from "@/api/hooks";
import { ErrorState } from "@/components/ErrorState";
import { SkeletonLines } from "@/components/SkeletonLines";
import { buttonVariants } from "@/components/ui/button-variants";
import { SeverityBadge } from "@/components/ui/severity-badge";
import { EMPTY_VALUE, pluralize } from "@/lib/format";
import type { ReactNode } from "react";
import { Link, useParams } from "react-router-dom";
import { BarChart, Sparkline } from "./project-insights/BarChart";
import {
  ageBars,
  daysOverdue,
  severityBars,
  stateBars,
  weeklyCounts,
} from "./project-insights/model";

function Stat({ value, label, alert = false }: {
  readonly value: ReactNode;
  readonly label: string;
  readonly alert?: boolean;
}) {
  return (
    <div className="border-border border-b py-3.5 pr-3.5">
      <div
        className={`text-3xl leading-none font-bold tabular-nums ${
          alert ? "text-sev-critical-fg" : ""
        }`}
      >
        {value}
      </div>
      <div className="text-muted-foreground mt-1.5 text-[0.8125rem]">{label}</div>
    </div>
  );
}

function Block({ title, note, children }: {
  readonly title: string;
  readonly note: string;
  readonly children: ReactNode;
}) {
  return (
    <section className="min-w-0">
      <h3 className="text-base font-semibold">{title}</h3>
      <p className="text-muted-foreground mt-0.5 mb-2.5 text-[0.8125rem]">{note}</p>
      {children}
    </section>
  );
}

/**
 * How a project's open findings stand: how many, how severe, where the triage is, how old, and
 * which are past the date they should have been fixed by. Fixed and archived findings are not counted.
 */
export function ProjectInsights() {
  const { slug } = useParams<{ slug: string; }>();
  const currentSlug = slug ?? "";
  const stats = useProjectStats(currentSlug);
  const aging = useProjectAging(currentSlug);

  if (stats.isLoading) return <SkeletonLines label="Loading insights" />;
  if (stats.isError || !stats.data) {
    return <ErrorState title="Could not load insights." onRetry={() => void stats.refetch()} />;
  }

  const data = stats.data;
  const now = new Date(aging.dataUpdatedAt);
  const agingData = aging.data;

  return (
    <section aria-labelledby="insights-heading" className="grid gap-8">
      <div>
        <h2 id="insights-heading" className="text-lg font-semibold">Insights</h2>
        <p className="text-muted-foreground mt-0.5 text-sm">
          Open findings only. Fixed and archived ones are not counted.
        </p>
      </div>

      <div className="border-foreground grid grid-cols-[repeat(auto-fit,minmax(9.5rem,1fr))] border-t-2">
        <Stat value={data.total_findings} label="open findings" />
        <Stat
          value={data.blocking_count}
          label="block the gate now"
          alert={data.blocking_count > 0}
        />
        <Stat
          value={agingData ? agingData.overdue_total : EMPTY_VALUE}
          label="past their fix date"
        />
        <Stat
          value={data.waiver_count}
          label={data.waiver_count === 1 ? "waiver in force" : "waivers in force"}
        />
      </div>

      {data.total_findings === 0
        ? (
          <p className="text-muted-foreground text-sm">
            No open findings, so there is nothing to chart.
          </p>
        )
        : (
          <div className="grid gap-x-10 gap-y-8 md:grid-cols-2">
            <Block title="By severity" note="Hatched part is what blocks the gate.">
              <BarChart label="Open findings by severity" rows={severityBars(data)} />
            </Block>
            <Block title="By triage state" note="Where the work stands.">
              <BarChart label="Open findings by triage state" rows={stateBars(data)} />
            </Block>
            {aging.isLoading && <SkeletonLines label="Loading ages" />}
            {aging.isError && (
              <div className="md:col-span-2">
                <ErrorState title="Could not load ages." onRetry={() => void aging.refetch()} />
              </div>
            )}
            {agingData && (
              <>
                <Block
                  title="How old"
                  note="Age of open findings. Past the fix date: critical 7 days, high 30, medium 90, low 180."
                >
                  <BarChart label="Open findings by age" rows={ageBars(agingData)} />
                </Block>
                <Block
                  title="New findings per week"
                  note="First seen in each of the last twelve weeks."
                >
                  <Sparkline
                    label="New findings per week"
                    values={weeklyCounts(agingData)}
                    startLabel="12 weeks ago"
                    endLabel="this week"
                  />
                </Block>
              </>
            )}
          </div>
        )}

      {agingData?.truncated && (
        <p className="bg-muted text-muted-foreground rounded-md px-3.5 py-3 text-[0.8125rem]">
          This project has more open findings than the age numbers cover. They count the oldest
          ones.
        </p>
      )}

      {agingData && agingData.overdue.length > 0 && (
        <section aria-labelledby="overdue-heading">
          <h3 id="overdue-heading" className="text-base font-semibold">Past their fix date</h3>
          <ul className="border-foreground m-0 mt-2.5 list-none border-t-2 p-0">
            {agingData.overdue.map((finding) => (
              <li
                key={finding.id}
                className="border-border grid items-start gap-x-5 gap-y-1 border-b px-0.5 py-4 sm:grid-cols-[minmax(0,1fr)_auto]"
              >
                <div className="min-w-0">
                  <p className="font-semibold">{finding.title}</p>
                  <p className="text-muted-foreground mt-1 flex flex-wrap items-center gap-x-2 text-[0.8125rem]">
                    <SeverityBadge severity={finding.severity} plain />
                    <span>· {pluralize(finding.age_days, "day")} old</span>
                    <span>· fix date was {pluralize(daysOverdue(finding, now), "day")} ago</span>
                    {finding.reopened && <span>· reopened</span>}
                  </p>
                </div>
                <Link
                  to={`/${currentSlug}/findings/${finding.id}`}
                  aria-label={`Open ${finding.title}`}
                  className={buttonVariants({ variant: "outline", size: "sm" })}
                >
                  Open
                </Link>
              </li>
            ))}
          </ul>
          {agingData.overdue_total > agingData.overdue.length && (
            <p className="text-muted-foreground mt-2 text-[0.8125rem]">
              Showing the oldest {agingData.overdue.length} of {agingData.overdue_total}.
            </p>
          )}
        </section>
      )}
    </section>
  );
}
