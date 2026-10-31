import { findingQueryOptions, useWaivers } from "@/api/hooks";
import { INLINE_LINK } from "@/components/inlineLink";
import { buttonVariants } from "@/components/ui/button-variants";
import { Skeleton } from "@/components/ui/skeleton";
import { pluralize } from "@/lib/format";
import { BlockerRow } from "@/pages/change-view/BlockerRow";
import { MAX_BLOCKER_ROWS } from "@/pages/change-view/BlockerSection";
import {
  type Cause,
  causeText,
  explainCleared,
  type PreviousBlockers,
  scanCoverage,
} from "@/pages/change-view/cleared";
import type { GateStatus, Report, Waiver } from "@/types/api";
import { useQuery } from "@tanstack/react-query";
import { type ReactNode, useState } from "react";
import { Link } from "react-router-dom";

const ROW = "flex items-start gap-3 border-t py-3.5";

function Mark({ cleared }: { readonly cleared: boolean; }) {
  return (
    <svg
      width="18"
      height="18"
      viewBox="0 0 16 16"
      fill="none"
      stroke="currentColor"
      strokeWidth="1.8"
      aria-hidden="true"
      className={cleared
        ? "text-verdict-pass mt-px flex-none"
        : "text-muted-foreground mt-px flex-none"}
    >
      {cleared ? <path d="M3 8.5l3.2 3L13 4.5" /> : <path d="M4 8h8" />}
    </svg>
  );
}

/** Whether a cause is a real clearing (fixed, waived, dismissed) or only a gate that stopped counting it. */
function isCleared(cause: Cause): boolean {
  return cause.kind !== "archived" && cause.kind !== "uncounted";
}

function ClearedRow(
  { slug, findingId, earlierGate, gate, waivers, now }: {
    readonly slug: string;
    readonly findingId: string;
    readonly earlierGate?: GateStatus;
    readonly gate?: GateStatus;
    readonly waivers: readonly Waiver[];
    readonly now: Date;
  },
) {
  // A copy from the blocked page predates the fix, so this read always goes to the server.
  const query = useQuery({ ...findingQueryOptions(findingId), staleTime: 0 });
  if (query.isPending) {
    return (
      <li className={ROW} aria-busy="true">
        <Skeleton className="h-4 w-1/2 rounded" />
      </li>
    );
  }
  if (query.isError || !query.data) {
    return (
      <li className={ROW}>
        <span className="grid">
          <span className="text-body">Could not load this finding</span>
          <button
            type="button"
            className={`${INLINE_LINK} text-start text-body`}
            onClick={() => void query.refetch()}
          >
            Retry
          </button>
        </span>
      </li>
    );
  }
  const cause = explainCleared(query.data, { earlierGate, gate, waivers, now });
  return (
    <li className={ROW}>
      <Mark cleared={isCleared(cause)} />
      <span className="grid min-w-0">
        <Link
          to={`/${slug}/findings/${findingId}`}
          className="text-body font-semibold hover:underline"
        >
          {query.data.current_title}
        </Link>
        <span className="text-muted-foreground text-meta">{causeText(cause)}</span>
      </span>
    </li>
  );
}

export interface ClearedEndProps {
  readonly slug: string;
  readonly projectName?: string;
  /** The passing report. */
  readonly report: Report;
  /** The passing scan's gate. */
  readonly gate: GateStatus;
  readonly earlierGate: GateStatus;
  readonly previous: PreviousBlockers;
  /** Earlier blockers that are open and still block the earlier scan. Empty when all cleared. */
  readonly openIds: readonly string[];
  /** Rendered between the lists and the way back, for the older findings of the project. */
  readonly children?: ReactNode;
}

/**
 * What became of the findings that blocked the earlier scan. Anything still open is listed first
 * and says the passing verdict did not examine it; the rest each say how they cleared, from the
 * finding's state, the gate's waivers and the analysis state, and nothing more.
 */
export function ClearedEnd(
  { slug, projectName, report, gate, earlierGate, previous, openIds, children }: ClearedEndProps,
) {
  const [showAll, setShowAll] = useState(false);
  const [now] = useState(() => new Date());
  const waiversQuery = useWaivers(slug, ["approved"]);
  const waivers = waiversQuery.data ?? [];
  const open = new Set(openIds);
  const rest = previous.ids.filter((id) => !open.has(id));
  const shown = showAll ? rest : rest.slice(0, MAX_BLOCKER_ROWS);
  const coverage = scanCoverage(report);

  return (
    <>
      {openIds.length > 0 && (
        <section aria-labelledby="still-open-h" className="mt-8 grid gap-2">
          <h2 id="still-open-h" className="text-section leading-tight font-semibold">
            Still open from the earlier scan
          </h2>
          <p className="max-w-[68ch] text-body">
            The passing verdict did not examine{" "}
            {openIds.length === 1 ? "this finding" : "these findings"}.{" "}
            {openIds.length === 1 ? "It is" : "They are"}{" "}
            open and would still block the earlier scan. Fix {openIds.length === 1 ? "it" : "each"}
            {" "}
            or ask for a waiver, then send a fresh scanner report.
          </p>
          <ul className="bg-card rounded-lg border" aria-label="Findings still open">
            {openIds.map((id) => <BlockerRow key={id} slug={slug} findingId={id} />)}
          </ul>
        </section>
      )}
      {rest.length > 0 && (
        <section aria-labelledby="cleared-h" className="mt-8 grid">
          <h2 id="cleared-h" className="mb-1.5 text-section leading-tight font-semibold">
            {openIds.length > 0 ? "What cleared the rest" : "What cleared it"}
          </h2>
          <ul aria-label={`${pluralize(rest.length, "finding")} that blocked the earlier scan`}>
            {shown.map((id) => (
              <ClearedRow
                key={id}
                slug={slug}
                findingId={id}
                earlierGate={earlierGate}
                gate={gate}
                waivers={waivers}
                now={now}
              />
            ))}
          </ul>
          {shown.length < rest.length && (
            <button
              type="button"
              className={`${INLINE_LINK} mt-2 text-start text-body`}
              onClick={() => setShowAll(true)}
            >
              Show all {rest.length}
            </button>
          )}
        </section>
      )}
      <p className="text-muted-foreground mt-6 max-w-[68ch] text-meta">
        <span className="text-foreground font-medium">What this scan covered.</span> {coverage.text}
      </p>
      {children}
      <Link
        to={`/${slug}/findings`}
        className={`${buttonVariants({ variant: "outline" })} mt-6 w-fit no-underline`}
      >
        Back to {projectName ?? slug}
      </Link>
    </>
  );
}
