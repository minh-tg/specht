import { VerdictBadge } from "@/components/VerdictBadge";
import { pluralize } from "@/lib/format";
import type { Verdict } from "@/lib/verdict";
import { floorSourceLabel } from "@/pages/change-view/resolve";
import type { PolicyEffective } from "@/types/api";

export type ChangeVerdictKind = "blocked" | "passing" | "no_verdict";

const BADGE: Record<ChangeVerdictKind, Verdict> = {
  blocked: "blocked",
  passing: "passing",
  no_verdict: "unknown",
};

/** Plain-language header sentence; the badge already carries the verdict word. */
function verdictSentence(kind: ChangeVerdictKind, blockers: number): string {
  switch (kind) {
    case "blocked":
      return `${pluralize(blockers, "finding")} ${blockers === 1 ? "blocks" : "block"} this change`;
    case "passing":
      return "this change introduces no blocking findings";
    case "no_verdict":
      return "this scan did not complete";
  }
}

/** Spoken form of the header, with the verdict word the visible badge shows. */
function verdictLabel(kind: ChangeVerdictKind, blockers: number): string {
  switch (kind) {
    case "blocked":
      return `BLOCKED — ${verdictSentence(kind, blockers)}`;
    case "passing":
      return `PASSING — ${verdictSentence(kind, blockers)}`;
    case "no_verdict":
      return `NO VERDICT — ${verdictSentence(kind, blockers)}`;
  }
}

export interface ChangeVerdictProps {
  kind: ChangeVerdictKind;
  blockers: number;
  waived: number;
  policy?: PolicyEffective;
  loading?: boolean;
}

/**
 * Verdict block for one change. Degraded evidence is announced by the caller
 * above this block, so the header never claims passing while a scan is still
 * running or has failed.
 */
export function ChangeVerdict(
  { kind, blockers, waived, policy, loading }: ChangeVerdictProps,
) {
  if (loading) {
    return (
      <section aria-label="Change verdict" aria-busy="true" className="rounded-lg border p-4">
        <div className="flex items-center gap-2">
          <span className="bg-muted h-5 w-20 animate-pulse rounded" />
          <span className="bg-muted h-4 w-64 max-w-full animate-pulse rounded" />
        </div>
        <div className="bg-muted mt-2 h-4 w-48 max-w-full animate-pulse rounded" />
      </section>
    );
  }

  const showFloor = policy !== undefined || waived > 0;

  return (
    <section
      aria-label="Change verdict"
      aria-live="polite"
      className="rounded-lg border p-4"
    >
      <h2
        aria-label={verdictLabel(kind, blockers)}
        className="flex flex-wrap items-center gap-2 text-lg font-semibold"
      >
        <VerdictBadge verdict={BADGE[kind]} />
        <span>{verdictSentence(kind, blockers)}</span>
      </h2>
      {showFloor && (
        <p className="text-muted-foreground mt-1 text-sm">
          {policy && (
            <span>
              Floor: {policy.severity_floor} (from {floorSourceLabel(policy.severity_source)})
            </span>
          )}
          {policy && waived > 0 && " · "}
          {waived > 0 && <span>{waived} waived</span>}
        </p>
      )}
    </section>
  );
}
