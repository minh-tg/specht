import { useNeedsYou } from "@/api/hooks";
import { ErrorState } from "@/components/ErrorState";
import { INLINE_LINK, TOUCH_TARGET } from "@/components/inlineLink";
import { RelativeTime } from "@/components/RelativeTime";
import { SkeletonLines } from "@/components/SkeletonLines";
import { SeverityBadge } from "@/components/ui/severity-badge";
import { formatDateTime } from "@/lib/format";
import type { NeedsYou as NeedsYouData, NeedsYouItem } from "@/types/api";
import { Link } from "react-router-dom";

interface Group {
  readonly kind: NeedsYouItem["kind"];
  readonly title: string;
  /** What the time on a row says. */
  readonly timeLabel: string;
  /** Where the items the list leaves out can be found. */
  readonly rest: string;
}

const ON_WAIVERS = "The rest are on each project's Waivers page.";

// The order is the order of urgency: a request blocks someone now, a waiver ending blocks
// findings soon, an assigned finding is the person's own work, and an answer is news.
const GROUPS: readonly Group[] = [
  {
    kind: "waiver_to_decide",
    title: "Waiver requests to decide",
    timeLabel: "Asked",
    rest: ON_WAIVERS,
  },
  { kind: "waiver_ending", title: "Waivers ending soon", timeLabel: "Ends", rest: ON_WAIVERS },
  {
    kind: "finding_assigned",
    title: "Assigned to you",
    timeLabel: "Last seen",
    rest: "The rest are in each project's findings list.",
  },
  {
    kind: "request_decided",
    title: "Answers to your requests",
    timeLabel: "Answered",
    rest: ON_WAIVERS,
  },
];

const ANSWER_WORDS: Record<NonNullable<NeedsYouItem["status"]>, string> = {
  approved: "Approved",
  rejected: "Rejected",
  expired: "Expired without an answer",
};

/** Everything that waits on the signed-in person, across their projects. */
export function NeedsYou() {
  const needs = useNeedsYou();

  return (
    <div className="mx-auto max-w-3xl space-y-8 px-4 py-8">
      <div>
        <h1 className="text-title font-bold">Needs you</h1>
        <p className="text-muted-foreground mt-1 text-body">
          Waiver requests to decide, answers to your own, waivers about to end and findings assigned
          to you.
        </p>
      </div>
      {needs.isError && !needs.data
        ? (
          <ErrorState
            title="Could not load what needs you."
            onRetry={() => void needs.refetch()}
          />
        )
        : needs.data
        ? <Lists items={needs.data.items} totals={needs.data.totals} />
        : <SkeletonLines label="Loading what needs you" lines={5} />}
    </div>
  );
}

function Lists(
  { items, totals }: {
    readonly items: readonly NeedsYouItem[];
    readonly totals: NeedsYouData["totals"];
  },
) {
  if (items.length === 0) {
    return (
      <div className="border-border border-t pt-6" role="status">
        <p className="text-body font-semibold">Nothing waits on you</p>
        <p className="text-muted-foreground mt-1 text-body">
          A waiver request, an answer or an assigned finding shows here when there is one.
        </p>
      </div>
    );
  }
  return (
    <div className="space-y-8">
      {GROUPS.map((group) => {
        const rows = items.filter((item) => item.kind === group.kind);
        if (rows.length === 0) return null;
        // The server lists at most 50 of a kind and counts them all.
        const total = Math.max(totals[group.kind], rows.length);
        return (
          <section
            key={group.kind}
            aria-labelledby={`needs-${group.kind}`}
            className="border-foreground grid gap-3 border-t-2 pt-5"
          >
            <h2 id={`needs-${group.kind}`} className="text-section font-semibold">
              {group.title}
              <span className="text-muted-foreground ml-2 text-body font-normal tabular-nums">
                {total}
              </span>
            </h2>
            <ul className="divide-border divide-y">
              {rows.map((item) => (
                <Row
                  key={`${item.link}:${item.title}:${item.at}`}
                  item={item}
                  group={group}
                />
              ))}
            </ul>
            {total > rows.length && (
              <p className="text-muted-foreground text-body">
                Showing {rows.length} of {total}. {group.rest}
              </p>
            )}
          </section>
        );
      })}
    </div>
  );
}

/** A waiver is stored as "Waiver request: <finding>". The group's heading already says what it is. */
function plainTitle(title: string): string {
  return title.replace(/^Waiver request: /, "");
}

function Row({ item, group }: { readonly item: NeedsYouItem; readonly group: Group; }) {
  const answer = item.status ? ANSWER_WORDS[item.status] : null;
  return (
    <li className="grid gap-1 py-3">
      <div className="flex flex-wrap items-center gap-x-3 gap-y-1">
        {item.severity && <SeverityBadge severity={item.severity} />}
        <Link
          to={item.link}
          className={`${INLINE_LINK} ${TOUCH_TARGET} min-w-0 text-body font-semibold [overflow-wrap:anywhere]`}
        >
          {plainTitle(item.title)}
        </Link>
      </div>
      {answer && (
        <p className="text-body">
          <span className="font-semibold">{answer}</span>
          {item.detail ? `: ${item.detail}` : ""}
        </p>
      )}
      {!answer && item.detail && (
        <p className="text-muted-foreground text-body [overflow-wrap:anywhere]">{item.detail}</p>
      )}
      <p className="text-muted-foreground text-meta">
        {item.project_name || item.project_slug} · {group.timeLabel}{" "}
        {/* A future time has no relative form: "just now" would be wrong for a waiver that ends. */}
        {item.kind === "waiver_ending"
          ? <time dateTime={item.at} className="tabular-nums">{formatDateTime(item.at)}</time>
          : <RelativeTime iso={item.at} />}
      </p>
    </li>
  );
}
