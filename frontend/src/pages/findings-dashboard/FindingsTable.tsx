import { SeverityBadge } from "@/components/ui/severity-badge";
import { analysisStateLabel, findingKindLabel, technicalStateLabel } from "@/lib/enums";
import { formatDate } from "@/lib/format";
import { blocksGate, blocksGateLabel } from "@/lib/gate";
import type { Finding, GateStatus } from "@/types/api";
import { type MouseEvent } from "react";
import { Link, useLocation, useNavigate } from "react-router-dom";
import { compactMeta } from "./sort";
import type { FindingsSort } from "./useFindingsQuery";

/** Clicks on these keep their own behaviour instead of opening the finding. */
const INTERACTIVE_SELECTOR = "a, button, input, select, textarea, label";

interface FindingsTableProps {
  slug: string | undefined;
  findings: Finding[];
  gate: GateStatus | undefined;
  sort: FindingsSort;
  onToggleSort: (column: string) => void;
}

/**
 * The findings table: sortable column headers, a row per finding with the
 * narrow-screen columns repeated under the title, and row-click routing to the
 * detail page.
 */
export function FindingsTable(
  { slug, findings, gate, sort, onToggleSort }: FindingsTableProps,
) {
  const navigate = useNavigate();
  const location = useLocation();

  // The detail page reads `state.from` to return to this exact filtered page.
  const detailState = { from: location.search };

  function openFinding(event: MouseEvent<HTMLTableRowElement>, findingId: string) {
    if (event.button !== 0 || event.ctrlKey || event.metaKey || event.shiftKey || event.altKey) {
      return;
    }
    if ((event.target as Element).closest(INTERACTIVE_SELECTOR)) return;
    if (window.getSelection()?.toString()) return;
    navigate(`/${slug}/findings/${findingId}`, { state: detailState });
  }

  const sortIndicator = (col: string) => {
    if (sort.by !== col) return "";
    return sort.dir === "asc" ? " ▲" : " ▼";
  };

  const ariaSort = (col: string): "ascending" | "descending" | "none" => {
    if (sort.by !== col) return "none";
    return sort.dir === "asc" ? "ascending" : "descending";
  };

  return (
    <div className="space-y-2">
      <div className="overflow-x-auto">
        <table className="w-full text-sm">
          <caption className="sr-only">Findings</caption>
          <thead>
            <tr className="border-border border-b text-left">
              <th
                scope="col"
                aria-sort={ariaSort("severity")}
                className="px-3 py-2 font-medium"
              >
                <button
                  type="button"
                  className="w-full cursor-pointer text-left whitespace-nowrap"
                  onClick={() => onToggleSort("severity")}
                >
                  Severity{sortIndicator("severity")}
                </button>
              </th>
              <th scope="col" className="hidden px-3 py-2 font-medium md:table-cell">Kind</th>
              <th
                scope="col"
                aria-sort={ariaSort("title")}
                className="px-3 py-2 font-medium"
              >
                <button
                  type="button"
                  className="w-full cursor-pointer text-left whitespace-nowrap"
                  onClick={() => onToggleSort("title")}
                >
                  Title{sortIndicator("title")}
                </button>
              </th>
              <th scope="col" className="hidden px-3 py-2 font-medium md:table-cell">
                Status
              </th>
              <th scope="col" className="hidden px-3 py-2 font-medium md:table-cell">
                Triage
              </th>
              <th scope="col" className="px-3 py-2 font-medium">Blocks gate</th>
              <th
                scope="col"
                aria-sort={ariaSort("last_seen")}
                className="hidden px-3 py-2 font-medium md:table-cell"
              >
                <button
                  type="button"
                  className="w-full cursor-pointer text-left whitespace-nowrap"
                  onClick={() => onToggleSort("last_seen")}
                >
                  Last Seen{sortIndicator("last_seen")}
                </button>
              </th>
            </tr>
          </thead>
          <tbody>
            {findings.map((f) => (
              <FindingsRow
                key={f.id}
                finding={f}
                slug={slug}
                gate={gate}
                detailState={detailState}
                onOpen={openFinding}
              />
            ))}
          </tbody>
        </table>
      </div>
      <p className="text-muted-foreground text-xs">
        Sorting applies only to the findings on this page.
      </p>
    </div>
  );
}

interface FindingsRowProps {
  finding: Finding;
  slug: string | undefined;
  gate: GateStatus | undefined;
  detailState: { from: string; };
  onOpen: (event: MouseEvent<HTMLTableRowElement>, findingId: string) => void;
}

/** One finding row: the desktop columns plus the narrow-screen summary line. */
function FindingsRow({ finding: f, slug, gate, detailState, onOpen }: FindingsRowProps) {
  const gateResult = blocksGate(f, gate);
  return (
    <tr
      className="border-border hover:bg-muted/50 focus-within:bg-muted/50 cursor-pointer border-b"
      onClick={(event) => onOpen(event, f.id)}
    >
      <td className="px-3 py-2">
        <SeverityBadge severity={f.current_severity} />
      </td>
      <td className="hidden px-3 py-2 md:table-cell">
        <span className="bg-muted text-muted-foreground inline-flex items-center rounded-md px-1.5 py-0.5 text-xs font-medium">
          {findingKindLabel(f.finding_kind) ?? "–"}
        </span>
      </td>
      <td className="px-3 py-2">
        <Link
          to={`/${slug}/findings/${f.id}`}
          state={detailState}
          className="underline-offset-2 hover:underline"
        >
          {f.current_title}
        </Link>
        <p className="text-muted-foreground mt-0.5 text-xs md:hidden">
          {compactMeta(f)}
        </p>
      </td>
      <td className="hidden px-3 py-2 capitalize md:table-cell">
        {technicalStateLabel(f.state) ?? "–"}
      </td>
      <td className="hidden px-3 py-2 text-xs md:table-cell">
        {analysisStateLabel(f.analysis_state)
          ? (
            <span className="bg-muted rounded px-1.5 py-0.5 whitespace-nowrap">
              {analysisStateLabel(f.analysis_state)}
            </span>
          )
          : <span className="text-muted-foreground">–</span>}
      </td>
      <td className="px-3 py-2">
        {gateResult?.blocks
          ? (
            <span className="bg-sev-critical-bg text-sev-critical-fg rounded-sm px-1.5 py-0.5 text-xs font-medium">
              Yes
            </span>
          )
          : (
            <span className="text-muted-foreground text-xs">
              {blocksGateLabel(gateResult)}
            </span>
          )}
      </td>
      <td className="text-muted-foreground hidden px-3 py-2 whitespace-nowrap md:table-cell">
        {formatDate(f.last_seen_at)}
      </td>
    </tr>
  );
}
