import { DataGrid, type DataGridColumn } from "@/components/ui/data-grid";
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
 * The findings ledger, rendered on the shared DataGrid so sorting, the roving
 * cursor and the keyboard model are the grid's, not a second hand-rolled table.
 *
 * The narrow-screen columns are hidden below `md` by the grid and repeated as one
 * line under the title, so no field is lost to a small viewport.
 */
export function FindingsTable(
  { slug, findings, gate, sort, onToggleSort }: FindingsTableProps,
) {
  const navigate = useNavigate();
  const location = useLocation();

  // The detail page reads `state.from` to return to this exact filtered page.
  const detailState = { from: location.search };
  const detailPath = (findingId: string) => `/${slug}/findings/${findingId}`;

  function openFinding(event: MouseEvent<HTMLTableRowElement>, findingId: string) {
    if (event.button !== 0 || event.ctrlKey || event.metaKey || event.shiftKey || event.altKey) {
      return;
    }
    if ((event.target as Element).closest(INTERACTIVE_SELECTOR)) return;
    if (window.getSelection()?.toString()) return;
    navigate(detailPath(findingId), { state: detailState });
  }

  const columns: readonly DataGridColumn<Finding>[] = [
    {
      id: "severity",
      header: "Severity",
      sortable: true,
      cell: (f) => <SeverityBadge severity={f.current_severity} />,
    },
    {
      id: "kind",
      header: "Kind",
      hideBelow: "md",
      cell: (f) => (
        <span className="bg-muted text-muted-foreground inline-flex items-center rounded-md px-1.5 py-0.5 text-xs font-medium">
          {findingKindLabel(f.finding_kind) ?? "–"}
        </span>
      ),
    },
    {
      id: "title",
      header: "Title",
      sortable: true,
      // The meta line below the title makes this cell two lines on phones.
      wrap: true,
      cell: (f) => (
        <>
          <Link
            to={detailPath(f.id)}
            state={detailState}
            className="underline-offset-2 hover:underline"
          >
            {f.current_title}
          </Link>
          <p className="text-muted-foreground mt-0.5 text-xs md:hidden">
            {compactMeta(f)}
          </p>
        </>
      ),
    },
    {
      id: "status",
      header: "Status",
      hideBelow: "md",
      cellClassName: "capitalize",
      cell: (f) => technicalStateLabel(f.state) ?? "–",
    },
    {
      id: "triage",
      header: "Triage",
      hideBelow: "md",
      cellClassName: "text-xs",
      cell: (f) => {
        const label = analysisStateLabel(f.analysis_state);
        return label
          ? <span className="bg-muted rounded px-1.5 py-0.5 whitespace-nowrap">{label}</span>
          : <span className="text-muted-foreground">–</span>;
      },
    },
    {
      id: "blocks",
      header: "Blocks gate",
      cell: (f) => {
        const result = blocksGate(f, gate);
        return result?.blocks
          ? (
            <span className="bg-sev-critical-bg text-sev-critical-fg rounded-sm px-1.5 py-0.5 text-xs font-medium">
              Yes
            </span>
          )
          : (
            <span className="text-muted-foreground text-xs">
              {blocksGateLabel(result)}
            </span>
          );
      },
    },
    {
      id: "last_seen",
      header: "Last Seen",
      sortable: true,
      hideBelow: "md",
      cellClassName: "text-muted-foreground tabular-nums",
      cell: (f) => formatDate(f.last_seen_at),
    },
  ];

  return (
    <div className="space-y-2">
      <div className="overflow-x-auto">
        <DataGrid
          label="Findings"
          rows={findings}
          columns={columns}
          rowKey={(f) => f.id}
          // A wrapped title makes the row taller than the density token.
          rowHeight="auto"
          proportionalFont
          rowClassName={() => "cursor-pointer"}
          sort={{
            columnId: sort.by,
            direction: sort.dir === "asc" ? "ascending" : "descending",
          }}
          onSortChange={onToggleSort}
          onActivate={(f) => navigate(detailPath(f.id), { state: detailState })}
          onRowClick={(f, event) => openFinding(event, f.id)}
        />
      </div>
      <p className="text-muted-foreground text-xs">
        Sorting applies only to the findings on this page.
      </p>
    </div>
  );
}
