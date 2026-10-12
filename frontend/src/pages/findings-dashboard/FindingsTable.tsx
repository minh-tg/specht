import { DataGrid, type DataGridColumn } from "@/components/ui/data-grid";
import { SeverityBadge } from "@/components/ui/severity-badge";
import { findingKindLabel } from "@/lib/enums";
import { findingWorkflowState } from "@/lib/findingState";
import { formatAge, formatDate } from "@/lib/format";
import type { Finding, GateStatus } from "@/types/api";
import { ChevronRightIcon } from "lucide-react";
import { type MouseEvent, useEffect, useRef } from "react";
import { Link, useLocation, useNavigate } from "react-router-dom";
import { locationText } from "./location";
import { compactMeta } from "./sort";
import type { FindingsSort } from "./useFindingsQuery";

/** Clicks on these keep their own behaviour instead of opening the finding. */
const INTERACTIVE_SELECTOR = "a, button, input, select, textarea, label";

export interface FindingsSelection {
  readonly keys: ReadonlySet<string>;
  readonly onToggle: (findingId: string) => void;
  /** Selects every finding on the page, or none. */
  readonly onToggleAll: (selectAll: boolean) => void;
}

interface FindingsTableProps {
  slug: string | undefined;
  findings: Finding[];
  gate: GateStatus | undefined;
  sort: FindingsSort;
  onToggleSort: (column: string) => void;
  /** Absent when the person can do nothing to a selection, so there is nothing to select. */
  selection?: FindingsSelection;
}

/** Blocking severities carry a bar of their colour on the row's left edge. */
function edgeClass(finding: Finding): string | undefined {
  if (finding.state !== "open" && finding.state !== "reopened") return undefined;
  const edge = "[&>td:first-child]:shadow-[inset_4px_0_0_var(--edge)]";
  if (finding.current_severity === "critical") return `[--edge:var(--sev-critical)] ${edge}`;
  if (finding.current_severity === "high") return `[--edge:var(--sev-high)] ${edge}`;
  return undefined;
}

function SelectAll({ findings, selection }: {
  readonly findings: readonly Finding[];
  readonly selection: FindingsSelection;
}) {
  const ref = useRef<HTMLInputElement>(null);
  const chosen = findings.filter((f) => selection.keys.has(f.id)).length;
  const all = findings.length > 0 && chosen === findings.length;
  useEffect(() => {
    if (ref.current) ref.current.indeterminate = chosen > 0 && !all;
  }, [chosen, all]);
  return (
    <input
      ref={ref}
      type="checkbox"
      aria-label="Select all findings on this page"
      checked={all}
      onChange={(event) => selection.onToggleAll(event.target.checked)}
      className="size-4 accent-foreground pointer-coarse:size-6"
    />
  );
}

/**
 * The findings ledger, rendered on the shared DataGrid so sorting, the roving cursor and the
 * keyboard model (j and k to move, x to select, Enter to open) are the grid's, not a second
 * hand-rolled table.
 *
 * The narrow-screen columns are hidden below `md` by the grid and repeated as one line under the
 * title, so no field is lost to a small viewport.
 */
export function FindingsTable(
  { slug, findings, gate, sort, onToggleSort, selection }: FindingsTableProps,
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

  const columns: DataGridColumn<Finding>[] = [
    {
      id: "severity",
      header: "Severity",
      sortable: true,
      cell: (f) => <SeverityBadge severity={f.current_severity} plain />,
    },
    {
      id: "title",
      header: "Finding",
      sortable: true,
      // The meta line below the title makes this cell two lines on phones.
      wrap: true,
      cell: (f) => (
        <>
          <Link
            to={detailPath(f.id)}
            state={detailState}
            className="font-medium underline-offset-2 hover:underline"
          >
            {f.current_title}
          </Link>
          <p className="text-muted-foreground mt-0.5 hidden font-mono text-xs md:block">
            {findingKindLabel(f.finding_kind) ?? "–"}
          </p>
          <p className="text-muted-foreground mt-0.5 text-xs md:hidden">{compactMeta(f)}</p>
        </>
      ),
    },
    {
      id: "where",
      header: "Where",
      hideBelow: "md",
      cellClassName: "max-w-[22rem] font-mono text-xs",
      cell: (f) => <span title={locationText(f.location)}>{locationText(f.location)}</span>,
    },
    {
      id: "state",
      header: "State",
      hideBelow: "md",
      cell: (f) => {
        const workflow = findingWorkflowState(f, gate);
        return (
          <span
            data-open={workflow.open}
            className={`inline-flex items-center gap-[7px] ${
              workflow.open ? "" : "text-muted-foreground"
            }`}
          >
            <span
              aria-hidden="true"
              className={`size-[7px] rounded-full ring-[1.5px] ring-current ring-inset ${
                workflow.open ? "bg-current" : ""
              }`}
            />
            {workflow.label}
          </span>
        );
      },
    },
    {
      id: "first_seen",
      header: "Age",
      sortable: true,
      hideBelow: "md",
      align: "end",
      cellClassName: "text-muted-foreground tabular-nums",
      cell: (f) => (
        <span title={`First seen ${formatDate(f.first_seen_at)}`}>
          {formatAge(f.first_seen_at)}
        </span>
      ),
    },
    {
      id: "open",
      header: <span className="sr-only">Open</span>,
      cellClassName: "w-7 text-muted-foreground",
      cell: () => <ChevronRightIcon aria-hidden="true" className="size-4" />,
    },
  ];

  if (selection) {
    columns.unshift({
      id: "select",
      header: <SelectAll findings={findings} selection={selection} />,
      cellClassName: "w-10",
      cell: (f) => (
        <input
          type="checkbox"
          aria-label={`Select ${f.current_title}`}
          checked={selection.keys.has(f.id)}
          onChange={() => selection.onToggle(f.id)}
          className="size-4 accent-foreground pointer-coarse:size-6"
        />
      ),
    });
  }

  return (
    <div className="border-foreground overflow-x-auto border-t-2">
      <DataGrid
        label="Findings"
        rows={findings}
        columns={columns}
        rowKey={(f) => f.id}
        proportionalFont
        rowClassName={(f) => `cursor-pointer ${edgeClass(f) ?? ""}`}
        sort={{
          columnId: sort.by,
          direction: sort.dir === "asc" ? "ascending" : "descending",
        }}
        onSortChange={onToggleSort}
        multiSelect={selection
          ? { selectedKeys: selection.keys, onToggle: (f) => selection.onToggle(f.id) }
          : undefined}
        onActivate={(f) => navigate(detailPath(f.id), { state: detailState })}
        onRowClick={(f, event) => openFinding(event, f.id)}
      />
    </div>
  );
}
