import { cn } from "@/lib/utils";
import * as React from "react";

/**
 * DataGrid — the ledger primitive.
 *
 * This exists because generated screens kept shipping a hand-rolled `keydown`
 * handler on a `div`: key bindings that looked right but produced `role=0` and
 * `tabindex=0`, so nothing was announced and the cursor never followed the list.
 * The ARIA pattern is therefore a *component property*, not a principle.
 *
 * Correctness it guarantees:
 *
 * - `role="grid"` with an accessible name, `role="row"`, `role="columnheader"`
 *   with `scope` and `aria-sort`, and `role="gridcell"`.
 * - **Roving tabindex with real focus** — one row is tabbable at a time and focus
 *   actually moves, rather than `aria-activedescendant`, so the browser announces
 *   the row natively and `:focus-visible` draws the cursor. A row cursor is
 *   shown **only while focused**; there is no permanently drawn cursor.
 * - **Scroll-follow** — the cursored row is scrolled into view, so traversal to row
 *   40 of 100 does not leave the cursor off-screen.
 * - Selection is separate from the cursor, and only selectable grids set
 *   `aria-selected`.
 *
 * Not included deliberately: virtualisation (`aria-rowcount` is wired for when it
 * arrives), grouping, and multi-select. Add them when a screen needs them.
 */

export interface DataGridColumn<Row> {
  readonly id: string;
  readonly header: React.ReactNode;
  readonly sortable?: boolean;
  readonly align?: "start" | "end";
  /**
   * Hide the whole column below the given breakpoint. The owner is responsible
   * for repeating the value somewhere that stays visible, so nothing is lost to
   * a small viewport or to assistive technology.
   */
  readonly hideBelow?: "md";
  /** Extra classes merged into this column's cells (not its header). */
  readonly cellClassName?: string;
  /**
   * Let a multi-line value wrap. Without this the cell clips to one line, which
   * keeps the row-height token honest. A table row's height is only a minimum,
   * so a wrapping cell grows its row instead of overflowing.
   */
  readonly wrap?: boolean;
  /** Cell content. Keep it single-line unless `wrap` is set. */
  readonly cell: (row: Row) => React.ReactNode;
}

export interface DataGridSort {
  readonly columnId: string;
  readonly direction: "ascending" | "descending";
}

export interface DataGridProps<Row> {
  /** Accessible name for the grid. Required — an unnamed grid is unusable. */
  readonly label: string;
  readonly rows: readonly Row[];
  readonly columns: readonly DataGridColumn<Row>[];
  readonly rowKey: (row: Row) => string;
  /** Row height token. Resolve it from the mode, not from the screen. */
  readonly density?: "compact" | "comfortable" | "group";
  /** Per-row classes, for a cursor affordance the column set cannot express. */
  readonly rowClassName?: (row: Row) => string | undefined;
  readonly selectedKey?: string | null;
  readonly onSelect?: (row: Row) => void;
  readonly onActivate?: (row: Row) => void;
  /**
   * Fired after the cursor update on a row click, with the click event so the
   * owner can apply its own guards. `onSelect` still runs as before.
   */
  readonly onRowClick?: (row: Row, event: React.MouseEvent<HTMLTableRowElement>) => void;
  /**
   * The ledger default is mono with tabular numerals. Prose-heavy grids read
   * better in the app font; a cell that still needs aligned digits can add
   * `tabular-nums` through `cellClassName`.
   */
  readonly proportionalFont?: boolean;
  readonly sort?: DataGridSort | null;
  readonly onSortChange?: (columnId: string) => void;
  readonly ariaRowCount?: number;
  /**
   * Announced on cursor move through a polite live region. Defaults to
   * "Row n of total"; override to name the row, or to include the selection count
   * that only the owner knows.
   */
  readonly getAnnouncement?: (row: Row, index: number) => string;
  /** Shown when there are no rows. Should say what to do next, not just "no data". */
  readonly emptyState?: React.ReactNode;
}

type Density = NonNullable<DataGridProps<unknown>["density"]>;

/** Elements that own their activation keys; the grid must not intercept them. */
const CONTROL_SELECTOR = "a, button, input, select, textarea, label";

// A table row's height is only a minimum (`min-height` is ignored on rows), so
// the token keeps rows uniform and still lets a wrapping cell grow its row.
const DENSITY_HEIGHT: Record<Density, string> = {
  compact: "h-[var(--row-compact)]",
  comfortable: "h-[var(--row-comfortable)]",
  group: "h-[var(--row-group)]",
};

export function DataGrid<Row>({
  label,
  rows,
  columns,
  rowKey,
  density = "comfortable",
  rowClassName,
  selectedKey = null,
  onSelect,
  onActivate,
  onRowClick,
  proportionalFont = false,
  sort = null,
  onSortChange,
  ariaRowCount,
  getAnnouncement,
  emptyState,
}: DataGridProps<Row>) {
  const [cursorState, setCursorState] = React.useState(0);
  const rowRefs = React.useRef<(HTMLTableRowElement | null)[]>([]);

  // Clamp during render rather than in an effect: filtering or a fresh report can
  // shrink the rows under the cursor, and clamping in an effect would cascade an
  // extra render for a value we can simply derive.
  const maxIndex = Math.max(0, rows.length - 1);
  const cursor = Math.min(cursorState, maxIndex);

  // Scroll-follow: without this, keyboard traversal is unusable past one viewport.
  React.useEffect(() => {
    const node = rowRefs.current[cursor];
    if (!node) return;
    if (typeof node.scrollIntoView === "function") {
      node.scrollIntoView({ block: "nearest" });
    }
  }, [cursor, rows.length]);

  const moveCursor = (next: number) => {
    if (rows.length === 0) return;
    const clamped = Math.max(0, Math.min(maxIndex, next));
    setCursorState(clamped);
    rowRefs.current[clamped]?.focus();
  };

  const handleKeyDown = (event: React.KeyboardEvent<HTMLTableElement>) => {
    // A header control owns Enter and Space itself. The grid must not steal the
    // activation keys from a sort button, and a link in a cell keeps its native
    // activation; the cursor row is not interactive, so row activation still
    // reaches onActivate/onSelect.
    const onControl = (event.target as Element | null)?.closest(CONTROL_SELECTOR) != null;
    switch (event.key) {
      case "ArrowDown":
      case "j":
        event.preventDefault();
        moveCursor(cursor + 1);
        return;
      case "ArrowUp":
      case "k":
        event.preventDefault();
        moveCursor(cursor - 1);
        return;
      case "Home":
        event.preventDefault();
        moveCursor(0);
        return;
      case "End":
        event.preventDefault();
        moveCursor(rows.length - 1);
        return;
      case "Enter": {
        if (onControl) return;
        const row = rows[cursor];
        if (!row) return;
        event.preventDefault();
        onActivate?.(row);
        return;
      }
      case " ":
      case "x": {
        if (onControl) return;
        const row = rows[cursor];
        if (!row || !onSelect) return;
        event.preventDefault();
        onSelect(row);
        return;
      }
      default:
    }
  };

  const selectable = typeof onSelect === "function";

  // Derived rather than stored: a live region announces when its text changes, so
  // the cursored row is enough and no extra state is needed.
  const cursoredRow = rows[cursor];
  const liveMessage = cursoredRow === undefined
    ? ""
    : (getAnnouncement?.(cursoredRow, cursor) ?? `Row ${cursor + 1} of ${rows.length}`);

  return (
    <>
      <div role="status" aria-live="polite" className="sr-only">
        {liveMessage}
      </div>
      <table
        role="grid"
        aria-label={label}
        aria-rowcount={ariaRowCount ?? rows.length}
        onKeyDown={handleKeyDown}
        className="w-full border-collapse text-left"
      >
        <thead>
          <tr role="row" className="h-8">
            {columns.map((column) => {
              const active = sort?.columnId === column.id ? sort.direction : undefined;
              return (
                <th
                  key={column.id}
                  role="columnheader"
                  scope="col"
                  // Sortable headers always carry a state: an absent aria-sort and
                  // "none" mean the same thing but only the latter is announced.
                  aria-sort={column.sortable ? (active ?? "none") : undefined}
                  className={cn(
                    "border-b border-border px-2 py-1",
                    "font-label text-[11px] leading-4 tracking-[0.06em] text-muted-foreground uppercase",
                    column.hideBelow === "md" && "hidden md:table-cell",
                    column.align === "end" && "text-right",
                  )}
                >
                  {column.sortable && onSortChange
                    ? (
                      <button
                        type="button"
                        onClick={() => onSortChange(column.id)}
                        className="inline-flex items-center gap-1 hover:text-foreground"
                      >
                        {column.header}
                        {active
                          ? <span aria-hidden="true">{active === "ascending" ? "↑" : "↓"}</span>
                          : null}
                      </button>
                    )
                    : (
                      column.header
                    )}
                </th>
              );
            })}
          </tr>
        </thead>
        <tbody>
          {rows.length === 0
            ? (
              <tr role="row">
                <td
                  role="gridcell"
                  colSpan={columns.length}
                  className="px-2 py-6 text-center text-muted-foreground"
                >
                  {emptyState ?? "Nothing to show."}
                </td>
              </tr>
            )
            : (
              rows.map((row, index) => {
                const key = rowKey(row);
                const isCursor = index === cursor;
                const isSelected = selectedKey !== null && selectedKey === key;
                return (
                  <tr
                    key={key}
                    role="row"
                    aria-rowindex={index + 2}
                    aria-selected={selectable ? isSelected : undefined}
                    // Roving tabindex: exactly one row is tabbable, and focus really moves.
                    tabIndex={isCursor ? 0 : -1}
                    ref={(node) => {
                      rowRefs.current[index] = node;
                    }}
                    onClick={(event) => {
                      setCursorState(index);
                      onSelect?.(row);
                      onRowClick?.(row, event);
                    }}
                    className={cn(
                      DENSITY_HEIGHT[density],
                      "border-b border-border/60 outline-none",
                      "hover:bg-muted/60",
                      isSelected && "bg-muted",
                      rowClassName?.(row),
                    )}
                  >
                    {columns.map((column) => (
                      <td
                        key={column.id}
                        role="gridcell"
                        className={cn(
                          // A table cell's height is only a minimum, so a wrapping value
                          // silently defeats the row-height token: clip instead of wrap.
                          column.wrap
                            ? "break-words whitespace-normal"
                            : "overflow-hidden text-ellipsis whitespace-nowrap",
                          "px-2 text-[13px] leading-[18px]",
                          proportionalFont ? "" : "font-mono tabular-nums",
                          column.align === "end" && "text-right",
                          column.hideBelow === "md" && "hidden md:table-cell",
                          column.cellClassName,
                        )}
                      >
                        {column.cell(row)}
                      </td>
                    ))}
                  </tr>
                );
              })
            )}
        </tbody>
      </table>
    </>
  );
}
