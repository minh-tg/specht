import { fireEvent, render, screen, within } from "@testing-library/react";
import { DataGrid, type DataGridColumn } from "./data-grid";

interface Row {
  readonly id: string;
  readonly title: string;
  readonly gate: string;
}

const rows: readonly Row[] = [
  { id: "f1", title: "runc breakout", gate: "block" },
  { id: "f2", title: "net/http DoS", gate: "block" },
  { id: "f3", title: "lodash pollution", gate: "ignore" },
];

const columns: readonly DataGridColumn<Row>[] = [
  { id: "title", header: "Finding", sortable: true, cell: (row) => row.title },
  { id: "gate", header: "Gate", align: "end", cell: (row) => row.gate },
];

const rowKey = (row: Row) => row.id;

describe("DataGrid — ARIA grid pattern", () => {
  it("exposes the grid with an accessible name", () => {
    render(
      <DataGrid
        label="Findings in payments-worker queue"
        rows={rows}
        columns={columns}
        rowKey={rowKey}
      />,
    );
    expect(screen.getByRole("grid", { name: "Findings in payments-worker queue" }))
      .toBeInTheDocument();
  });

  it("scopes column headers and reports sort state", () => {
    render(
      <DataGrid
        label="Findings"
        rows={rows}
        columns={columns}
        rowKey={rowKey}
        sort={{ columnId: "title", direction: "descending" }}
        onSortChange={() => {}}
      />,
    );
    const header = screen.getByRole("columnheader", { name: /Finding/ });
    expect(header).toHaveAttribute("scope", "col");
    expect(header).toHaveAttribute("aria-sort", "descending");
  });

  it("keeps exactly one row tabbable (roving tabindex)", () => {
    // The generated screens shipped tabindex=0 everywhere, which is not a grid.
    render(<DataGrid label="Findings" rows={rows} columns={columns} rowKey={rowKey} />);
    const gridRows = screen.getAllByRole("row").filter((r) => r.hasAttribute("aria-rowindex"));
    expect(gridRows).toHaveLength(3);
    expect(gridRows.filter((r) => r.getAttribute("tabindex") === "0")).toHaveLength(1);
    expect(gridRows.filter((r) => r.getAttribute("tabindex") === "-1")).toHaveLength(2);
  });

  it("moves real focus down and up with the keyboard", () => {
    render(<DataGrid label="Findings" rows={rows} columns={columns} rowKey={rowKey} />);
    const grid = screen.getByRole("grid");
    const gridRows = screen.getAllByRole("row").filter((r) => r.hasAttribute("aria-rowindex"));

    // The cursor row is tabbable but must NOT steal focus on mount.
    expect(gridRows[0]).toHaveAttribute("tabindex", "0");

    fireEvent.keyDown(grid, { key: "ArrowDown" });
    expect(gridRows[1]).toHaveFocus();
    expect(gridRows[1]).toHaveAttribute("tabindex", "0");
    expect(gridRows[0]).toHaveAttribute("tabindex", "-1");

    fireEvent.keyDown(grid, { key: "k" });
    expect(gridRows[0]).toHaveFocus();

    fireEvent.keyDown(grid, { key: "End" });
    expect(gridRows[2]).toHaveFocus();

    fireEvent.keyDown(grid, { key: "Home" });
    expect(gridRows[0]).toHaveFocus();
  });

  it("scrolls the cursored row into view (scroll-follow)", () => {
    // Without this, traversal past one viewport leaves the cursor off-screen.
    const scrollIntoView = vi.fn();
    Element.prototype.scrollIntoView = scrollIntoView;
    render(<DataGrid label="Findings" rows={rows} columns={columns} rowKey={rowKey} />);
    scrollIntoView.mockClear();

    fireEvent.keyDown(screen.getByRole("grid"), { key: "ArrowDown" });
    expect(scrollIntoView).toHaveBeenCalled();
  });

  it("marks selection separately from the cursor", () => {
    render(
      <DataGrid
        label="Findings"
        rows={rows}
        columns={columns}
        rowKey={rowKey}
        selectedKey="f2"
        onSelect={() => {}}
      />,
    );
    const gridRows = screen.getAllByRole("row").filter((r) => r.hasAttribute("aria-rowindex"));
    expect(gridRows[1]).toHaveAttribute("aria-selected", "true");
    expect(gridRows[0]).toHaveAttribute("aria-selected", "false");
    // The cursor and the selection are independent: f2 is selected, f1 is cursored.
    expect(gridRows[0]).toHaveAttribute("tabindex", "0");
    expect(gridRows[1]).toHaveAttribute("tabindex", "-1");
  });

  it("omits aria-selected when the grid is not selectable", () => {
    render(<DataGrid label="Findings" rows={rows} columns={columns} rowKey={rowKey} />);
    const gridRows = screen.getAllByRole("row").filter((r) => r.hasAttribute("aria-rowindex"));
    expect(gridRows[0]).not.toHaveAttribute("aria-selected");
  });

  it("activates the cursored row on Enter", () => {
    const onActivate = vi.fn();
    render(
      <DataGrid
        label="Findings"
        rows={rows}
        columns={columns}
        rowKey={rowKey}
        onActivate={onActivate}
      />,
    );
    const grid = screen.getByRole("grid");
    fireEvent.keyDown(grid, { key: "ArrowDown" });
    fireEvent.keyDown(grid, { key: "Enter" });
    expect(onActivate).toHaveBeenCalledWith(rows[1]);
  });

  it("selects the cursored row on x or Space", () => {
    const onSelect = vi.fn();
    render(
      <DataGrid
        label="Findings"
        rows={rows}
        columns={columns}
        rowKey={rowKey}
        onSelect={onSelect}
      />,
    );
    const grid = screen.getByRole("grid");
    fireEvent.keyDown(grid, { key: "x" });
    expect(onSelect).toHaveBeenCalledWith(rows[0]);
    fireEvent.keyDown(grid, { key: " " });
    expect(onSelect).toHaveBeenCalledTimes(2);
  });

  it("clamps the cursor when rows shrink under it", () => {
    const { rerender } = render(
      <DataGrid label="Findings" rows={rows} columns={columns} rowKey={rowKey} />,
    );
    fireEvent.keyDown(screen.getByRole("grid"), { key: "End" });
    rerender(
      <DataGrid label="Findings" rows={rows.slice(0, 1)} columns={columns} rowKey={rowKey} />,
    );
    const remaining = screen.getAllByRole("row").filter((r) => r.hasAttribute("aria-rowindex"));
    expect(remaining).toHaveLength(1);
    expect(remaining[0]).toHaveAttribute("tabindex", "0");
  });

  it("states what to do when empty rather than showing nothing", () => {
    render(
      <DataGrid
        label="Findings"
        rows={[]}
        columns={columns}
        rowKey={rowKey}
        emptyState="Ingest a scan report to see findings"
      />,
    );
    expect(screen.getByText("Ingest a scan report to see findings")).toBeInTheDocument();
  });

  it("announces the cursored row through a polite live region", () => {
    // A live region is how a screen-reader user hears the cursor move.
    render(<DataGrid label="Findings" rows={rows} columns={columns} rowKey={rowKey} />);
    const status = screen.getByRole("status");
    expect(status).toHaveAttribute("aria-live", "polite");
    expect(status).toHaveTextContent("Row 1 of 3");

    fireEvent.keyDown(screen.getByRole("grid"), { key: "ArrowDown" });
    expect(status).toHaveTextContent("Row 2 of 3");
  });

  it("lets the owner name the announced row", () => {
    // The owner knows things the grid does not, such as the selection count.
    render(
      <DataGrid
        label="Findings"
        rows={rows}
        columns={columns}
        rowKey={rowKey}
        getAnnouncement={(row, index) => `Row ${index + 1} of 3: ${row.title}`}
      />,
    );
    expect(screen.getByRole("status")).toHaveTextContent("Row 1 of 3: runc breakout");
  });

  it("applies the mode's row-height token", () => {
    render(
      <DataGrid label="Findings" rows={rows} columns={columns} rowKey={rowKey} density="compact" />,
    );
    const gridRows = screen.getAllByRole("row").filter((r) => r.hasAttribute("aria-rowindex"));
    expect(gridRows[0].className).toContain("--row-compact");
  });

  it("reports aria-sort=none on a sortable header that is not the sorted column", () => {
    // An absent aria-sort and "none" mean the same thing, but only the latter is
    // announced, so a sortable column must always carry a state.
    const sortableColumns: readonly DataGridColumn<Row>[] = [
      { id: "title", header: "Title", sortable: true, cell: (row) => row.title },
      { id: "gate", header: "Gate", sortable: true, cell: (row) => row.gate },
    ];
    render(
      <DataGrid
        label="Findings"
        rows={rows}
        columns={sortableColumns}
        rowKey={rowKey}
        sort={{ columnId: "gate", direction: "ascending" }}
        onSortChange={() => {}}
      />,
    );
    expect(screen.getByRole("columnheader", { name: /Title/ }))
      .toHaveAttribute("aria-sort", "none");
    expect(screen.getByRole("columnheader", { name: /Gate/ }))
      .toHaveAttribute("aria-sort", "ascending");
  });

  it("omits aria-sort on a column that cannot be sorted", () => {
    render(
      <DataGrid
        label="Findings"
        rows={rows}
        columns={columns}
        rowKey={rowKey}
        sort={{ columnId: "title", direction: "ascending" }}
        onSortChange={() => {}}
      />,
    );
    expect(screen.getByRole("columnheader", { name: "Gate" })).not.toHaveAttribute("aria-sort");
  });

  it("hides a column below md on both its header and its cells", () => {
    const narrowColumns: readonly DataGridColumn<Row>[] = [
      { id: "title", header: "Title", cell: (row) => row.title },
      { id: "gate", header: "Gate", hideBelow: "md", cell: (row) => row.gate },
    ];
    render(<DataGrid label="Findings" rows={rows} columns={narrowColumns} rowKey={rowKey} />);

    const header = screen.getByRole("columnheader", { name: "Gate" });
    expect(header.className).toContain("hidden");
    expect(header.className).toContain("md:table-cell");

    const gridRows = screen.getAllByRole("row").filter((r) => r.hasAttribute("aria-rowindex"));
    const gateCell = within(gridRows[0]).getAllByRole("gridcell")[1];
    expect(gateCell.className).toContain("hidden");
    expect(gateCell.className).toContain("md:table-cell");
  });

  it("merges a column's cellClassName into that column's cells", () => {
    const styledColumns: readonly DataGridColumn<Row>[] = [
      {
        id: "title",
        header: "Title",
        cellClassName: "text-muted-foreground",
        cell: (row) => row.title,
      },
    ];
    render(<DataGrid label="Findings" rows={rows} columns={styledColumns} rowKey={rowKey} />);

    const gridRows = screen.getAllByRole("row").filter((r) => r.hasAttribute("aria-rowindex"));
    const cell = within(gridRows[0]).getAllByRole("gridcell")[0];
    expect(cell.className).toContain("text-muted-foreground");
    // The cell keeps its default ledger styling as well.
    expect(cell.className).toContain("font-mono");
  });

  it("drops the one-line clipping only for a wrapping cell", () => {
    const wrapColumns: readonly DataGridColumn<Row>[] = [
      { id: "title", header: "Title", wrap: true, cell: (row) => row.title },
      { id: "gate", header: "Gate", cell: (row) => row.gate },
    ];
    render(<DataGrid label="Findings" rows={rows} columns={wrapColumns} rowKey={rowKey} />);

    const gridRows = screen.getAllByRole("row").filter((r) => r.hasAttribute("aria-rowindex"));
    const [titleCell, gateCell] = within(gridRows[0]).getAllByRole("gridcell");
    expect(titleCell.className).toContain("whitespace-normal");
    expect(titleCell.className).not.toContain("whitespace-nowrap");
    expect(gateCell.className).toContain("whitespace-nowrap");
  });

  it("uses a minimum height instead of a fixed one when rows may grow", () => {
    render(
      <DataGrid
        label="Findings"
        rows={rows}
        columns={columns}
        rowKey={rowKey}
        density="compact"
        rowHeight="auto"
      />,
    );
    const gridRows = screen.getAllByRole("row").filter((r) => r.hasAttribute("aria-rowindex"));
    expect(gridRows[0].className).toContain("min-h-[var(--row-compact)]");
  });

  it("merges per-row classes from rowClassName", () => {
    render(
      <DataGrid
        label="Findings"
        rows={rows}
        columns={columns}
        rowKey={rowKey}
        rowClassName={(row) => (row.id === "f2" ? "cursor-pointer" : undefined)}
      />,
    );
    const gridRows = screen.getAllByRole("row").filter((r) => r.hasAttribute("aria-rowindex"));
    expect(gridRows[1].className).toContain("cursor-pointer");
    expect(gridRows[0].className).not.toContain("cursor-pointer");
  });

  it("fires onRowClick after moving the cursor, keeping onSelect", () => {
    const calls: string[] = [];
    const onSelect = vi.fn((row: Row) => calls.push(`select:${row.id}`));
    const onRowClick = vi.fn((row: Row) => calls.push(`click:${row.id}`));
    render(
      <DataGrid
        label="Findings"
        rows={rows}
        columns={columns}
        rowKey={rowKey}
        onSelect={onSelect}
        onRowClick={onRowClick}
      />,
    );
    const gridRows = screen.getAllByRole("row").filter((r) => r.hasAttribute("aria-rowindex"));

    fireEvent.click(gridRows[1]);

    expect(onRowClick).toHaveBeenCalledWith(rows[1], expect.anything());
    expect(onSelect).toHaveBeenCalledWith(rows[1]);
    // The click moves the cursor before the owner's handler runs, so a click and
    // the keyboard cursor never disagree about which row is current.
    expect(calls).toEqual(["select:f2", "click:f2"]);
    expect(gridRows[1]).toHaveAttribute("tabindex", "0");
  });

  it("leaves Enter to a control inside the grid instead of activating the row", () => {
    // A sort button in a header owns Enter; hijacking it would make the grid
    // impossible to sort from the keyboard.
    const controlColumns: readonly DataGridColumn<Row>[] = [
      {
        id: "title",
        header: <button type="button">Sort by title</button>,
        cell: (row) => row.title,
      },
    ];
    const onActivate = vi.fn();
    render(
      <DataGrid
        label="Findings"
        rows={rows}
        columns={controlColumns}
        rowKey={rowKey}
        onActivate={onActivate}
      />,
    );

    fireEvent.keyDown(screen.getByRole("button", { name: "Sort by title" }), { key: "Enter" });

    expect(onActivate).not.toHaveBeenCalled();
  });

  it("switches cells to the app font when proportionalFont is set", () => {
    render(
      <DataGrid label="Findings" rows={rows} columns={columns} rowKey={rowKey} proportionalFont />,
    );
    const gridRows = screen.getAllByRole("row").filter((r) => r.hasAttribute("aria-rowindex"));
    const cell = within(gridRows[0]).getAllByRole("gridcell")[0];
    expect(cell.className).not.toContain("font-mono");
    expect(cell.className).not.toContain("tabular-nums");
  });
});
