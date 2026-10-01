import { fireEvent, render, screen } from "@testing-library/react";
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
});
