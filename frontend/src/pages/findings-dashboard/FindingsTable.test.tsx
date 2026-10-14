import { formatDate } from "@/lib/format";
import type { Finding, GateStatus } from "@/types/api";
import { fireEvent, render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter, Route, Routes, useLocation } from "react-router-dom";
import { describe, expect, it, vi } from "vitest";
import { FindingsTable } from "./FindingsTable";
import { locationText } from "./location";
import type { FindingsSort } from "./useFindingsQuery";

const FINDINGS: Finding[] = [
  {
    id: "f1",
    project_id: "p1",
    finding_kind: "sca",
    fingerprint: "fp1",
    current_title: "runc breakout",
    current_severity: "critical",
    current_score: 9.8,
    state: "open",
    triage_status: "untriaged",
    analysis_state: "unanalyzed",
    gate_effect: "block",
    first_seen_at: "2025-01-01T00:00:00Z",
    last_seen_at: "2025-01-01T00:00:00Z",
    created_at: "2025-01-01T00:00:00Z",
    updated_at: "2025-01-01T00:00:00Z",
  },
  {
    id: "f2",
    project_id: "p1",
    finding_kind: "sast",
    fingerprint: "fp2",
    current_title: "net/http DoS",
    current_severity: "high",
    current_score: 7.5,
    state: "reopened",
    triage_status: "untriaged",
    analysis_state: "accepted_risk",
    gate_effect: "block",
    first_seen_at: "2025-02-01T00:00:00Z",
    last_seen_at: "2025-02-01T00:00:00Z",
    created_at: "2025-02-01T00:00:00Z",
    updated_at: "2025-02-01T00:00:00Z",
  },
  {
    id: "f3",
    project_id: "p1",
    finding_kind: "secret",
    fingerprint: "fp3",
    current_title: "leaked token",
    current_severity: "low",
    current_score: 2.1,
    state: "fixed",
    triage_status: "untriaged",
    analysis_state: "wont_fix",
    gate_effect: "ignore",
    first_seen_at: "2025-03-01T00:00:00Z",
    last_seen_at: "2025-03-01T00:00:00Z",
    created_at: "2025-03-01T00:00:00Z",
    updated_at: "2025-03-01T00:00:00Z",
  },
];

const GATE: GateStatus = { threshold_breached: false, blocking_count: 0, blocked_by: [] };

const NO_SELECTION = { keys: new Set<string>(), onToggle: vi.fn(), onToggleAll: vi.fn() };

/** Exact token match, because "overflow-hidden" is a different class to "hidden". */
function hasClass(element: Element, token: string): boolean {
  return element.className.split(/\s+/).includes(token);
}

function gridRows(): HTMLElement[] {
  return within(screen.getByRole("grid", { name: "Findings" })).getAllByRole("row")
    .filter((row) => row.hasAttribute("aria-rowindex"));
}

function dataCells(rowIndex: number): HTMLElement[] {
  return within(gridRows()[rowIndex]).getAllByRole("gridcell");
}

function renderTable(
  options: {
    readonly initialPath?: string;
    readonly sort?: FindingsSort;
    readonly selection?: Parameters<typeof FindingsTable>[0]["selection"];
  } = {},
) {
  const sort: FindingsSort = options.sort ?? { by: "severity", dir: "desc" };
  return render(
    <MemoryRouter initialEntries={[options.initialPath ?? "/test-project/findings"]}>
      <Routes>
        <Route
          path="/:slug/findings"
          element={
            <FindingsTable
              slug="test-project"
              findings={FINDINGS}
              gate={GATE}
              sort={sort}
              onToggleSort={vi.fn()}
              selection={options.selection}
            />
          }
        />
        <Route path="/:slug/findings/:findingId" element={<DetailState />} />
      </Routes>
    </MemoryRouter>,
  );
}

describe("FindingsTable on the data grid", () => {
  it("exposes the findings as an ARIA grid named Findings", () => {
    renderTable();
    const grid = screen.getByRole("grid", { name: "Findings" });
    expect(grid).toBeInTheDocument();
    // The list is not selectable, so it must not claim aria-selected.
    expect(gridRows()[0]).not.toHaveAttribute("aria-selected");
  });

  it("moves the cursor down with ArrowDown and j", () => {
    renderTable();
    const grid = screen.getByRole("grid", { name: "Findings" });
    const rows = gridRows();
    expect(rows[0]).toHaveAttribute("tabindex", "0");

    fireEvent.keyDown(grid, { key: "ArrowDown" });
    expect(rows[1]).toHaveFocus();
    expect(rows[1]).toHaveAttribute("tabindex", "0");

    fireEvent.keyDown(rows[1], { key: "j" });
    expect(rows[2]).toHaveFocus();
  });

  it("opens the cursored finding with Enter, carrying the list search as state", async () => {
    renderTable({ initialPath: "/test-project/findings?severity=high&offset=0" });
    const grid = screen.getByRole("grid", { name: "Findings" });

    fireEvent.keyDown(grid, { key: "ArrowDown" });
    fireEvent.keyDown(grid, { key: "Enter" });

    expect(await screen.findByTestId("detail-state")).toHaveTextContent(
      JSON.stringify({ from: "?severity=high&offset=0" }),
    );
  });

  it("opens the finding when a non-interactive cell is clicked", async () => {
    renderTable();
    const user = userEvent.setup();

    await user.click(within(gridRows()[0]).getByText("Open"));

    expect(await screen.findByTestId("detail-state")).toBeInTheDocument();
  });

  it("opens the finding once, not twice, when the title link is clicked", async () => {
    renderTable();
    const user = userEvent.setup();

    await user.click(screen.getByRole("link", { name: "runc breakout" }));

    expect(await screen.findByTestId("detail-state")).toBeInTheDocument();
    expect(screen.getAllByTestId("detail-state")).toHaveLength(1);
  });

  it("leaves a ctrl-click to the browser instead of opening the finding", async () => {
    renderTable();
    const user = userEvent.setup();

    await user.keyboard("{Control>}");
    await user.click(within(gridRows()[0]).getByText("Open"));
    await user.keyboard("{/Control}");

    expect(screen.queryByTestId("detail-state")).not.toBeInTheDocument();
  });

  it("does not open the finding while the user is selecting text", async () => {
    renderTable();
    const user = userEvent.setup();
    vi.spyOn(window, "getSelection").mockReturnValue(
      { toString: () => "Open" } as unknown as Selection,
    );

    await user.click(within(gridRows()[0]).getByText("Open"));

    expect(screen.queryByTestId("detail-state")).not.toBeInTheDocument();
  });

  it("hides Where, State and Age below md but keeps them in the DOM", () => {
    renderTable();

    for (const name of ["Where", "State", "Age"]) {
      const header = screen.getByRole("columnheader", { name: new RegExp(name) });
      expect(hasClass(header, "hidden")).toBe(true);
      expect(hasClass(header, "md:table-cell")).toBe(true);
    }
    for (const name of ["Severity", "Finding"]) {
      const header = screen.getByRole("columnheader", { name: new RegExp(name) });
      expect(hasClass(header, "hidden")).toBe(false);
    }

    // Severity, Finding, Where, State, Age, and the chevron that says the row opens.
    const cells = dataCells(0);
    expect(cells).toHaveLength(6);
    for (const index of [2, 3, 4]) {
      expect(hasClass(cells[index], "hidden")).toBe(true);
      expect(hasClass(cells[index], "md:table-cell")).toBe(true);
    }
    for (const index of [0, 1, 5]) {
      expect(hasClass(cells[index], "hidden")).toBe(false);
    }
  });

  it("repeats the hidden columns as one meta line under the title", () => {
    renderTable();
    const titleCell = dataCells(1)[1];

    expect(titleCell).toHaveTextContent(
      `Accepted risk · Last seen ${formatDate("2025-02-01T00:00:00Z")}`,
    );
    const meta = within(titleCell).getByText(/Last seen/);
    expect(hasClass(meta, "md:hidden")).toBe(true);
  });

  it("shows where a finding was seen, in the shortest form it has", () => {
    expect(locationText(undefined)).toBe("None");
    expect(locationText({ summary: "package openssh-server 9.6p1-2" })).toBe(
      "package openssh-server 9.6p1-2",
    );
    expect(locationText({ file: "internal/auth/token.go", start_line: 42 })).toBe(
      "internal/auth/token.go:42",
    );
    expect(locationText({ file: "Dockerfile" })).toBe("Dockerfile");
    expect(locationText({ resource: "aws_s3_bucket.logs" })).toBe("aws_s3_bucket.logs");
    expect(locationText({})).toBe("None");
  });

  it("marks a critical or high finding that is still open with its colour on the row's edge", () => {
    renderTable();
    const rows = gridRows();

    expect(rows[0].className).toContain("--edge:var(--sev-critical)");
    expect(rows[1].className).toContain("--edge:var(--sev-high)");
    // A fixed finding, whatever its severity, is no longer a thing in the way.
    expect(rows[2].className).not.toContain("--edge");
  });

  it("reports the sort state on the sorted header and none on the others", () => {
    renderTable({ sort: { by: "title", dir: "asc" } });

    expect(screen.getByRole("columnheader", { name: /Finding/ }))
      .toHaveAttribute("aria-sort", "ascending");
    expect(screen.getByRole("columnheader", { name: /Severity/ }))
      .toHaveAttribute("aria-sort", "none");
    expect(screen.getByRole("columnheader", { name: /Age/ }))
      .toHaveAttribute("aria-sort", "none");
    expect(screen.queryByText(/Sorting applies only/)).not.toBeInTheDocument();
  });

  it("does not show the grid's empty state while rows exist", () => {
    renderTable();
    expect(screen.queryByText("Nothing to show.")).not.toBeInTheDocument();
  });
});

describe("FindingsTable selection", () => {
  it("has no checkboxes when there is nothing a person could do to a selection", () => {
    renderTable();
    expect(screen.queryAllByRole("checkbox")).toHaveLength(0);
  });

  it("gives every row a checkbox named for its finding, and one to select the page", () => {
    renderTable({ selection: NO_SELECTION });

    expect(screen.getByRole("checkbox", { name: "Select all findings on this page" }))
      .not.toBeChecked();
    for (const finding of FINDINGS) {
      expect(screen.getByRole("checkbox", { name: `Select ${finding.current_title}` }))
        .not.toBeChecked();
    }
  });

  it("reports a click on a row's checkbox without opening the finding", async () => {
    const onToggle = vi.fn();
    renderTable({ selection: { ...NO_SELECTION, onToggle } });
    const user = userEvent.setup();

    await user.click(screen.getByRole("checkbox", { name: "Select net/http DoS" }));

    expect(onToggle).toHaveBeenCalledWith("f2");
    expect(screen.queryByTestId("detail-state")).not.toBeInTheDocument();
  });

  it("shows what is selected, and marks the rows", () => {
    renderTable({ selection: { ...NO_SELECTION, keys: new Set(["f1", "f3"]) } });

    expect(screen.getByRole("checkbox", { name: "Select runc breakout" })).toBeChecked();
    expect(screen.getByRole("checkbox", { name: "Select net/http DoS" })).not.toBeChecked();
    expect(gridRows().map((r) => r.getAttribute("aria-selected"))).toEqual([
      "true",
      "false",
      "true",
    ]);
    expect(screen.getByRole("grid", { name: "Findings" })).toHaveAttribute(
      "aria-multiselectable",
      "true",
    );
  });

  it("selects the whole page, or none of it, from the header checkbox", async () => {
    const onToggleAll = vi.fn();
    renderTable({ selection: { ...NO_SELECTION, onToggleAll } });
    const user = userEvent.setup();

    await user.click(screen.getByRole("checkbox", { name: "Select all findings on this page" }));
    expect(onToggleAll).toHaveBeenLastCalledWith(true);
  });

  it("shows the header checkbox as checked when every row is, and as mixed when some are", () => {
    const { unmount } = renderTable({
      selection: { ...NO_SELECTION, keys: new Set(["f1", "f2", "f3"]) },
    });
    expect(screen.getByRole("checkbox", { name: "Select all findings on this page" }))
      .toBeChecked();
    unmount();

    renderTable({ selection: { ...NO_SELECTION, keys: new Set(["f2"]) } });
    const some = screen.getByRole("checkbox", {
      name: "Select all findings on this page",
    }) as HTMLInputElement;
    expect(some.indeterminate).toBe(true);
    expect(some).not.toBeChecked();
  });

  it("toggles the cursor row with x", () => {
    const onToggle = vi.fn();
    renderTable({ selection: { ...NO_SELECTION, onToggle } });
    const grid = screen.getByRole("grid", { name: "Findings" });

    fireEvent.keyDown(grid, { key: "j" });
    fireEvent.keyDown(gridRows()[1], { key: "x" });

    expect(onToggle).toHaveBeenCalledWith("f2");
  });
});

function DetailState() {
  const location = useLocation();
  return <div data-testid="detail-state">{JSON.stringify(location.state)}</div>;
}
