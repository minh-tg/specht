import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter, useLocation } from "react-router-dom";
import { describe, expect, it } from "vitest";
import { useFindingsQuery } from "./useFindingsQuery";

function Probe() {
  const { filters, sort, offset, setFilter, setSort, setPage, clearFilters } = useFindingsQuery();
  const location = useLocation();
  return (
    <div>
      <span data-testid="search">{location.search}</span>
      <span data-testid="filters">{`${filters.severity}|${filters.status}|${filters.kind}`}</span>
      <span data-testid="sort">{`${sort.by}:${sort.dir}`}</span>
      <span data-testid="offset">{offset}</span>
      <button onClick={() => setFilter("severity", "high")}>filter severity</button>
      <button onClick={() => setFilter("severity", "")}>clear severity</button>
      <button onClick={() => setSort("title", "asc")}>sort title</button>
      <button onClick={() => setPage(40)}>page 40</button>
      <button onClick={clearFilters}>clear filters</button>
    </div>
  );
}

function renderAt(initialPath: string) {
  return render(
    <MemoryRouter initialEntries={[initialPath]}>
      <Probe />
    </MemoryRouter>,
  );
}

describe("useFindingsQuery", () => {
  it("reads the filters, page offset and default sort from the URL", () => {
    renderAt("/findings?severity=high&status=open&kind=sca&offset=40");

    expect(screen.getByTestId("filters")).toHaveTextContent("high|open|sca");
    expect(screen.getByTestId("offset")).toHaveTextContent("40");
    expect(screen.getByTestId("sort")).toHaveTextContent("severity:desc");
  });

  it("falls back to empty filters and the first page when the URL is bare", () => {
    renderAt("/findings");

    expect(screen.getByTestId("filters")).toHaveTextContent("||");
    expect(screen.getByTestId("offset")).toHaveTextContent("0");
    expect(screen.getByTestId("sort")).toHaveTextContent("severity:desc");
    expect(screen.getByTestId("search")).toHaveTextContent("");
  });

  it("writes a filter to the URL and returns to the first page", async () => {
    renderAt("/findings?offset=40");
    const user = userEvent.setup();

    await user.click(screen.getByRole("button", { name: "filter severity" }));

    expect(screen.getByTestId("filters")).toHaveTextContent("high||");
    expect(screen.getByTestId("offset")).toHaveTextContent("0");
    const search = screen.getByTestId("search").textContent ?? "";
    expect(search).toContain("severity=high");
    expect(search).toContain("offset=0");
  });

  it("removes a filter from the URL when it is cleared", async () => {
    renderAt("/findings?severity=high&offset=40");
    const user = userEvent.setup();

    await user.click(screen.getByRole("button", { name: "clear severity" }));

    expect(screen.getByTestId("filters")).toHaveTextContent("||");
    expect(screen.getByTestId("search").textContent).not.toContain("severity");
  });

  it("keeps the sort out of the URL", async () => {
    renderAt("/findings");
    const user = userEvent.setup();

    await user.click(screen.getByRole("button", { name: "sort title" }));

    expect(screen.getByTestId("sort")).toHaveTextContent("title:asc");
    expect(screen.getByTestId("search")).toHaveTextContent("");
  });

  it("moves to the requested page", async () => {
    renderAt("/findings");
    const user = userEvent.setup();

    await user.click(screen.getByRole("button", { name: "page 40" }));

    expect(screen.getByTestId("offset")).toHaveTextContent("40");
    expect(screen.getByTestId("search")).toHaveTextContent("offset=40");
  });

  it("clears every filter and returns to the first page", async () => {
    renderAt("/findings?severity=high&status=open&kind=sca&offset=40");
    const user = userEvent.setup();

    await user.click(screen.getByRole("button", { name: "clear filters" }));

    expect(screen.getByTestId("filters")).toHaveTextContent("||");
    expect(screen.getByTestId("offset")).toHaveTextContent("0");
    const search = screen.getByTestId("search").textContent ?? "";
    expect(search).not.toContain("severity");
    expect(search).not.toContain("status");
    expect(search).not.toContain("kind");
    expect(search).toContain("offset=0");
  });
});
