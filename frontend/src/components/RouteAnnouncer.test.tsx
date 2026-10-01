import { AppShell } from "@/components/AppShell";
import { useDocumentTitle } from "@/lib/useDocumentTitle";
import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { Link, MemoryRouter, Route, Routes } from "react-router-dom";
import { beforeEach, expect, it, vi } from "vitest";

function PageA() {
  useDocumentTitle("Alpha");
  return (
    <div>
      <h1>Alpha</h1>
      <Link to="/b">Go to B</Link>
      <Link to="/a?filter=1">Filter A</Link>
    </div>
  );
}

function PageB() {
  useDocumentTitle("Beta");
  return <h1>Beta</h1>;
}

function renderApp() {
  return render(
    <MemoryRouter initialEntries={["/a"]}>
      <AppShell header={<nav aria-label="Main" />}>
        <Routes>
          <Route path="/a" element={<PageA />} />
          <Route path="/b" element={<PageB />} />
        </Routes>
      </AppShell>
    </MemoryRouter>,
  );
}

beforeEach(() => {
  document.title = "";
  vi.spyOn(window, "scrollTo").mockImplementation(() => {});
});

it("stays silent on the first render", () => {
  renderApp();

  expect(screen.getByRole("status")).toBeEmptyDOMElement();
});

it("announces the title of the page the user navigated to", async () => {
  const user = userEvent.setup();
  renderApp();

  await user.click(screen.getByRole("link", { name: "Go to B" }));

  expect(await screen.findByRole("heading", { name: "Beta" })).toBeInTheDocument();
  expect(screen.getByRole("status")).toHaveTextContent("Beta · Specht");
});

it("does not announce a search-only change", async () => {
  const user = userEvent.setup();
  renderApp();

  await user.click(screen.getByRole("link", { name: "Filter A" }));

  expect(screen.getByRole("status")).toBeEmptyDOMElement();
});
