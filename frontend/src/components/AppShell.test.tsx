import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { Link, MemoryRouter, Route, Routes, useNavigate } from "react-router-dom";
import { afterEach, beforeEach, expect, it, vi } from "vitest";
import { AppShell } from "./AppShell";

function Boom(): never {
  throw new Error("render failure");
}

function BackButton() {
  const navigate = useNavigate();
  return (
    <button type="button" onClick={() => navigate(-1)}>
      Back
    </button>
  );
}

function renderShell(initialPath = "/a") {
  return render(
    <MemoryRouter initialEntries={[initialPath]}>
      <AppShell
        header={
          <nav aria-label="Main">
            <Link to="/a">Page A</Link>
          </nav>
        }
      >
        <Routes>
          <Route
            path="/a"
            element={
              <div>
                <h1>Page A</h1>
                <Link to="/b">Go to B</Link>
                <Link to="/a?filter=1">Filter A</Link>
                <Link to="/boom">Go to broken page</Link>
              </div>
            }
          />
          <Route path="/b" element={<h1>Page B</h1>} />
          <Route path="/boom" element={<Boom />} />
        </Routes>
      </AppShell>
    </MemoryRouter>,
  );
}

beforeEach(() => {
  vi.spyOn(window, "scrollTo").mockImplementation(() => {});
});

afterEach(() => {
  vi.restoreAllMocks();
});

it("makes the skip link the first focusable element and gives it a target", async () => {
  const user = userEvent.setup();
  renderShell();

  await user.tab();
  const skip = screen.getByRole("link", { name: "Skip to main content" });
  expect(skip).toHaveFocus();
  expect(skip).toHaveAttribute("href", "#main-content");
});

it("moves focus to the main landmark when the skip link is activated", async () => {
  const user = userEvent.setup();
  renderShell();

  const main = screen.getByRole("main");
  expect(main).toHaveAttribute("id", "main-content");
  expect(main).toHaveAttribute("tabindex", "-1");

  await user.click(screen.getByRole("link", { name: "Skip to main content" }));
  expect(main).toHaveFocus();
});

it("does not steal focus on the first render", () => {
  renderShell();

  expect(screen.getByRole("main")).not.toHaveFocus();
  expect(window.scrollTo).not.toHaveBeenCalled();
});

it("moves focus to main and scrolls to the top when the pathname changes", async () => {
  const user = userEvent.setup();
  renderShell();

  await user.click(screen.getByRole("link", { name: "Go to B" }));

  expect(await screen.findByRole("heading", { name: "Page B" })).toBeInTheDocument();
  expect(screen.getByRole("main")).toHaveFocus();
  expect(window.scrollTo).toHaveBeenCalledWith(0, 0);
});

it("keeps the scroll position on back navigation", async () => {
  const user = userEvent.setup();
  render(
    <MemoryRouter initialEntries={["/a", "/b"]}>
      <AppShell
        header={
          <nav aria-label="Main">
            <Link to="/b">Page B</Link>
          </nav>
        }
      >
        <Routes>
          <Route path="/a" element={<h1>Page A</h1>} />
          <Route path="/b" element={<BackButton />} />
        </Routes>
      </AppShell>
    </MemoryRouter>,
  );

  await user.click(screen.getByRole("button", { name: "Back" }));

  expect(await screen.findByRole("heading", { name: "Page A" })).toBeInTheDocument();
  expect(screen.getByRole("main")).toHaveFocus();
  expect(window.scrollTo).not.toHaveBeenCalled();
});

it("keeps focus where it is when only the search string changes", async () => {
  const user = userEvent.setup();
  renderShell();

  const filter = screen.getByRole("link", { name: "Filter A" });
  await user.click(filter);

  expect(screen.getByRole("main")).not.toHaveFocus();
  expect(window.scrollTo).not.toHaveBeenCalled();
});

it("shows a recoverable message when a page crashes and keeps the header", async () => {
  vi.spyOn(console, "error").mockImplementation(() => {});
  const user = userEvent.setup();
  renderShell();

  await user.click(screen.getByRole("link", { name: "Go to broken page" }));

  expect(await screen.findByRole("alert")).toHaveTextContent("Something went wrong");
  expect(screen.getByRole("button", { name: "Reload" })).toBeInTheDocument();
  expect(screen.getByRole("navigation", { name: "Main" })).toBeInTheDocument();
});

it("recovers from a crashed page when the user navigates away", async () => {
  vi.spyOn(console, "error").mockImplementation(() => {});
  const user = userEvent.setup();
  renderShell("/boom");

  expect(await screen.findByRole("alert")).toBeInTheDocument();
  await user.click(screen.getByRole("link", { name: "Page A" }));

  expect(await screen.findByRole("heading", { name: "Page A" })).toBeInTheDocument();
  expect(screen.queryByRole("alert")).not.toBeInTheDocument();
});

it("reloads the page from the error fallback", async () => {
  vi.spyOn(console, "error").mockImplementation(() => {});
  const reload = vi.fn();
  Object.defineProperty(window, "location", {
    configurable: true,
    value: { ...window.location, reload },
  });
  const user = userEvent.setup();
  renderShell("/boom");

  await user.click(await screen.findByRole("button", { name: "Reload" }));

  expect(reload).toHaveBeenCalledTimes(1);
});
