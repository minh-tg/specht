import { act, render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { Link, MemoryRouter, useNavigate } from "react-router-dom";
import { afterEach, beforeEach, expect, it, vi } from "vitest";
import { useScrollRestoration } from "./useScrollRestoration";

let scrollY: number;
let scrollHeight: number;
let scrollTo: ReturnType<typeof vi.spyOn>;

beforeEach(() => {
  scrollY = 0;
  scrollHeight = 5000;
  sessionStorage.clear();
  Object.defineProperty(window, "scrollY", { get: () => scrollY, configurable: true });
  Object.defineProperty(document.documentElement, "scrollHeight", {
    get: () => scrollHeight,
    configurable: true,
  });
  vi.spyOn(window, "innerHeight", "get").mockReturnValue(800);
  scrollTo = vi.spyOn(window, "scrollTo").mockImplementation(() => {});
});

afterEach(() => {
  vi.useRealTimers();
  vi.restoreAllMocks();
});

function Harness() {
  useScrollRestoration();
  const navigate = useNavigate();
  return (
    <div>
      <Link to="/b">Go to B</Link>
      <button type="button" onClick={() => navigate(-1)}>Back</button>
    </div>
  );
}

function renderHarness() {
  return render(
    <MemoryRouter initialEntries={["/a"]}>
      <Harness />
    </MemoryRouter>,
  );
}

function setup() {
  vi.useFakeTimers({ shouldAdvanceTime: true });
  return userEvent.setup({ advanceTimers: vi.advanceTimersByTime });
}

/** Scrolls the window the way a person does and lets the throttled save run. */
function scrollPage(y: number) {
  scrollY = y;
  act(() => {
    window.dispatchEvent(new Event("scroll"));
    vi.advanceTimersByTime(200);
  });
}

it("puts the page back where it was on Back", async () => {
  const user = setup();
  renderHarness();
  scrollPage(1200);

  await user.click(screen.getByRole("link", { name: "Go to B" }));
  expect(scrollTo).not.toHaveBeenCalled();
  await user.click(screen.getByRole("button", { name: "Back" }));

  expect(scrollTo).toHaveBeenCalledExactlyOnceWith(0, 1200);
});

it("keeps a position that had not been written yet when the link was followed", async () => {
  const user = setup();
  renderHarness();
  scrollY = 640;
  act(() => {
    window.dispatchEvent(new Event("scroll"));
  });
  await user.click(screen.getByRole("link", { name: "Go to B" }));
  await user.click(screen.getByRole("button", { name: "Back" }));

  expect(scrollTo).toHaveBeenCalledExactlyOnceWith(0, 640);
});

it("keeps a position whose scroll event had not been delivered when the link was followed", async () => {
  const user = setup();
  renderHarness();
  // scrollTo moves window.scrollY at once; the scroll event only arrives with the next frame. A
  // click in between must still save the position the person left from.
  scrollY = 640;
  await user.click(screen.getByRole("link", { name: "Go to B" }));
  await user.click(screen.getByRole("button", { name: "Back" }));

  expect(scrollTo).toHaveBeenCalledExactlyOnceWith(0, 640);
});

it("saves the position of the page being left, not the one it opens", async () => {
  const user = setup();
  renderHarness();
  scrollPage(900);
  await user.click(screen.getByRole("link", { name: "Go to B" }));
  // The shorter page B makes the browser clamp the offset and fire a scroll event after the switch.
  scrollPage(0);
  await user.click(screen.getByRole("button", { name: "Back" }));

  expect(scrollTo).toHaveBeenCalledExactlyOnceWith(0, 900);
});

it("does not restore a position for a page opened by a link", async () => {
  const user = setup();
  renderHarness();
  scrollPage(700);
  await user.click(screen.getByRole("link", { name: "Go to B" }));
  scrollPage(300);

  expect(scrollTo).not.toHaveBeenCalled();
});

it("waits for rows that are not rendered yet, then restores once", async () => {
  const user = setup();
  renderHarness();
  scrollPage(1200);
  await user.click(screen.getByRole("link", { name: "Go to B" }));

  scrollHeight = 600;
  await user.click(screen.getByRole("button", { name: "Back" }));
  expect(scrollTo).not.toHaveBeenCalled();

  scrollHeight = 5000;
  await act(async () => {
    document.body.append(document.createElement("div"));
  });
  expect(scrollTo).toHaveBeenCalledExactlyOnceWith(0, 1200);
});

it("gives up once the person has scrolled or typed", async () => {
  const user = setup();
  renderHarness();
  scrollPage(1200);
  await user.click(screen.getByRole("link", { name: "Go to B" }));
  scrollHeight = 600;
  await user.click(screen.getByRole("button", { name: "Back" }));

  window.dispatchEvent(new Event("wheel"));
  scrollHeight = 5000;
  await act(async () => {
    document.body.append(document.createElement("div"));
  });
  expect(scrollTo).not.toHaveBeenCalled();
});

it("hands scrolling to the router while mounted and gives it back after", () => {
  history.scrollRestoration = "auto";
  const { unmount } = renderHarness();
  expect(history.scrollRestoration).toBe("manual");
  unmount();
  expect(history.scrollRestoration).toBe("auto");
});

it("still works when session storage is blocked", async () => {
  const user = setup();
  vi.spyOn(window, "sessionStorage", "get").mockImplementation(() => {
    throw new Error("blocked");
  });
  renderHarness();
  scrollPage(400);
  await user.click(screen.getByRole("link", { name: "Go to B" }));
  await user.click(screen.getByRole("button", { name: "Back" }));

  expect(scrollTo).not.toHaveBeenCalled();
});
