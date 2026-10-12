import { render, screen } from "@testing-library/react";
import { HoleTracker } from "./HoleTracker";

describe("HoleTracker", () => {
  it("names the progress for assistive technology", () => {
    render(<HoleTracker total={3} filled={1} />);
    expect(screen.getByRole("img", { name: "1 of 3 handled" })).toBeInTheDocument();
  });

  it("draws one hole per blocker and fills the handled ones", () => {
    const { container } = render(<HoleTracker total={3} filled={2} />);
    const holes = Array.from(container.querySelectorAll("i"));
    expect(holes.map((hole) => hole.dataset.filled)).toEqual(["true", "true", "false"]);
  });

  it("never reports more handled than there are blockers", () => {
    render(<HoleTracker total={2} filled={5} />);
    expect(screen.getByRole("img", { name: "2 of 2 handled" })).toBeInTheDocument();
  });

  it("copes with nothing to track", () => {
    const { container } = render(<HoleTracker total={0} filled={0} />);
    expect(container.querySelectorAll("i")).toHaveLength(0);
    expect(screen.getByRole("img", { name: "0 of 0 handled" })).toBeInTheDocument();
  });
});
