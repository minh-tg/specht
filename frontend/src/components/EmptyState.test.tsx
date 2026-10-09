import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import { EmptyState } from "./EmptyState";

describe("EmptyState", () => {
  it("says what is empty, why, and offers the next action", () => {
    render(
      <EmptyState
        title="No company teams exist yet."
        description="Teams grant a role to many people at once."
        action={<button type="button">Create First Team</button>}
      />,
    );

    expect(screen.getByText("No company teams exist yet.")).toBeInTheDocument();
    expect(screen.getByText("Teams grant a role to many people at once.")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Create First Team" })).toBeInTheDocument();
  });

  it("renders just the title when there is nothing more to say", () => {
    const { container } = render(<EmptyState title="Nothing here." />);

    expect(screen.getByText("Nothing here.")).toBeInTheDocument();
    expect(container.querySelectorAll("p")).toHaveLength(1);
    expect(screen.queryByRole("button")).not.toBeInTheDocument();
  });
});
