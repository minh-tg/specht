import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi } from "vitest";
import { ErrorState } from "./ErrorState";

describe("ErrorState", () => {
  it("announces what failed as an alert", () => {
    render(<ErrorState title="Could not load members." />);

    expect(screen.getByRole("alert")).toHaveTextContent("Could not load members.");
    expect(screen.queryByRole("button", { name: "Retry" })).not.toBeInTheDocument();
  });

  it("offers a retry that calls back", async () => {
    const onRetry = vi.fn();
    render(<ErrorState title="Could not load members." onRetry={onRetry} />);

    await userEvent.setup().click(screen.getByRole("button", { name: "Retry" }));
    expect(onRetry).toHaveBeenCalledOnce();
  });
});
