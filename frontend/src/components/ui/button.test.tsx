import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi } from "vitest";
import { Button } from "./button";

describe("Button", () => {
  it("activates its action when selected", async () => {
    const onClick = vi.fn();
    render(<Button onClick={onClick}>Save changes</Button>);

    await userEvent.setup().click(screen.getByRole("button", { name: "Save changes" }));
    expect(onClick).toHaveBeenCalledOnce();
  });

  it("does not activate while disabled", async () => {
    const onClick = vi.fn();
    render(<Button disabled onClick={onClick}>Save changes</Button>);

    expect(screen.getByRole("button", { name: "Save changes" })).toBeDisabled();
    await userEvent.setup().click(screen.getByRole("button", { name: "Save changes" }));
    expect(onClick).not.toHaveBeenCalled();
  });
});
