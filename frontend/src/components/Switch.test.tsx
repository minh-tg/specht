import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi } from "vitest";
import { Switch } from "./Switch";

describe("Switch", () => {
  it("reports its state as on or off and asks for the opposite when pressed", async () => {
    const onCheckedChange = vi.fn();
    const user = userEvent.setup();
    const { rerender } = render(
      <Switch aria-label="Watch this project" checked={false} onCheckedChange={onCheckedChange} />,
    );
    const control = screen.getByRole("switch", { name: "Watch this project" });
    expect(control).toHaveAttribute("aria-checked", "false");
    await user.click(control);
    expect(onCheckedChange).toHaveBeenLastCalledWith(true);

    rerender(
      <Switch aria-label="Watch this project" checked onCheckedChange={onCheckedChange} />,
    );
    expect(control).toHaveAttribute("aria-checked", "true");
    await user.click(control);
    expect(onCheckedChange).toHaveBeenLastCalledWith(false);
  });

  it("works from the keyboard", async () => {
    const onCheckedChange = vi.fn();
    const user = userEvent.setup();
    render(<Switch aria-label="Watch" checked={false} onCheckedChange={onCheckedChange} />);
    await user.tab();
    await user.keyboard(" ");
    expect(onCheckedChange).toHaveBeenCalledWith(true);
  });

  it("does nothing while disabled", async () => {
    const onCheckedChange = vi.fn();
    const user = userEvent.setup();
    render(<Switch aria-label="Watch" checked disabled onCheckedChange={onCheckedChange} />);
    await user.click(screen.getByRole("switch"));
    expect(onCheckedChange).not.toHaveBeenCalled();
  });
});
