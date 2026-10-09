import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it } from "vitest";
import { DisabledReason } from "./DisabledReason";

describe("DisabledReason", () => {
  it("leaves an enabled control untouched", () => {
    render(
      <DisabledReason reason={undefined}>
        <button type="button">Remove</button>
      </DisabledReason>,
    );

    const button = screen.getByRole("button", { name: "Remove" });
    expect(button.parentElement).toBe(document.body.firstElementChild);
    expect(button).not.toHaveAttribute("title");
  });

  it("puts the reason where keyboard and screen reader users can reach it", () => {
    render(
      <DisabledReason reason="Cannot remove the last project admin">
        <button type="button" disabled>Remove</button>
      </DisabledReason>,
    );

    const wrapper = screen.getByRole("button", { name: "Remove" }).parentElement!;
    expect(wrapper).toHaveAttribute("tabindex", "0");
    expect(wrapper).toHaveTextContent("Cannot remove the last project admin");
    expect(screen.getByRole("button", { name: "Remove" })).toBeDisabled();
  });

  it("shows the reason in a tooltip on hover and on keyboard focus", async () => {
    const user = userEvent.setup();
    render(
      <DisabledReason reason="Only Project Admins can unlink Admin-tier teams">
        <button type="button" disabled>Unlink</button>
      </DisabledReason>,
    );
    const popup = () => document.querySelector<HTMLElement>("[data-slot=\"tooltip-content\"]")!;
    const wrapper = screen.getByRole("button", { name: "Unlink" }).parentElement!;
    expect(popup()).not.toBeVisible();

    await user.hover(wrapper);
    await waitFor(() => expect(popup()).toBeVisible(), { timeout: 3000 });
    expect(popup()).toHaveTextContent("Only Project Admins can unlink Admin-tier teams");

    await user.unhover(wrapper);
    await waitFor(() => expect(popup()).not.toBeVisible(), { timeout: 3000 });

    await user.tab();
    expect(wrapper).toHaveFocus();
    await waitFor(() => expect(popup()).toBeVisible(), { timeout: 3000 });
  });
});
