import { GLOSSARY } from "@/lib/glossary";
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { expect, it } from "vitest";
import { InfoTip } from "./InfoTip";

const { label, short } = GLOSSARY.severityFloor;
const button = () => screen.getByRole("button", { name: `What is ${label}?` });
const explanation = () => screen.getByText(short);

it("is a real button named after the word it explains, with a decorative icon", () => {
  render(<InfoTip term="severityFloor" />);

  expect(button().querySelector("svg")).toHaveAttribute("aria-hidden", "true");
  expect(explanation()).not.toBeVisible();
});

it("announces the explanation as the button's description, not only its name", () => {
  render(<InfoTip term="severityFloor" />);

  // A screen reader that lands on the button hears the question and then the answer, even though
  // the popup is closed. Base UI gives the popup no role and the trigger no description itself.
  expect(button()).toHaveAccessibleDescription(short);
});

it("shows the glossary text on hover and hides it again when the pointer leaves", async () => {
  const user = userEvent.setup();
  render(<InfoTip term="severityFloor" />);

  await user.hover(button());
  await waitFor(() => expect(explanation()).toBeVisible());

  await user.unhover(button());
  await waitFor(() => expect(explanation()).not.toBeVisible());
});

it("shows the text for keyboard users on focus and closes on Escape", async () => {
  const user = userEvent.setup();
  render(<InfoTip term="reachability" />);

  await user.tab();
  expect(screen.getByRole("button", { name: `What is ${GLOSSARY.reachability.label}?` }))
    .toHaveFocus();
  await waitFor(() => expect(screen.getByText(GLOSSARY.reachability.short)).toBeVisible());

  await user.keyboard("{Escape}");
  await waitFor(() => expect(screen.getByText(GLOSSARY.reachability.short)).not.toBeVisible());
});

it("opens on a touch tap and closes on a second tap", async () => {
  const user = userEvent.setup();
  render(<InfoTip term="severityFloor" />);

  await user.pointer({ keys: "[TouchA]", target: button() });
  await waitFor(() => expect(explanation()).toBeVisible());

  await user.pointer({ keys: "[TouchA]", target: button() });
  await waitFor(() => expect(explanation()).not.toBeVisible());
});
