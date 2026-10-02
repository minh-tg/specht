import { GLOSSARY } from "@/lib/glossary";
import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { expect, it } from "vitest";
import { InfoTip } from "./InfoTip";

const { label, short } = GLOSSARY.severityFloor;

it("is a real button named after the word it explains, with a decorative icon", () => {
  render(<InfoTip term="severityFloor" />);

  const button = screen.getByRole("button", { name: `What is ${label}?` });
  expect(button.querySelector("svg")).toHaveAttribute("aria-hidden", "true");
  expect(screen.queryByText(short)).not.toBeInTheDocument();
});

it("shows the glossary text on hover and hides it again when the pointer leaves", async () => {
  const user = userEvent.setup();
  render(<InfoTip term="severityFloor" />);

  await user.hover(screen.getByRole("button", { name: `What is ${label}?` }));
  expect(await screen.findByText(short)).toBeInTheDocument();

  await user.unhover(screen.getByRole("button", { name: `What is ${label}?` }));
  await expect.poll(() => screen.queryByText(short)).toBeNull();
});

it("shows the text for keyboard users on focus and closes on Escape", async () => {
  const user = userEvent.setup();
  render(<InfoTip term="reachability" />);

  await user.tab();
  expect(screen.getByRole("button", { name: `What is ${GLOSSARY.reachability.label}?` }))
    .toHaveFocus();
  expect(await screen.findByText(GLOSSARY.reachability.short)).toBeInTheDocument();

  await user.keyboard("{Escape}");
  await expect.poll(() => screen.queryByText(GLOSSARY.reachability.short)).toBeNull();
});

it("opens on a touch tap and closes on a second tap", async () => {
  const user = userEvent.setup();
  render(<InfoTip term="severityFloor" />);
  const button = screen.getByRole("button", { name: `What is ${label}?` });

  await user.pointer({ keys: "[TouchA]", target: button });
  expect(await screen.findByText(short)).toBeInTheDocument();

  await user.pointer({ keys: "[TouchA]", target: button });
  await expect.poll(() => screen.queryByText(short)).toBeNull();
});
