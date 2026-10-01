import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, expect, it } from "vitest";
import { ThemeToggle } from "./ThemeToggle";

beforeEach(() => {
  window.localStorage.clear();
  document.documentElement.classList.remove("dark");
});

it("starts on system and names the current choice", () => {
  render(<ThemeToggle />);

  const button = screen.getByRole("button", { name: "Theme: system (click to change)" });
  expect(button).toHaveAttribute("title", "Theme: system (click to change)");
  expect(button.querySelector("svg")).toHaveAttribute("aria-hidden", "true");
});

it("cycles system, light, dark and back, updating its name each time", async () => {
  const user = userEvent.setup();
  render(<ThemeToggle />);

  await user.click(screen.getByRole("button", { name: /^Theme: system/ }));
  expect(screen.getByRole("button", { name: "Theme: light (click to change)" }))
    .toBeInTheDocument();

  await user.click(screen.getByRole("button", { name: /^Theme: light/ }));
  expect(screen.getByRole("button", { name: "Theme: dark (click to change)" })).toBeInTheDocument();
  expect(document.documentElement).toHaveClass("dark");

  await user.click(screen.getByRole("button", { name: /^Theme: dark/ }));
  expect(screen.getByRole("button", { name: "Theme: system (click to change)" }))
    .toBeInTheDocument();
});

it("remembers the choice across mounts", async () => {
  const user = userEvent.setup();
  const first = render(<ThemeToggle />);
  await user.click(screen.getByRole("button", { name: /^Theme: system/ }));
  first.unmount();

  render(<ThemeToggle />);

  expect(screen.getByRole("button", { name: "Theme: light (click to change)" }))
    .toBeInTheDocument();
});

it("is large enough to hit", () => {
  render(<ThemeToggle />);

  expect(screen.getByRole("button")).toHaveClass("h-7", "w-7");
});
