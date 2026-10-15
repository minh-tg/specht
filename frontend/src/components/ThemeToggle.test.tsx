import { resetThemeStore } from "@/lib/theme";
import { act, render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, expect, it } from "vitest";
import { ThemeToggle } from "./ThemeToggle";

beforeEach(() => {
  resetThemeStore();
  window.localStorage.clear();
  document.documentElement.classList.remove("dark");
});

it("starts on system and names the current and the next choice in words", () => {
  render(<ThemeToggle />);

  const button = screen.getByRole("button", { name: "Theme: system. Switch to light" });
  expect(button).toHaveAttribute("title", "Theme: system. Switch to light");
  expect(button.querySelector("svg")).toHaveAttribute("aria-hidden", "true");
});

it("cycles system, light, dark and back, updating its name each time", async () => {
  const user = userEvent.setup();
  render(<ThemeToggle />);

  await user.click(screen.getByRole("button", { name: /^Theme: system/ }));
  expect(screen.getByRole("button", { name: "Theme: light. Switch to dark" }))
    .toBeInTheDocument();

  await user.click(screen.getByRole("button", { name: /^Theme: light/ }));
  expect(screen.getByRole("button", { name: "Theme: dark. Switch to system" }))
    .toBeInTheDocument();
  expect(document.documentElement).toHaveClass("dark");

  await user.click(screen.getByRole("button", { name: /^Theme: dark/ }));
  expect(screen.getByRole("button", { name: "Theme: system. Switch to light" }))
    .toBeInTheDocument();
});

it("remembers the choice across mounts", async () => {
  const user = userEvent.setup();
  const first = render(<ThemeToggle />);
  await user.click(screen.getByRole("button", { name: /^Theme: system/ }));
  first.unmount();

  render(<ThemeToggle />);

  expect(screen.getByRole("button", { name: "Theme: light. Switch to dark" }))
    .toBeInTheDocument();
});

it("follows a choice made in another tab", () => {
  render(<ThemeToggle />);

  act(() => {
    window.localStorage.setItem("specht.theme", "dark");
    window.dispatchEvent(new StorageEvent("storage", { key: "specht.theme", newValue: "dark" }));
  });

  expect(screen.getByRole("button", { name: "Theme: dark. Switch to system" }))
    .toBeInTheDocument();
});

it("is large enough to hit", () => {
  render(<ThemeToggle />);

  expect(screen.getByRole("button")).toHaveClass("h-7", "w-7");
});
