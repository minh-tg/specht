import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import { Input } from "./input";
import { Textarea } from "./textarea";

/** The percentage of `--input` a class paints, e.g. `dark:bg-input/30` gives 30. */
function fill(element: HTMLElement, prefix: string): number {
  const match = element.className.split(/\s+/).find((c) =>
    c.startsWith(`${prefix}bg-input/`) && !c.slice(prefix.length).includes(":")
  );
  if (!match) throw new Error(`no ${prefix}bg-input/N class on ${element.className}`);
  return Number(match.slice(match.lastIndexOf("/") + 1));
}

describe.each([
  ["Input", () => <Input aria-label="field" />],
  ["Textarea", () => <Textarea aria-label="field" />],
])("%s in dark mode", (_, ui) => {
  it("is dimmer when disabled than when enabled, never a brighter patch", () => {
    render(ui());
    const field = screen.getByLabelText("field");

    // In dark, --input is a mid grey and the enabled field is a faint lift of it. A disabled field
    // that took a larger share (the light-mode habit) would be the brightest thing on the page.
    expect(fill(field, "dark:disabled:")).toBeLessThan(fill(field, "dark:"));
  });
});
