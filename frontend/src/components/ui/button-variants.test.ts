import { describe, expect, it } from "vitest";
import { buttonVariants } from "./button-variants";

describe("buttonVariants", () => {
  const classes = buttonVariants().split(" ");

  it("presses with a scale, not a 1px shift", () => {
    expect(classes).toContain("active:not-aria-[haspopup]:scale-[0.97]");
    expect(classes.some((c) => c.includes("translate-y"))).toBe(false);
  });

  it("transitions named properties on the motion tokens, never everything", () => {
    expect(classes).not.toContain("transition-all");
    expect(classes).toContain(
      "transition-[color,background-color,border-color,box-shadow,opacity,scale]",
    );
    expect(classes).toContain("duration-(--dur-instant)");
    expect(classes).toContain("ease-entering");
  });

  it("styles a link like the outline button", () => {
    const outline = buttonVariants({ variant: "outline" });
    expect(outline).toContain("bg-background");
    expect(outline).toContain("border-border");
  });
});
