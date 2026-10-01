import { render } from "@testing-library/react";
import { expect, it } from "vitest";
import { BrandMark } from "./BrandMark";

it("renders a decorative svg hidden from assistive technology", () => {
  const { container } = render(<BrandMark className="h-5 w-5" />);

  const svg = container.querySelector("svg");
  expect(svg).not.toBeNull();
  expect(svg).toHaveAttribute("aria-hidden", "true");
  expect(svg).toHaveAttribute("focusable", "false");
  expect(svg).toHaveClass("h-5", "w-5");
});

it("draws the head, the beak and the crest and inherits the text colour", () => {
  const { container } = render(<BrandMark />);

  const svg = container.querySelector("svg")!;
  expect(svg).toHaveAttribute("fill", "currentColor");
  expect(svg.querySelectorAll("path")).toHaveLength(3);
});
