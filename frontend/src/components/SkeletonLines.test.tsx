import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import { SkeletonLines } from "./SkeletonLines";

describe("SkeletonLines", () => {
  it("announces what is loading and renders one skeleton per line", () => {
    const { container } = render(<SkeletonLines label="Loading members" lines={4} />);
    expect(screen.getByRole("status", { name: "Loading members" })).toBeInTheDocument();
    expect(container.querySelectorAll("[data-slot='skeleton']")).toHaveLength(4);
  });

  it("defaults to three lines", () => {
    const { container } = render(<SkeletonLines label="Loading" />);
    expect(container.querySelectorAll("[data-slot='skeleton']")).toHaveLength(3);
  });
});
