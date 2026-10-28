import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import { Section } from "./Section";

describe("Section", () => {
  it("draws a level 2 heading by default, over the content", () => {
    render(
      <Section title="Evidence">
        <p>body</p>
      </Section>,
    );

    const heading = screen.getByRole("heading", { level: 2, name: "Evidence" });
    expect(heading).toBeVisible();
    expect(heading.parentElement?.tagName).toBe("SECTION");
    expect(screen.getByText("body")).toBeVisible();
  });

  it("draws a level 3 heading when asked", () => {
    render(<Section title="References" level={3} />);

    expect(screen.getByRole("heading", { level: 3, name: "References" })).toBeVisible();
    expect(screen.queryByRole("heading", { level: 2 })).not.toBeInTheDocument();
  });

  it("is a named region only when region is set", () => {
    const named = render(<Section title="CVE details" region />);
    expect(screen.getByRole("region", { name: "CVE details" })).toBeVisible();
    named.unmount();

    render(<Section title="CVE details" />);
    expect(screen.queryByRole("region", { name: "CVE details" })).not.toBeInTheDocument();
  });

  it("prints the description under the heading", () => {
    render(<Section title="Decide" description="Currently: Exploitable" />);

    expect(screen.getByText("Currently: Exploitable")).toBeVisible();
  });

  it("collapses to one compact row when it is empty, without its children", () => {
    render(
      <Section title="History" isEmpty empty="No history yet.">
        <p>never drawn</p>
      </Section>,
    );

    expect(screen.getByRole("heading", { level: 2, name: "History" })).toBeVisible();
    expect(screen.getByText("No history yet.")).toBeVisible();
    expect(screen.queryByText("never drawn")).not.toBeInTheDocument();
  });

  it("renders nothing when it is empty and says nothing about it", () => {
    const { container } = render(
      <Section title="History" isEmpty>
        <p>never drawn</p>
      </Section>,
    );

    expect(container).toBeEmptyDOMElement();
  });
});
