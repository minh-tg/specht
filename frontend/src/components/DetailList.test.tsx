import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import { DetailList, hasDetails } from "./DetailList";

describe("DetailList", () => {
  it("leaves out every row whose value is missing or blank", () => {
    render(
      <DetailList
        rows={[
          { label: "Branch", value: "main" },
          { label: "Null", value: null },
          { label: "Undefined" },
          { label: "False", value: false },
          { label: "Empty", value: "" },
          { label: "Spaces", value: "  " },
        ]}
      />,
    );

    expect(screen.getByText("Branch")).toBeVisible();
    expect(screen.getByText("main")).toBeVisible();
    for (const label of ["Null", "Undefined", "False", "Empty", "Spaces"]) {
      expect(screen.queryByText(label)).not.toBeInTheDocument();
    }
  });

  it("renders nothing when every row is empty", () => {
    const { container } = render(
      <DetailList rows={[{ label: "Commit" }, { label: "Branch", value: "  " }]} />,
    );

    expect(container).toBeEmptyDOMElement();
  });

  it("reports whether any row carries a value", () => {
    expect(hasDetails([{ label: "a" }, { label: "b", value: "x" }])).toBe(true);
    expect(hasDetails([{ label: "a" }, { label: "b", value: "  " }, { label: "c" }])).toBe(false);
  });

  it("gives a code row the mono role", () => {
    render(<DetailList rows={[{ label: "Commit", value: "abc123def456", code: true }]} />);

    expect(screen.getByText("abc123def456")).toHaveClass("font-mono", "text-code");
  });

  it("keeps a label beside its value in the inline variant", () => {
    render(<DetailList variant="inline" rows={[{ label: "Status", value: "Open" }]} />);

    const value = screen.getByText("Open");
    expect(value.tagName).toBe("DD");
    expect(screen.getByText("Status").tagName).toBe("DT");
    expect(screen.getByText("Status").nextElementSibling).toBe(value);
  });
});
