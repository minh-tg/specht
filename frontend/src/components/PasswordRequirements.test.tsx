import { isPasswordValid } from "@/lib/passwordRules";
import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import { PasswordRequirements } from "./PasswordRequirements";

describe("PasswordRequirements", () => {
  it("shows nothing until the first character", () => {
    const { container } = render(<PasswordRequirements id="r" value="" />);
    expect(container).toBeEmptyDOMElement();
  });

  it("lists every rule as not met after one character, with the state in words", () => {
    render(<PasswordRequirements id="r" value="a" />);
    const items = screen.getAllByRole("listitem");
    expect(items).toHaveLength(2);
    expect(items[0]).toHaveTextContent("At least 8 characters (not met)");
    expect(items[0]).toHaveAttribute("data-met", "false");
    expect(items[1]).toHaveTextContent("At most 72 bytes (met)");
    expect(items[1]).toHaveAttribute("data-met", "true");
  });

  it("turns a rule met as soon as it holds", () => {
    const { rerender } = render(<PasswordRequirements id="r" value="1234567" />);
    expect(screen.getByText("At least 8 characters").closest("li")).toHaveAttribute(
      "data-met",
      "false",
    );
    rerender(<PasswordRequirements id="r" value="12345678" />);
    expect(screen.getByText("At least 8 characters").closest("li")).toHaveAttribute(
      "data-met",
      "true",
    );
  });

  it("counts the upper limit in bytes, as the server does", () => {
    // 40 two-byte characters is 80 bytes: long enough, but over the limit.
    render(<PasswordRequirements id="r" value={"é".repeat(40)} />);
    expect(screen.getByText("At most 72 bytes").closest("li")).toHaveAttribute(
      "data-met",
      "false",
    );
  });
});

describe("isPasswordValid", () => {
  it("accepts 8 to 72 bytes", () => {
    expect(isPasswordValid("1234567")).toBe(false);
    expect(isPasswordValid("12345678")).toBe(true);
    expect(isPasswordValid("a".repeat(72))).toBe(true);
    expect(isPasswordValid("a".repeat(73))).toBe(false);
  });
});
