import { APIError } from "@/api/client";
import { isPasswordValid, passwordPolicyMessage } from "@/lib/passwordRules";
import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import { PasswordRequirements } from "./PasswordRequirements";

describe("PasswordRequirements", () => {
  it("shows nothing until the first character", () => {
    const { container } = render(<PasswordRequirements id="r" value="" />);
    expect(container).toBeEmptyDOMElement();
  });

  it("lists the minimum as not met after one character, with the state in words", () => {
    render(<PasswordRequirements id="r" value="a" />);
    const items = screen.getAllByRole("listitem");
    expect(items).toHaveLength(1);
    expect(items[0]).toHaveTextContent("At least 8 characters (not met)");
    expect(items[0]).toHaveAttribute("data-met", "false");
  });

  it("turns a rule met as soon as it holds", () => {
    const { rerender } = render(<PasswordRequirements id="r" value="abcdefg" />);
    expect(screen.getByText("At least 8 characters").closest("li")).toHaveAttribute(
      "data-met",
      "false",
    );
    rerender(<PasswordRequirements id="r" value="abcdefgh" />);
    expect(screen.getByText("At least 8 characters").closest("li")).toHaveAttribute(
      "data-met",
      "true",
    );
  });

  it("counts the minimum in characters: four accented letters are eight bytes but too short", () => {
    render(<PasswordRequirements id="r" value="éàüö" />);
    expect(screen.getByText("At least 8 characters").closest("li")).toHaveAttribute(
      "data-met",
      "false",
    );
  });

  it("shows the byte rule only within 12 bytes of the limit, with the count", () => {
    const { rerender } = render(<PasswordRequirements id="r" value={"a".repeat(59)} />);
    expect(screen.queryByText(/bytes/)).not.toBeInTheDocument();

    rerender(<PasswordRequirements id="r" value={"a".repeat(60)} />);
    const rule = screen.getByText(/At most 72 bytes/).closest("li");
    expect(rule).toHaveTextContent("At most 72 bytes: 60 of 72 bytes (met)");
    expect(rule).toHaveAttribute("data-met", "true");
  });

  it("counts the upper limit in bytes, as the server does", () => {
    // 40 two-byte characters is 80 bytes: long enough, but over the limit.
    render(<PasswordRequirements id="r" value={"é".repeat(40)} />);
    const rule = screen.getByText(/At most 72 bytes/).closest("li");
    expect(rule).toHaveTextContent("80 of 72 bytes (not met)");
    expect(rule).toHaveAttribute("data-met", "false");
  });
});

describe("isPasswordValid", () => {
  it("accepts 8 characters to 72 bytes", () => {
    expect(isPasswordValid("abcdefg")).toBe(false);
    expect(isPasswordValid("abcdefgh")).toBe(true);
    expect(isPasswordValid("a".repeat(72))).toBe(true);
    expect(isPasswordValid("a".repeat(73))).toBe(false);
    expect(isPasswordValid("😀".repeat(19))).toBe(false);
  });
});

describe("passwordPolicyMessage", () => {
  it("returns the server's message for the two password policy codes only", () => {
    const listed = new APIError(400, "password_too_common", "This password is on a list.");
    const account = new APIError(400, "password_matches_account", "Not your email.");
    expect(passwordPolicyMessage(listed)).toBe("This password is on a list.");
    expect(passwordPolicyMessage(account)).toBe("Not your email.");
    expect(passwordPolicyMessage(new APIError(400, "invalid_password", "too short"))).toBeNull();
    expect(passwordPolicyMessage(new Error("network"))).toBeNull();
  });
});
