import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import { PasswordStrength } from "./PasswordStrength";

// These run the real estimator and its dictionaries, the same chunks the browser loads lazily.
describe("PasswordStrength with the real estimator", () => {
  it("rates a listed password as weak and says why", async () => {
    render(<PasswordStrength value="password1" active />);
    const meter = await screen.findByRole("meter", { name: "Strength" });
    expect(meter).toHaveAttribute("aria-valuetext", "Weak");
    expect(screen.getByText("This is a commonly used password.")).toBeInTheDocument();
  });

  it("rates a long unusual phrase as strong", async () => {
    render(<PasswordStrength value="quartz-heron-velvet-orbit-41" active />);
    const meter = await screen.findByRole("meter", { name: "Strength" });
    expect(meter).toHaveAttribute("aria-valuetext", "Strong");
  });

  it("counts the account's own words against the password", async () => {
    const { unmount } = render(<PasswordStrength value="zanzibarquill" active />);
    const without = (await screen.findByRole("meter")).getAttribute("aria-valuenow");
    unmount();

    render(<PasswordStrength value="zanzibarquill" active userInputs={["zanzibarquill"]} />);
    const meter = await screen.findByRole("meter");
    expect(Number(meter.getAttribute("aria-valuenow"))).toBeLessThan(Number(without));
  });

  it("renders nothing while inactive", () => {
    const { container } = render(<PasswordStrength value="password1" active={false} />);
    expect(container).toBeEmptyDOMElement();
  });
});
