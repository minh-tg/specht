import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { useState } from "react";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { PasswordField } from "./PasswordField";

const { loadStrengthEngine, check } = vi.hoisted(() => {
  const check = vi.fn();
  return { check, loadStrengthEngine: vi.fn(() => Promise.resolve({ check })) };
});
vi.mock("./PasswordStrengthEngine", () => ({ loadStrengthEngine }));

function Harness({ initial = "", userInputs }: {
  readonly initial?: string;
  readonly userInputs?: readonly string[];
}) {
  const [value, setValue] = useState(initial);
  return (
    <PasswordField
      label="Password"
      rulesId="rules"
      value={value}
      onChange={(e) => setValue(e.target.value)}
      {...(userInputs ? { userInputs } : {})}
    />
  );
}

function scoreAs(score: number, warning: string | null = null, suggestions: string[] = []) {
  check.mockReturnValue({ score, feedback: { warning, suggestions } });
}

describe("PasswordField", () => {
  beforeEach(() => {
    loadStrengthEngine.mockClear();
    check.mockReset();
    scoreAs(0);
  });

  it("does not load the estimator until the field is focused", async () => {
    const user = userEvent.setup();
    render(<Harness />);
    expect(loadStrengthEngine).not.toHaveBeenCalled();

    await user.click(screen.getByLabelText("Password"));
    expect(loadStrengthEngine).toHaveBeenCalledTimes(1);
  });

  it("loads the estimator when the field starts with a value", () => {
    render(<Harness initial="prefilled-by-a-manager" />);
    expect(loadStrengthEngine).toHaveBeenCalledTimes(1);
  });

  it("shows no meter while the field is empty", async () => {
    const user = userEvent.setup();
    render(<Harness />);
    await user.click(screen.getByLabelText("Password"));
    await waitFor(() => expect(loadStrengthEngine).toHaveBeenCalled());
    expect(screen.queryByRole("meter")).not.toBeInTheDocument();
  });

  it.each([
    [0, "Weak", "1"],
    [1, "Weak", "1"],
    [2, "Fair", "2"],
    [3, "Good", "3"],
    [4, "Strong", "4"],
  ])("shows score %i as %s, in text and as the meter's value", async (score, label, now) => {
    scoreAs(score);
    render(<Harness initial="some-password" />);
    const meter = await screen.findByRole("meter", { name: "Strength" });
    expect(meter).toHaveAttribute("aria-valuetext", label);
    expect(meter).toHaveAttribute("aria-valuenow", now);
    expect(meter).toHaveAttribute("aria-valuemax", "4");
    expect(screen.getByText(label)).toBeVisible();
  });

  it("shows one line of advice, the warning before any suggestion", async () => {
    scoreAs(1, "This is a top-10 common password.", ["Add more words."]);
    render(<Harness initial="password1" />);
    expect(await screen.findByText("This is a top-10 common password.")).toBeInTheDocument();
    expect(screen.queryByText("Add more words.")).not.toBeInTheDocument();
  });

  it("falls back to the first suggestion when there is no warning", async () => {
    scoreAs(2, null, ["Add more words.", "Avoid dates."]);
    render(<Harness initial="tr0ub4dor" />);
    expect(await screen.findByText("Add more words.")).toBeInTheDocument();
    expect(screen.queryByText("Avoid dates.")).not.toBeInTheDocument();
  });

  it("passes the account's words to the estimator, skipping empty ones", async () => {
    render(<Harness initial="ada-1815" userInputs={["ada@example.com", ""]} />);
    await screen.findByRole("meter");
    expect(check).toHaveBeenLastCalledWith("ada-1815", ["ada@example.com"]);
  });

  it("keeps the rules list as the input's description", () => {
    render(<Harness initial="abc" />);
    expect(screen.getByLabelText("Password")).toHaveAttribute("aria-describedby", "rules");
    expect(screen.getByRole("list", { name: "Requirements" })).toHaveAttribute("id", "rules");
  });

  it("shows no meter when the estimator fails to load, and keeps the rules", async () => {
    loadStrengthEngine.mockReturnValueOnce(Promise.reject(new Error("chunk failed")));
    render(<Harness initial="abc" />);
    await waitFor(() => expect(loadStrengthEngine).toHaveBeenCalled());
    expect(screen.queryByRole("meter")).not.toBeInTheDocument();
    expect(screen.getByRole("list", { name: "Requirements" })).toBeInTheDocument();
  });
});
