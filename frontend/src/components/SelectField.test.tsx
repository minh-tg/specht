import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { useState } from "react";
import { describe, expect, it } from "vitest";
import { SelectField } from "./SelectField";

const OPTIONS = [
  { value: "", label: "All severities" },
  { value: "critical", label: "Critical" },
  { value: "high", label: "High" },
];

function Harness({ initial = "" }: { initial?: string; }) {
  const [value, setValue] = useState(initial);
  return (
    <>
      <SelectField
        aria-label="Filter by severity"
        value={value}
        onValueChange={setValue}
        options={OPTIONS}
      />
      <output data-testid="value">{value === "" ? "(empty)" : value}</output>
    </>
  );
}

describe("SelectField", () => {
  it("shows the label of the current value, including the empty choice", () => {
    render(<Harness />);
    expect(screen.getByRole("combobox", { name: "Filter by severity" })).toHaveTextContent(
      "All severities",
    );
  });

  it("opens, lists the options and reports the picked value", async () => {
    const user = userEvent.setup();
    render(<Harness />);

    await user.click(screen.getByRole("combobox", { name: "Filter by severity" }));
    await user.click(await screen.findByRole("option", { name: "Critical" }));

    expect(screen.getByTestId("value")).toHaveTextContent("critical");
    expect(screen.getByRole("combobox", { name: "Filter by severity" })).toHaveTextContent(
      "Critical",
    );
  });

  it("can go back to the empty choice", async () => {
    const user = userEvent.setup();
    render(<Harness initial="high" />);

    await user.click(screen.getByRole("combobox", { name: "Filter by severity" }));
    await user.click(await screen.findByRole("option", { name: "All severities" }));

    expect(screen.getByTestId("value")).toHaveTextContent("(empty)");
  });

  it("is operable from the keyboard", async () => {
    const user = userEvent.setup();
    render(<Harness />);

    screen.getByRole("combobox", { name: "Filter by severity" }).focus();
    await user.keyboard("{Enter}");
    await user.keyboard("{ArrowDown}{Enter}");

    expect(screen.getByTestId("value")).not.toHaveTextContent("(empty)");
  });
});
