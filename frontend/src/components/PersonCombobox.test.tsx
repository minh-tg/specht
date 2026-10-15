import type { PersonSuggestion } from "@/api/memberSuggestions";
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { useState } from "react";
import { describe, expect, it } from "vitest";
import { PersonCombobox } from "./PersonCombobox";

const ADA: PersonSuggestion = {
  user_id: "u-ada",
  email: "ada@acme.example",
  display_name: "Ada Lovelace",
};
const LOVE: PersonSuggestion = { user_id: "u-love", email: "l.ove@acme.example", display_name: "" };

interface HarnessProps {
  readonly suggestions?: readonly PersonSuggestion[];
  readonly active?: (value: string) => boolean;
  readonly searching?: boolean;
  readonly unavailable?: boolean;
}

/** A labelled field holding the text, as the add-member dialogs do. */
function Harness(
  { suggestions = [], active = (v) => v.length >= 3, searching, unavailable }: HarnessProps,
) {
  const [value, setValue] = useState("");
  return (
    <>
      <label htmlFor="person">Email address</label>
      <PersonCombobox
        id="person"
        value={value}
        onValueChange={setValue}
        suggestions={suggestions}
        active={active(value)}
        searching={searching}
        unavailable={unavailable}
      />
      <output data-testid="value">{value}</output>
    </>
  );
}

function field() {
  return screen.getByLabelText("Email address");
}

describe("PersonCombobox", () => {
  it("shows each person with the email first and the display name as secondary text", async () => {
    const user = userEvent.setup();
    render(<Harness suggestions={[ADA, LOVE]} />);
    await user.type(field(), "ada");

    const options = await screen.findAllByRole("option");
    expect(options.map((o) => o.textContent)).toEqual([
      "ada@acme.example" + "Ada Lovelace",
      "l.ove@acme.example",
    ]);
    expect(options[0]?.firstElementChild?.textContent).toBe("ada@acme.example");
  });

  it("keeps a server match whose email does not contain the typed text", async () => {
    const user = userEvent.setup();
    render(<Harness suggestions={[LOVE, ADA]} />);
    await user.type(field(), "lovel");

    expect(await screen.findByRole("option", { name: /ada@acme\.example/ })).toBeInTheDocument();
    expect(screen.getByRole("option", { name: /l\.ove@acme\.example/ })).toBeInTheDocument();
  });

  it("fills in the email, never the name, when a person is chosen with the keyboard", async () => {
    const user = userEvent.setup();
    render(<Harness suggestions={[ADA]} />);
    await user.type(field(), "lov");
    await screen.findByRole("option");

    await user.keyboard("{ArrowDown}{Enter}");
    expect(field()).toHaveValue("ada@acme.example");
    expect(screen.getByTestId("value")).toHaveTextContent("ada@acme.example");
  });

  it("closes on Escape and keeps the typed text", async () => {
    const user = userEvent.setup();
    render(<Harness suggestions={[ADA]} />);
    await user.type(field(), "ada");
    await screen.findByRole("option");

    await user.keyboard("{Escape}");
    await waitFor(() => expect(screen.queryByRole("option")).not.toBeInTheDocument());
    expect(field()).toHaveValue("ada");
  });

  it("accepts an exact address for someone who is not offered", async () => {
    const user = userEvent.setup();
    render(<Harness suggestions={[]} />);
    await user.type(field(), "new.person@acme.example");
    expect(screen.getByTestId("value")).toHaveTextContent("new.person@acme.example");
  });

  it("stays closed for a complete address that matches nobody, so the fields below stay reachable", async () => {
    const user = userEvent.setup();
    const { rerender } = render(<Harness suggestions={[]} />);
    await user.type(field(), "new.person@acme.example");
    expect(screen.queryByRole("listbox")).not.toBeInTheDocument();
    expect(screen.queryByText(/No matching people/)).not.toBeInTheDocument();

    rerender(<Harness suggestions={[ADA]} />);
    await user.type(field(), "x");
    expect(await screen.findByRole("option")).toBeInTheDocument();
  });

  it("says when nobody matches and how to add someone anyway", async () => {
    const user = userEvent.setup();
    render(<Harness suggestions={[]} />);
    await user.type(field(), "zzz");
    expect(
      await screen.findByText("No matching people. Type the full email address to add someone."),
    ).toBeInTheDocument();
  });

  it("says suggestions are unavailable when the lookup failed", async () => {
    const user = userEvent.setup();
    render(<Harness suggestions={[]} unavailable />);
    await user.type(field(), "zzz");
    expect(await screen.findByText(/Suggestions are not available right now/)).toBeInTheDocument();
  });

  it("stays closed below the minimum length and while a first lookup runs", async () => {
    const user = userEvent.setup();
    const { rerender } = render(<Harness suggestions={[ADA]} />);
    await user.type(field(), "ad");
    expect(screen.queryByRole("listbox")).not.toBeInTheDocument();

    rerender(<Harness suggestions={[]} searching />);
    await user.type(field(), "a");
    expect(screen.queryByRole("listbox")).not.toBeInTheDocument();
    expect(screen.queryByText(/No matching people/)).not.toBeInTheDocument();
  });

  it("announces the search while the list is still closed", async () => {
    const user = userEvent.setup();
    render(<Harness suggestions={[]} searching />);
    await user.type(field(), "ada");
    expect(screen.queryByRole("listbox")).not.toBeInTheDocument();
    expect(screen.getByText("Searching for people.")).toHaveAttribute("role", "status");
  });

  it("announces how many people were found", async () => {
    const user = userEvent.setup();
    render(<Harness suggestions={[ADA, LOVE]} />);
    await user.type(field(), "ada");
    expect(await screen.findByText("2 people found.")).toBeInTheDocument();
  });
});
