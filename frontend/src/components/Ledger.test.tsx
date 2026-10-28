import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { useState } from "react";
import { Ledger, LedgerEntry } from "./Ledger";

function Harness(
  { initiallyOpen = false, resolved = false }: { initiallyOpen?: boolean; resolved?: boolean; },
) {
  const [open, setOpen] = useState(initiallyOpen);
  return (
    <Ledger label="Blockers">
      <LedgerEntry
        index={1}
        open={open}
        onOpenChange={setOpen}
        summary={<span>openssh-server</span>}
        tone="critical"
        resolved={resolved}
      >
        <button type="button">Copy fix</button>
      </LedgerEntry>
    </Ledger>
  );
}

describe("Ledger", () => {
  it("names the list and numbers the entries", () => {
    render(<Harness />);
    expect(screen.getByRole("list", { name: "Blockers" })).toBeInTheDocument();
    expect(screen.getByText("01")).toBeInTheDocument();
  });

  it("names the toggle with its visible text, so a speech user can say what they see", () => {
    render(<Harness />);
    expect(screen.getByRole("button", { name: "01 openssh-server" })).toBeInTheDocument();
  });

  it("opens and closes with the summary button, and says so to assistive technology", async () => {
    const user = userEvent.setup();
    render(<Harness />);
    const toggle = screen.getByRole("button", { name: "01 openssh-server" });
    expect(toggle).toHaveAttribute("aria-expanded", "false");

    await user.click(toggle);
    expect(toggle).toHaveAttribute("aria-expanded", "true");

    await user.click(toggle);
    expect(toggle).toHaveAttribute("aria-expanded", "false");
  });

  it("marks closed detail inert, so its controls leave the tab order and the accessibility tree", async () => {
    const user = userEvent.setup();
    const { container } = render(<Harness />);
    // jsdom does not apply `inert`, so the attribute itself is what is checked.
    expect(container.querySelector("[inert]")).toContainElement(screen.getByText("Copy fix"));

    await user.click(screen.getByRole("button", { name: "01 openssh-server" }));
    expect(container.querySelector("[inert]")).toBeNull();
  });

  it("paints the edge of an open entry with its severity", () => {
    render(<Harness initiallyOpen />);
    const entry = screen.getByRole("listitem");
    expect(entry.className).toContain("shadow-[inset_4px_0_0_var(--sev-critical)]");
    expect(entry.className).toContain("bg-card");
  });

  it("leaves a closed entry on the page, without the edge", () => {
    render(<Harness />);
    expect(screen.getByRole("listitem").className).not.toContain("bg-card");
  });

  it("dims a handled entry and drops its edge", () => {
    render(<Harness initiallyOpen resolved />);
    const entry = screen.getByRole("listitem");
    expect(entry).toHaveAttribute("data-resolved", "true");
    expect(entry.className).toContain("opacity-60");
    expect(entry.className).not.toContain("shadow-[inset_4px_0_0_var(--sev-critical)]");
  });

  it("links the toggle to the region it controls", () => {
    render(<Harness initiallyOpen />);
    const toggle = screen.getByRole("button", { name: "01 openssh-server" });
    const controlled = toggle.getAttribute("aria-controls");
    expect(controlled).toBeTruthy();
    expect(document.getElementById(controlled ?? "")).toContainElement(
      screen.getByRole("button", { name: "Copy fix" }),
    );
  });
});
