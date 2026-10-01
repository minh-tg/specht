import { getFocusable } from "@/lib/focus";
import { fireEvent, render, screen } from "@testing-library/react";
import * as React from "react";
import { FocusScope } from "./focus-scope";

function Panel({ modal = false, ...rest }: { modal?: boolean; } & Record<string, unknown>) {
  return (
    <FocusScope modal={modal} {...rest}>
      <button type="button">Close</button>
      <button type="button">Decision</button>
      <button type="button">Apply</button>
    </FocusScope>
  );
}

describe("FocusScope — the focus contracts", () => {
  it("moves focus to the initial target on mount, not to the first control", () => {
    // Rule 1: a panel exists to make a decision, so focus starts there.
    const decision = React.createRef<HTMLButtonElement>();
    render(
      <FocusScope initialFocus={decision}>
        <button type="button">Close</button>
        <button type="button" ref={decision}>
          Decision
        </button>
      </FocusScope>,
    );
    expect(screen.getByRole("button", { name: "Decision" })).toHaveFocus();
  });

  it("falls back to the first focusable descendant when no target is given", () => {
    render(<Panel />);
    expect(screen.getByRole("button", { name: "Close" })).toHaveFocus();
  });

  it("traps Tab at the end and Shift+Tab at the start", () => {
    render(<Panel modal />);
    const close = screen.getByRole("button", { name: "Close" });
    const apply = screen.getByRole("button", { name: "Apply" });
    const scope = close.closest("[tabindex='-1']");
    if (!scope) throw new Error("scope container not found");

    apply.focus();
    fireEvent.keyDown(scope, { key: "Tab" });
    expect(close).toHaveFocus();

    fireEvent.keyDown(scope, { key: "Tab", shiftKey: true });
    expect(apply).toHaveFocus();
  });

  it("does not trap Tab when the scope is not modal", () => {
    render(<Panel />);
    const close = screen.getByRole("button", { name: "Close" });
    const apply = screen.getByRole("button", { name: "Apply" });
    const scope = close.closest("[tabindex='-1']");
    if (!scope) throw new Error("scope container not found");

    apply.focus();
    fireEvent.keyDown(scope, { key: "Tab" });
    // Focus is left to the browser; the handler must not have wrapped it.
    expect(apply).toHaveFocus();
  });

  it("keeps focus on the container when it holds no controls", () => {
    render(
      <FocusScope modal>
        <p>Nothing to focus here.</p>
      </FocusScope>,
    );
    const scope = screen.getByText("Nothing to focus here.").closest("[tabindex='-1']");
    if (!scope) throw new Error("scope container not found");
    fireEvent.keyDown(scope, { key: "Tab" });
    expect(scope).toHaveFocus();
  });

  it("reports Escape so the owner can close", () => {
    const onEscape = vi.fn();
    render(<Panel onEscape={onEscape} />);
    fireEvent.keyDown(screen.getByRole("button", { name: "Close" }), { key: "Escape" });
    expect(onEscape).toHaveBeenCalledTimes(1);
  });

  it("leaves Escape alone when the owner does not handle it", () => {
    render(<Panel />);
    // No onEscape means no error and no swallowing — a non-modal panel must not
    // consume Escape on behalf of a parent that wants it.
    fireEvent.keyDown(screen.getByRole("button", { name: "Close" }), { key: "Escape" });
    expect(screen.getByRole("button", { name: "Close" })).toBeInTheDocument();
  });

  it("returns focus to the invoker on unmount", () => {
    // Rule 3: a keyboard user is put back where they were.
    function Host() {
      const [open, setOpen] = React.useState(false);
      return (
        <div>
          <button type="button" onClick={() => setOpen(true)}>
            Open
          </button>
          {open
            ? (
              <FocusScope>
                <button type="button" onClick={() => setOpen(false)}>
                  Close
                </button>
              </FocusScope>
            )
            : null}
        </div>
      );
    }
    render(<Host />);
    const open = screen.getByRole("button", { name: "Open" });
    open.focus();
    fireEvent.click(open);
    expect(screen.getByRole("button", { name: "Close" })).toHaveFocus();

    fireEvent.click(screen.getByRole("button", { name: "Close" }));
    expect(screen.getByRole("button", { name: "Open" })).toHaveFocus();
  });

  it("does not restore focus when asked not to", () => {
    function Host() {
      const [open, setOpen] = React.useState(true);
      return (
        <div>
          <button type="button">Behind</button>
          {open
            ? (
              <FocusScope restoreFocus={false}>
                <button type="button" onClick={() => setOpen(false)}>
                  Close
                </button>
              </FocusScope>
            )
            : null}
        </div>
      );
    }
    render(<Host />);
    const behind = screen.getByRole("button", { name: "Behind" });
    // The panel took focus on mount; closing with restoreFocus={false} must not
    // hand it back to the invoker.
    fireEvent.click(screen.getByRole("button", { name: "Close" }));
    expect(behind).not.toHaveFocus();
  });

  it("survives an invoker that has been removed from the DOM", () => {
    // A bulk action can delete the row that opened the panel.
    function Host() {
      const [state, setState] = React.useState<"row" | "panel" | "gone">("row");
      return (
        <div>
          {state === "row"
            ? (
              <button type="button" onClick={() => setState("panel")}>
                Open
              </button>
            )
            : null}
          {state === "panel"
            ? (
              <FocusScope>
                <button type="button" onClick={() => setState("gone")}>
                  Close
                </button>
              </FocusScope>
            )
            : null}
        </div>
      );
    }
    render(<Host />);
    fireEvent.click(screen.getByRole("button", { name: "Open" }));
    expect(() => fireEvent.click(screen.getByRole("button", { name: "Close" }))).not.toThrow();
  });
});

describe("getFocusable", () => {
  it("skips disabled and non-tabbable elements", () => {
    const { container } = render(
      <div>
        <button type="button">Enabled</button>
        <button type="button" disabled>
          Disabled
        </button>
        <a href="#x">Link</a>
        <a>No href</a>
      </div>,
    );
    const names = getFocusable(container).map((node) => node.textContent);
    expect(names).toEqual(["Enabled", "Link"]);
  });
});
