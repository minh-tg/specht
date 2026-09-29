import { getFocusable } from "@/lib/focus";
import * as React from "react";

/**
 * FocusScope — the focus contracts, as a component.
 *
 * "Keyboard-correct everywhere" only holds if focus is *managed*: it lands
 * somewhere deliberate on open, cannot escape a modal, and comes back to whatever
 * opened it. Three rules, all of which are easy to get subtly wrong and were
 * missing from every generated screen:
 *
 * 1. **Open moves focus to the first decision control**, not to Close. A panel
 *    exists to make a decision, so focus starts where the work is.
 * 2. **A modal scope traps Tab and Shift+Tab**, wrapping at both ends.
 * 3. **Close returns focus to the invoking element**, so a keyboard user is put
 *    back where they were rather than at the top of the document.
 *
 * Non-modal scopes skip the trap but still manage initial and return focus, which
 * is what a side panel or a details disclosure needs.
 */

export interface FocusScopeProps extends React.HTMLAttributes<HTMLDivElement> {
  /** Modal scopes trap Tab. Default false. */
  readonly modal?: boolean;
  /** Focused on mount. Defaults to the first focusable descendant. */
  readonly initialFocus?: React.RefObject<HTMLElement | null>;
  /**
   * Called when Escape is pressed. Omit to leave Escape alone — a non-modal panel
   * should not swallow it.
   */
  readonly onEscape?: () => void;
  /** Return focus to the invoker on unmount. Default true. */
  readonly restoreFocus?: boolean;
}

export function FocusScope({
  modal = false,
  initialFocus,
  onEscape,
  restoreFocus = true,
  children,
  ...rest
}: FocusScopeProps) {
  const containerRef = React.useRef<HTMLDivElement | null>(null);
  const invokerRef = React.useRef<HTMLElement | null>(null);

  // Captured in an effect rather than during render: writing a ref while rendering
  // is unsafe under concurrent rendering. Effects run in declaration order, so this
  // still runs before the focus effect below moves focus away from the invoker.
  React.useEffect(() => {
    invokerRef.current = document.activeElement as HTMLElement | null;
  }, []);

  React.useEffect(() => {
    const container = containerRef.current;
    if (!container) return;
    const target = initialFocus?.current ?? getFocusable(container)[0] ?? container;
    target.focus();
  }, [initialFocus]);

  React.useEffect(() => {
    const invoker = invokerRef.current;
    if (!restoreFocus) return;
    return () => {
      // The invoker can be gone — a row removed by a bulk action, or a route change.
      if (invoker && invoker.isConnected) invoker.focus();
    };
  }, [restoreFocus]);

  const handleKeyDown = (event: React.KeyboardEvent<HTMLDivElement>) => {
    if (event.key === "Escape" && onEscape) {
      event.stopPropagation();
      onEscape();
      return;
    }
    if (!modal || event.key !== "Tab") return;

    const container = containerRef.current;
    if (!container) return;
    const focusable = getFocusable(container);
    if (focusable.length === 0) {
      // Nothing to cycle: keep focus on the container rather than losing it.
      event.preventDefault();
      container.focus();
      return;
    }

    const first = focusable[0];
    const last = focusable[focusable.length - 1];
    const active = document.activeElement;

    if (event.shiftKey && (active === first || active === container)) {
      event.preventDefault();
      last.focus();
      return;
    }
    if (!event.shiftKey && active === last) {
      event.preventDefault();
      first.focus();
    }
  };

  return (
    // The container is programmatically focusable so focus is never lost when a
    // scope happens to contain no controls yet.
    <div ref={containerRef} tabIndex={-1} onKeyDown={handleKeyDown} {...rest}>
      {children}
    </div>
  );
}
