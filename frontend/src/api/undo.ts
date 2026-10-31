import { MAIN_CONTENT_ID } from "@/components/SkipLink";
import { playCue } from "@/lib/sound";
import { type ExternalToast, toast } from "sonner";

/**
 * How long a toast with Undo stays up. Sonner's own 4 seconds leave too little time to read the
 * message and reach the button, and for a revoked waiver or a removed member the toast is the only
 * way back.
 */
export const UNDO_TOAST_MS = 10_000;

/** The inverse of a mutation that just succeeded, offered on its success toast. */
export interface UndoPlan {
  /**
   * Sends the inverse request. It throws an Error whose message says why when it did nothing, for
   * example because the record changed since.
   */
  run: () => Promise<void>;
  /** The plain confirmation shown when `run` resolves. */
  done: string;
  /** Refreshes the queries the original mutation refreshed. Runs whether or not `run` worked. */
  refresh: () => void;
}

const TOASTER_SELECTOR = "[data-sonner-toaster]";

/** Focus is lost when it sits on nothing or on a toast that is about to leave. */
function focusIsAdrift(): boolean {
  const active = document.activeElement;
  return !active || active === document.body || active.closest(TOASTER_SELECTOR) !== null;
}

/**
 * Puts focus back on `target` when it is still on the page and usable, otherwise on `<main>`. Does
 * nothing when the person has already moved focus somewhere real.
 *
 * The body is never a target. A button that disables itself while it saves (Save decision) drops
 * focus to the body before its toast is raised, and focusing the body again would leave a keyboard
 * user nowhere.
 */
function restoreFocus(target: Element | null): void {
  if (!focusIsAdrift()) return;
  const usable = target instanceof HTMLElement && target !== document.body && target.isConnected
      && !target.matches(":disabled")
    ? target
    : document.getElementById(MAIN_CONTENT_ID);
  usable?.focus({ preventScroll: true });
}

async function performUndo(plan: UndoPlan, returnTo: Element | null): Promise<void> {
  try {
    await plan.run();
    toast.success(plan.done);
    playCue("accepted");
  } catch (error) {
    toast.error(error instanceof Error && error.message ? error.message : "Could not undo that.");
    playCue("error");
  } finally {
    plan.refresh();
  }
  restoreFocus(returnTo);
}

/**
 * Sonner options that add an Undo button to a toast. The button runs the plan's inverse request on
 * its own, not through a mutation hook, so it announces once and keeps working after the person
 * has left the page. When the toast closes with focus inside it, focus returns to the control that
 * was focused when the toast was raised.
 */
export function undoOptions(plan: UndoPlan): ExternalToast {
  const returnTo = document.activeElement;
  const closed = () => restoreFocus(returnTo);
  return {
    duration: UNDO_TOAST_MS,
    action: { label: "Undo", onClick: () => void performUndo(plan, returnTo) },
    onDismiss: closed,
    onAutoClose: closed,
  };
}
