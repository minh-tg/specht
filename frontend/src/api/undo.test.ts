import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

const success = vi.hoisted(() => vi.fn());
const error = vi.hoisted(() => vi.fn());
vi.mock("sonner", () => ({ toast: { success, error } }));

const playCue = vi.hoisted(() => vi.fn());
vi.mock("@/lib/sound", () => ({ playCue }));

import { MAIN_CONTENT_ID } from "@/components/SkipLink";
import { UNDO_TOAST_MS, undoOptions, type UndoPlan } from "./undo";

function plan(over: Partial<UndoPlan> = {}): UndoPlan {
  return { run: vi.fn(async () => {}), done: "Restored", refresh: vi.fn(), ...over };
}

/** The sonner `action` of the options, typed for the test. */
function actionOf(options: ReturnType<typeof undoOptions>) {
  return options.action as { label: string; onClick: () => void; };
}

async function settle() {
  await vi.waitFor(() => expect(success.mock.calls.length + error.mock.calls.length).toBe(1));
}

let main: HTMLElement;
let control: HTMLButtonElement;

beforeEach(() => {
  success.mockClear();
  error.mockClear();
  playCue.mockClear();
  main = document.createElement("main");
  main.id = MAIN_CONTENT_ID;
  main.tabIndex = -1;
  control = document.createElement("button");
  document.body.append(main, control);
});

afterEach(() => {
  main.remove();
  control.remove();
});

describe("undoOptions", () => {
  it("keeps the toast up for ten seconds and labels the button Undo", () => {
    const options = undoOptions(plan());
    expect(options.duration).toBe(UNDO_TOAST_MS);
    expect(UNDO_TOAST_MS).toBe(10_000);
    expect(actionOf(options).label).toBe("Undo");
  });

  it("confirms with a plain toast and the accepted cue when the inverse worked", async () => {
    const p = plan();
    actionOf(undoOptions(p)).onClick();
    await settle();
    expect(p.run).toHaveBeenCalledOnce();
    expect(success).toHaveBeenCalledExactlyOnceWith("Restored");
    expect(playCue).toHaveBeenCalledExactlyOnceWith("accepted");
    expect(error).not.toHaveBeenCalled();
    expect(p.refresh).toHaveBeenCalledOnce();
  });

  it("shows the reason and the error cue when the inverse refuses, and still refreshes", async () => {
    const p = plan({
      run: vi.fn(async () => {
        throw new Error("The waiver changed in the meantime, so Undo did nothing");
      }),
    });
    actionOf(undoOptions(p)).onClick();
    await settle();
    expect(error).toHaveBeenCalledExactlyOnceWith(
      "The waiver changed in the meantime, so Undo did nothing",
    );
    expect(playCue).toHaveBeenCalledExactlyOnceWith("error");
    expect(success).not.toHaveBeenCalled();
    expect(p.refresh).toHaveBeenCalledOnce();
  });

  it("falls back to a generic message for an error without one", async () => {
    actionOf(undoOptions(plan({ run: vi.fn(async () => Promise.reject("boom")) }))).onClick();
    await settle();
    expect(error).toHaveBeenCalledExactlyOnceWith("Could not undo that.");
  });

  it("returns focus to the control that was focused when the toast was raised", async () => {
    control.focus();
    const options = undoOptions(plan());
    // The person moves to the toast's button, which then goes away with the toast.
    const inToast = document.createElement("button");
    const region = document.createElement("ol");
    region.setAttribute("data-sonner-toaster", "true");
    region.append(inToast);
    document.body.append(region);
    inToast.focus();
    actionOf(options).onClick();
    await settle();
    await vi.waitFor(() => expect(document.activeElement).toBe(control));
    region.remove();
  });

  it("falls back to main when that control is gone", async () => {
    control.focus();
    const options = undoOptions(plan());
    control.remove();
    document.body.focus();
    actionOf(options).onClick();
    await settle();
    await vi.waitFor(() => expect(document.activeElement).toBe(main));
  });

  it("falls back to main when focus was on the body when the toast was raised", async () => {
    // A button that disables itself while saving drops focus to the body before the toast shows.
    // Browsers move focus off a control that becomes disabled; jsdom does not, so blur it here.
    control.focus();
    control.blur();
    control.disabled = true;
    expect(document.activeElement).toBe(document.body);
    const options = undoOptions(plan());
    actionOf(options).onClick();
    await settle();
    await vi.waitFor(() => expect(document.activeElement).toBe(main));
  });

  it("falls back to main when that control is disabled by the time Undo finishes", async () => {
    control.focus();
    const options = undoOptions(plan());
    control.blur();
    control.disabled = true;
    actionOf(options).onClick();
    await settle();
    await vi.waitFor(() => expect(document.activeElement).toBe(main));
  });

  it("leaves focus alone when the person has moved on", async () => {
    control.focus();
    const options = undoOptions(plan());
    const elsewhere = document.createElement("input");
    document.body.append(elsewhere);
    elsewhere.focus();
    actionOf(options).onClick();
    await settle();
    expect(document.activeElement).toBe(elsewhere);
    elsewhere.remove();
  });

  it("returns focus when the toast closes with focus inside it", () => {
    control.focus();
    const options = undoOptions(plan());
    const inToast = document.createElement("button");
    const region = document.createElement("ol");
    region.setAttribute("data-sonner-toaster", "true");
    region.append(inToast);
    document.body.append(region);
    inToast.focus();
    options.onAutoClose?.({} as never);
    expect(document.activeElement).toBe(control);
    region.remove();
  });

  it("does not touch focus when the toast closes with focus elsewhere", () => {
    control.focus();
    const options = undoOptions(plan());
    const elsewhere = document.createElement("input");
    document.body.append(elsewhere);
    elsewhere.focus();
    options.onDismiss?.({} as never);
    expect(document.activeElement).toBe(elsewhere);
    elsewhere.remove();
  });
});
