import { Toaster } from "@/components/ui/sonner";
import { act, render, screen } from "@testing-library/react";
import { toast } from "sonner";
import { describe, expect, it } from "vitest";
import { shortcut } from "./shortcuts";

describe("the notifications shortcut", () => {
  it("is registered as the key that makes the toaster focus its notifications", async () => {
    expect(shortcut("notifications")).toMatchObject({
      scope: "Everywhere",
      description: "Focus notifications",
      combos: [["Alt", "T"]],
    });

    render(<Toaster />);
    act(() => void toast("Saved"));
    await screen.findByText("Saved");
    const list = document.querySelector<HTMLElement>("[data-sonner-toaster]")!;
    expect(list).not.toHaveFocus();

    act(() => {
      document.dispatchEvent(
        new KeyboardEvent("keydown", { altKey: true, code: "KeyT", key: "†", bubbles: true }),
      );
    });
    expect(list).toHaveFocus();
  });
});
