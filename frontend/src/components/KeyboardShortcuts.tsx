import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import {
  comboLabel,
  displayCombos,
  helpReturnTarget,
  keyLabel,
  matchesModShortcut,
  SHORTCUT_SCOPES,
  shortcutHelp,
  shortcutsIn,
  useShortcutHelpOpen,
} from "@/lib/shortcuts";
import { Fragment, useEffect } from "react";

/**
 * The shortcut sheet. Ctrl+/ or ⌘/ opens it on every platform (Safari on macOS can claim ⌘/ for a
 * menu item, so Ctrl+/ is the way in there), as does the "Keyboard shortcuts" palette entry.
 * There is deliberately no bare-character key such as "?": a shortcut made of one printable
 * character cannot be switched off, and it would fire under a screen reader's virtual cursor.
 * Closing returns focus to the element that had it.
 */
export function KeyboardShortcuts() {
  const open = useShortcutHelpOpen();

  useEffect(() => {
    function onKeyDown(event: KeyboardEvent) {
      if (matchesModShortcut(event, "help")) {
        event.preventDefault();
        shortcutHelp.toggle();
      }
    }
    document.addEventListener("keydown", onKeyDown);
    return () => document.removeEventListener("keydown", onKeyDown);
  }, []);

  return (
    <Dialog
      open={open}
      onOpenChange={(next) => (next ? shortcutHelp.open() : shortcutHelp.close())}
    >
      <DialogContent
        className="max-h-[85vh] overflow-y-auto sm:max-w-md"
        finalFocus={() => helpReturnTarget() ?? true}
      >
        <DialogHeader>
          <DialogTitle>Keyboard shortcuts</DialogTitle>
          <DialogDescription>
            Keys marked with a place only work while focus is there.
          </DialogDescription>
        </DialogHeader>
        {SHORTCUT_SCOPES.map((scope) => (
          <section key={scope} aria-labelledby={`shortcuts-${scope.replaceAll(" ", "-")}`}>
            <h3
              id={`shortcuts-${scope.replaceAll(" ", "-")}`}
              className="text-muted-foreground mb-1 text-[0.6875rem] font-medium tracking-wider uppercase"
            >
              {scope}
            </h3>
            <dl className="m-0 grid gap-1.5">
              {shortcutsIn(scope).map((shortcut) => (
                <div key={shortcut.id} className="flex items-baseline justify-between gap-3">
                  <dt className="text-sm">{shortcut.description}</dt>
                  <dd className="m-0 flex flex-wrap justify-end gap-x-2 gap-y-1">
                    {displayCombos(shortcut).map((combo, index) => (
                      <Fragment key={combo.join("+")}>
                        {index > 0 && shortcut.alsoCtrl && (
                          <span className="text-muted-foreground text-xs">{" or "}</span>
                        )}
                        <kbd
                          aria-label={combo.map((key) => keyLabel(key)).join(" ")}
                          className="bg-muted text-muted-foreground rounded px-1.5 py-0.5 font-mono text-xs"
                        >
                          {comboLabel(combo)}
                        </kbd>
                      </Fragment>
                    ))}
                  </dd>
                </div>
              ))}
            </dl>
          </section>
        ))}
      </DialogContent>
    </Dialog>
  );
}
