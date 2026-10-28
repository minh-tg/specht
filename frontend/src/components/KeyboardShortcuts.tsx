import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import {
  activeShortcutsIn,
  comboLabel,
  displayCombos,
  helpReturnTarget,
  keyLabel,
  matchesHelpKey,
  matchesModShortcut,
  SHORTCUT_SCOPES,
  shortcutHelp,
  useShortcutHelpOpen,
} from "@/lib/shortcuts";
import { useSingleKeyEnabled } from "@/lib/singleKeyShortcuts";
import { Fragment, useEffect } from "react";

/**
 * The shortcut sheet. Ctrl+/ or ⌘/ opens it on every platform (Safari on macOS can claim ⌘/ for a
 * menu item, so Ctrl+/ is the way in there), as does the "Keyboard shortcuts" palette entry. Those
 * two always work, which is also the way in for a screen reader's browse mode, where a bare `?` is
 * swallowed before the page sees it.
 *
 * WCAG 2.1.4 (character key shortcuts): the arrow keys, Home, End, Enter and Space are not
 * character keys, and j, k and x only act while the findings grid has focus, which the criterion
 * exempts. The bare `?` is global, so the "Single-key shortcuts" switch in the account menu turns
 * it off; the grid's j, k and x follow the same switch to keep "off" simple. The sheet lists only
 * the keys that are active. Closing returns focus to the element that had it.
 */
export function KeyboardShortcuts() {
  const open = useShortcutHelpOpen();
  const singleKeys = useSingleKeyEnabled();

  useEffect(() => {
    function onKeyDown(event: KeyboardEvent) {
      if (matchesModShortcut(event, "help")) {
        event.preventDefault();
        shortcutHelp.toggle();
      } else if (matchesHelpKey(event)) {
        event.preventDefault();
        shortcutHelp.open();
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
            {!singleKeys && " Single-key shortcuts are off. Turn them on in the account menu."}
          </DialogDescription>
        </DialogHeader>
        {SHORTCUT_SCOPES.map((scope) => ({ scope, items: activeShortcutsIn(scope, singleKeys) }))
          .filter(({ items }) => items.length > 0).map(({ scope, items }) => (
            <section key={scope} aria-labelledby={`shortcuts-${scope.replaceAll(" ", "-")}`}>
              <h3
                id={`shortcuts-${scope.replaceAll(" ", "-")}`}
                className="text-muted-foreground mb-1 text-label font-medium tracking-wider uppercase"
              >
                {scope}
              </h3>
              <dl className="m-0 grid gap-1.5">
                {items.map((shortcut) => (
                  <div key={shortcut.id} className="flex items-baseline justify-between gap-3">
                    <dt className="text-body">{shortcut.description}</dt>
                    <dd className="m-0 flex flex-wrap justify-end gap-x-2 gap-y-1">
                      {displayCombos(shortcut, undefined, singleKeys).map((combo, index) => (
                        <Fragment key={combo.join("+")}>
                          {index > 0 && shortcut.alsoCtrl && (
                            <span className="text-muted-foreground text-meta">{" or "}</span>
                          )}
                          <kbd
                            aria-label={combo.map((key) =>
                              keyLabel(key)
                            ).join(" ")}
                            className="bg-muted text-muted-foreground rounded px-1.5 py-0.5 font-mono text-code"
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
