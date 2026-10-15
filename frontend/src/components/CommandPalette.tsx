import { KeyboardShortcuts } from "@/components/KeyboardShortcuts";
import { Button } from "@/components/ui/button";
import { Dialog, DialogContent, DialogTitle } from "@/components/ui/dialog";
import { useCommands } from "@/components/useCommands";
import { type Command, sectionCommands } from "@/lib/commands";
import { comboLabel, matchesModShortcut, shortcut } from "@/lib/shortcuts";
import { SearchIcon } from "lucide-react";
import { type KeyboardEvent, useEffect, useId, useMemo, useRef, useState } from "react";

/**
 * Jump anywhere from the keyboard. Ctrl+K or ⌘K opens it from any page; type to narrow, the arrow
 * keys move, Enter goes, Escape closes. It opens with no animation, because a key someone presses a
 * hundred times a day should not make them wait for it.
 */
export function CommandPalette() {
  const commands = useCommands();
  const [open, setOpen] = useState(false);
  const [query, setQuery] = useState("");
  const [active, setActive] = useState(0);
  const listId = useId();
  const listRef = useRef<HTMLDivElement>(null);
  const originRef = useRef<HTMLElement | null>(null);

  function openPalette(from: Element | null) {
    originRef.current = from instanceof HTMLElement ? from : null;
    setOpen(true);
  }

  const sections = useMemo(() => sectionCommands(commands, query), [commands, query]);
  const flat = useMemo(() => sections.flatMap((s) => s.items), [sections]);
  const optionId = (command: Command) => `${listId}-${command.id}`;
  const activeCommand = flat[Math.min(active, flat.length - 1)];

  useEffect(() => {
    function onKeyDown(event: globalThis.KeyboardEvent) {
      if (matchesModShortcut(event, "palette")) {
        event.preventDefault();
        if (open) setOpen(false);
        else openPalette(document.activeElement);
      }
    }
    document.addEventListener("keydown", onKeyDown);
    return () => document.removeEventListener("keydown", onKeyDown);
  }, [open]);

  const activeId = activeCommand ? `${listId}-${activeCommand.id}` : undefined;
  useEffect(() => {
    if (!activeId) return;
    listRef.current?.querySelector(`[id="${activeId}"]`)?.scrollIntoView?.({ block: "nearest" });
  }, [activeId]);

  function changeOpen(next: boolean) {
    setOpen(next);
    if (!next) {
      setQuery("");
      setActive(0);
    }
  }

  function run(command: Command | undefined) {
    if (!command) return;
    changeOpen(false);
    command.run(originRef.current);
  }

  function onKeyDown(event: KeyboardEvent<HTMLInputElement>) {
    if (event.key === "ArrowDown" || event.key === "ArrowUp") {
      event.preventDefault();
      if (flat.length === 0) return;
      const step = event.key === "ArrowDown" ? 1 : -1;
      setActive((Math.min(active, flat.length - 1) + step + flat.length) % flat.length);
    } else if (event.key === "Home" || event.key === "End") {
      event.preventDefault();
      setActive(event.key === "Home" ? 0 : Math.max(0, flat.length - 1));
    } else if (event.key === "Enter") {
      event.preventDefault();
      run(activeCommand);
    }
  }

  return (
    <>
      <Button
        type="button"
        variant="outline"
        size="sm"
        onClick={(event) => openPalette(event.currentTarget)}
        aria-label="Open command palette"
        title={`Search and jump (${comboLabel(shortcut("palette").combos[0]!)})`}
        className="shrink-0"
      >
        <SearchIcon aria-hidden="true" />
        <kbd className="bg-muted text-muted-foreground rounded px-1 font-mono text-[0.6875rem] max-sm:hidden">
          {comboLabel(shortcut("palette").combos[0]!).replace("+", " ")}
        </kbd>
      </Button>

      <Dialog open={open} onOpenChange={changeOpen}>
        <DialogContent
          showCloseButton={false}
          className="top-[16%] w-full max-w-[calc(100%-2rem)] -translate-y-0 gap-0 overflow-hidden p-0 data-closed:animate-none data-open:animate-none sm:max-w-lg"
        >
          <DialogTitle className="sr-only">Command palette</DialogTitle>
          <div className="border-border flex items-center gap-2.5 border-b px-3.5">
            <SearchIcon aria-hidden="true" size={16} className="text-muted-foreground shrink-0" />
            <input
              role="combobox"
              aria-label="Search commands"
              aria-expanded={flat.length > 0}
              aria-controls={flat.length > 0 ? listId : undefined}
              aria-autocomplete="list"
              aria-activedescendant={activeId}
              autoFocus
              autoComplete="off"
              spellCheck={false}
              placeholder="Jump to a project, a page, or a setting"
              value={query}
              onChange={(e) => {
                setQuery(e.target.value);
                setActive(0);
              }}
              onKeyDown={onKeyDown}
              className="placeholder:text-muted-foreground h-12 w-full bg-transparent text-[0.9375rem] outline-none"
            />
          </div>

          {flat.length > 0
            ? (
              <div
                id={listId}
                ref={listRef}
                role="listbox"
                aria-label="Commands"
                className="max-h-[min(22rem,60vh)] overflow-y-auto p-1.5"
              >
                {sections.map((section) => (
                  <div key={section.group} role="group" aria-label={section.group} className="py-1">
                    <div
                      aria-hidden="true"
                      className="text-muted-foreground px-2.5 py-1 text-[0.6875rem] font-medium tracking-wider uppercase"
                    >
                      {section.group}
                    </div>
                    {section.items.map((command) => {
                      const selected = command === activeCommand;
                      return (
                        <div
                          key={command.id}
                          id={optionId(command)}
                          role="option"
                          aria-selected={selected}
                          onMouseMove={() => setActive(flat.indexOf(command))}
                          onClick={() =>
                            run(command)}
                          className={`flex cursor-pointer items-baseline justify-between gap-3 rounded-md px-2.5 py-2 text-sm ${
                            selected ? "bg-muted text-foreground" : "text-foreground"
                          }`}
                        >
                          <span className="truncate">{command.label}</span>
                          {command.hint && command.hint !== command.label && (
                            <span className="text-muted-foreground truncate font-mono text-xs">
                              {command.hint}
                            </span>
                          )}
                        </div>
                      );
                    })}
                  </div>
                ))}
              </div>
            )
            : (
              <p role="status" className="text-muted-foreground px-3 py-6 text-center text-sm">
                Nothing matches “{query.trim()}”.
              </p>
            )}

          <p className="text-muted-foreground border-border border-t px-3.5 py-2 text-xs max-sm:hidden">
            ↑ ↓ to move · Enter to go · Esc to close
          </p>
        </DialogContent>
      </Dialog>
      <KeyboardShortcuts />
    </>
  );
}
