import type { PersonSuggestion } from "@/api/memberSuggestions";
import { Input } from "@/components/ui/input";
import { looksLikeEmail } from "@/lib/email";
import { Autocomplete } from "@base-ui/react/autocomplete";
import { useState } from "react";

interface PersonComboboxProps {
  readonly id: string;
  /** The typed text. Any text stays valid input, so an exact address for someone not offered still works. */
  readonly value: string;
  readonly onValueChange: (value: string) => void;
  /** People to offer for the current text, already matched and capped by the caller. */
  readonly suggestions: readonly PersonSuggestion[];
  /** Whether a lookup applies to the current text. When false the list stays closed. */
  readonly active: boolean;
  /** A lookup for the current text is still running. */
  readonly searching?: boolean;
  /** The lookup failed, so the list cannot say who exists. */
  readonly unavailable?: boolean;
  readonly placeholder?: string;
  readonly required?: boolean;
  /** Names the field when no visible label points at `id`. */
  readonly "aria-label"?: string;
}

const EMPTY_TEXT = "No matching people. Type the full email address to add someone.";
const UNAVAILABLE_TEXT =
  "Suggestions are not available right now. Type the full email address to add someone.";

function statusText(count: number, searching: boolean, active: boolean): string {
  if (!active) return "";
  if (searching) return "Searching for people.";
  if (count === 0) return "";
  return count === 1 ? "1 person found." : `${count} people found.`;
}

/**
 * An email field that offers matching people as you type. The email is the primary line of each
 * option and is what a choice fills in; the display name is secondary, because anyone can set their
 * own display name and only the address says who the account belongs to. The list is filtered by
 * whoever supplies `suggestions`, so the built-in client-side filter is off.
 */
export function PersonCombobox({
  id,
  value,
  onValueChange,
  suggestions,
  active,
  searching = false,
  unavailable = false,
  placeholder,
  required,
  "aria-label": ariaLabel,
}: PersonComboboxProps) {
  const [open, setOpen] = useState(false);
  // Closed while a first lookup runs, so an empty box does not flash under the field, and closed
  // when a complete address matches nobody: the empty-list hint has nothing to add then, and an open
  // list would cover the controls below the field.
  const visible = active
    && (suggestions.length > 0 || (!searching && !looksLikeEmail(value.trim())));
  return (
    <Autocomplete.Root
      items={active ? suggestions : []}
      mode="none"
      value={value}
      onValueChange={(next) => onValueChange(next)}
      itemToStringValue={(person: PersonSuggestion) => person.email}
      open={open && visible}
      onOpenChange={setOpen}
    >
      <Autocomplete.Input
        render={
          <Input
            id={id}
            type="email"
            autoComplete="off"
            required={required}
            placeholder={placeholder}
            aria-label={ariaLabel}
          />
        }
      />
      <Autocomplete.Portal>
        <Autocomplete.Positioner sideOffset={4} className="isolate z-50">
          <Autocomplete.Popup className="bg-popover text-popover-foreground ring-foreground/10 max-h-(--available-height) w-(--anchor-width) overflow-y-auto rounded-lg p-1 shadow-md ring-1">
            <Autocomplete.Status className="sr-only">
              {statusText(suggestions.length, searching, active)}
            </Autocomplete.Status>
            <Autocomplete.Empty className="text-muted-foreground px-2 py-1.5 text-xs empty:hidden">
              {active && !searching ? (unavailable ? UNAVAILABLE_TEXT : EMPTY_TEXT) : null}
            </Autocomplete.Empty>
            <Autocomplete.List>
              {(person: PersonSuggestion) => (
                <Autocomplete.Item
                  key={person.user_id}
                  value={person}
                  className="data-highlighted:bg-accent data-highlighted:text-accent-foreground flex cursor-default flex-col rounded-md px-2 py-1.5 text-sm outline-hidden select-none"
                >
                  <span className="truncate">{person.email}</span>
                  {person.display_name && (
                    <span className="text-muted-foreground truncate text-xs">
                      {person.display_name}
                    </span>
                  )}
                </Autocomplete.Item>
              )}
            </Autocomplete.List>
          </Autocomplete.Popup>
        </Autocomplete.Positioner>
      </Autocomplete.Portal>
    </Autocomplete.Root>
  );
}
