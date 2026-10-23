import { INLINE_LINK } from "@/components/inlineLink";
import { SelectField } from "@/components/SelectField";
import { Input } from "@/components/ui/input";
import {
  ANALYSIS_STATES,
  analysisStateLabel,
  FINDING_KINDS,
  findingKindLabel,
  TECHNICAL_STATES,
  technicalStateLabel,
} from "@/lib/enums";
import { NEEDS_TRIAGE_STATES, OPEN_FINDING_STATES } from "@/lib/findingViews";
import type { SeverityCount } from "@/types/api";
import { SearchIcon } from "lucide-react";
import { useEffect, useRef, useState } from "react";
import { SeverityChips } from "./SeverityChips";
import { SORT_OPTIONS } from "./sort";
import type { FindingsFilters as FindingsFilterState, FindingsSort } from "./useFindingsQuery";

/** What the person is still typing, until they pause. */
const SEARCH_PAUSE_MS = 300;

interface FindingsFiltersProps {
  filters: FindingsFilterState;
  sort: FindingsSort;
  onFilterChange: (key: string, value: string) => void;
  onSortChange: (by: FindingsSort["by"], dir: "asc" | "desc") => void;
  /** How many open findings each severity holds, for the chips. */
  severityCounts?: readonly SeverityCount[];
}

/**
 * The search box. It keeps what is being typed until the typing pauses, then writes it to the
 * URL, so the server is asked once per pause and not once per key. Whatever the URL holds is
 * shown whenever nothing is being typed, so the back button and "Clear filters" are honoured.
 */
function SearchBox({ value, onSearch }: { value: string; onSearch: (value: string) => void; }) {
  const [draft, setDraft] = useState<string | null>(null);
  const timer = useRef<ReturnType<typeof setTimeout> | null>(null);

  useEffect(() => () => {
    if (timer.current) clearTimeout(timer.current);
  }, []);

  function change(next: string) {
    setDraft(next);
    if (timer.current) clearTimeout(timer.current);
    timer.current = setTimeout(() => {
      onSearch(next.trim());
      setDraft(null);
    }, SEARCH_PAUSE_MS);
  }

  return (
    <div className="relative w-full sm:w-64">
      <SearchIcon
        aria-hidden="true"
        className="text-muted-foreground pointer-events-none absolute top-1/2 left-2.5 size-3.5 -translate-y-1/2"
      />
      <Input
        type="search"
        aria-label="Search findings"
        placeholder="Search title or package"
        maxLength={100}
        className="pl-8"
        value={draft ?? value}
        onChange={(e) => change(e.target.value)}
      />
    </div>
  );
}

/**
 * The filter bar above the findings table. It is fully controlled: the route
 * component owns the search params, so this only renders the current values and
 * reports changes.
 */
export function FindingsFilters(
  { filters, sort, onFilterChange, onSortChange, severityCounts }: FindingsFiltersProps,
) {
  return (
    <div className="flex flex-wrap items-center gap-2">
      <SearchBox value={filters.q} onSearch={(v) => onFilterChange("q", v)} />
      <SeverityChips
        value={filters.severity}
        counts={severityCounts}
        onChange={(v) => onFilterChange("severity", v)}
      />
      <SelectField
        aria-label="Filter by triage state"
        value={filters.analysisState}
        onValueChange={(v) => onFilterChange("analysis_state", v)}
        options={[
          { value: "", label: "All triage states" },
          { value: NEEDS_TRIAGE_STATES, label: "Needs triage" },
          ...ANALYSIS_STATES.map((value) => ({
            value,
            label: analysisStateLabel(value) ?? value,
          })),
        ]}
      />
      <SelectField
        aria-label="Filter by status"
        value={filters.status}
        onValueChange={(v) => onFilterChange("status", v)}
        options={[
          { value: "", label: "All statuses" },
          { value: OPEN_FINDING_STATES, label: "Open or reopened" },
          ...TECHNICAL_STATES.map((value) => ({
            value,
            label: technicalStateLabel(value) ?? value,
          })),
        ]}
      />
      <SelectField
        aria-label="Filter by finding type"
        value={filters.kind}
        onValueChange={(v) => onFilterChange("kind", v)}
        options={[
          { value: "", label: "All kinds" },
          ...FINDING_KINDS.map((value) => ({ value, label: findingKindLabel(value) ?? value })),
        ]}
      />
      <SelectField
        aria-label="Sort findings"
        value={`${sort.by}:${sort.dir}`}
        onValueChange={(v) => {
          const [by, dir] = v.split(":");
          const known = SORT_OPTIONS.some((o) => o.value === v);
          if (known) onSortChange(by as FindingsSort["by"], dir === "asc" ? "asc" : "desc");
        }}
        options={SORT_OPTIONS}
      />
    </div>
  );
}

/** The "Clear filters" affordance shown when a filtered page matches nothing. */
export function ClearFiltersButton({ onClear }: { onClear: () => void; }) {
  return (
    <button
      type="button"
      className={`${INLINE_LINK} text-sm`}
      onClick={onClear}
    >
      Clear filters
    </button>
  );
}
