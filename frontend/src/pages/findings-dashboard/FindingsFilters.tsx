import {
  FINDING_KINDS,
  findingKindLabel,
  SEVERITIES,
  severityLabel,
  TECHNICAL_STATES,
  technicalStateLabel,
} from "@/lib/enums";
import { SORT_OPTIONS } from "./sort";
import type { FindingsFilters as FindingsFilterState, FindingsSort } from "./useFindingsQuery";

interface FindingsFiltersProps {
  filters: FindingsFilterState;
  sort: FindingsSort;
  onFilterChange: (key: string, value: string) => void;
  onSortChange: (by: string, dir: "asc" | "desc") => void;
}

/**
 * The filter bar above the findings table. It is fully controlled: the route
 * component owns the search params and the sort, so this only renders the
 * current values and reports changes.
 */
export function FindingsFilters(
  { filters, sort, onFilterChange, onSortChange }: FindingsFiltersProps,
) {
  return (
    <div className="flex flex-wrap gap-2">
      <select
        aria-label="Filter by severity"
        className="border-input bg-background rounded-md border px-3 py-1 text-sm"
        value={filters.severity}
        onChange={(e) => onFilterChange("severity", e.target.value)}
      >
        <option value="">All severities</option>
        {SEVERITIES.map((value) => <option key={value} value={value}>{severityLabel(value)}
        </option>)}
      </select>
      <select
        aria-label="Filter by status"
        className="border-input bg-background rounded-md border px-3 py-1 text-sm"
        value={filters.status}
        onChange={(e) => onFilterChange("status", e.target.value)}
      >
        <option value="">All statuses</option>
        {TECHNICAL_STATES.map((value) => (
          <option key={value} value={value}>{technicalStateLabel(value)}</option>
        ))}
      </select>
      <select
        aria-label="Filter by finding type"
        className="border-input bg-background rounded-md border px-3 py-1 text-sm"
        value={filters.kind}
        onChange={(e) => onFilterChange("kind", e.target.value)}
      >
        <option value="">All kinds</option>
        {FINDING_KINDS.map((value) => (
          <option key={value} value={value}>{findingKindLabel(value)}</option>
        ))}
      </select>
      <select
        aria-label="Sort findings"
        className="border-input bg-background rounded-md border px-3 py-1 text-sm md:hidden"
        value={`${sort.by}:${sort.dir}`}
        onChange={(e) => {
          const [by, dir] = e.target.value.split(":");
          onSortChange(by, dir === "asc" ? "asc" : "desc");
        }}
      >
        {SORT_OPTIONS.map(({ value, label }) => <option key={value} value={value}>{label}</option>)}
      </select>
    </div>
  );
}

/** The "Clear filters" affordance shown when a filtered page matches nothing. */
export function ClearFiltersButton({ onClear }: { onClear: () => void; }) {
  return (
    <button
      type="button"
      className="text-primary text-sm underline hover:no-underline"
      onClick={onClear}
    >
      Clear filters
    </button>
  );
}
