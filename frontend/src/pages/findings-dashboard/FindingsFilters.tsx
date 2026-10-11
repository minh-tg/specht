import { SelectField } from "@/components/SelectField";
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
      <SelectField
        aria-label="Filter by severity"
        value={filters.severity}
        onValueChange={(v) => onFilterChange("severity", v)}
        options={[
          { value: "", label: "All severities" },
          ...SEVERITIES.map((value) => ({ value, label: severityLabel(value) ?? value })),
        ]}
      />
      <SelectField
        aria-label="Filter by status"
        value={filters.status}
        onValueChange={(v) => onFilterChange("status", v)}
        options={[
          { value: "", label: "All statuses" },
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
        className="md:hidden"
        value={`${sort.by}:${sort.dir}`}
        onValueChange={(v) => {
          const [by, dir] = v.split(":");
          onSortChange(by, dir === "asc" ? "asc" : "desc");
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
      className="text-action text-sm underline hover:no-underline"
      onClick={onClear}
    >
      Clear filters
    </button>
  );
}
