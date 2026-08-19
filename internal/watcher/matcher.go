// Package watcher implements the CVE feed watcher's pure matching logic:
// deciding whether an inventory version falls inside an OSV advisory's
// affected region, and normalizing advisory alias identifiers. It contains
// no database, HTTP, or daemon code — finding creation and the
// polling daemon consume it, and every function here is deterministic.
package watcher

import (
	"sort"
	"strings"

	"golang.org/x/mod/semver"
)

// Ecosystem identifies the package ecosystem an affected entry applies to,
// mirroring the OSV "ecosystem" field (for example "Go", "npm", "PyPI",
// "Maven", "Debian").
type Ecosystem string

// Package is the minimal identification of an affected package.
type Package struct {
	Name string `json:"name"`
	// Ecosystem is the OSV ecosystem this affected entry applies to. In real
	// OSV records it is nested inside the package object
	// (affected[].package.ecosystem), alongside name and purl. It is kept here
	// (not as a top-level Affected field) to match the upstream decode shape.
	Ecosystem Ecosystem `json:"ecosystem,omitempty"`
}

// VersionRange is one OSV "ranges[]" interval. Type carries the OSV range
// type ("SEMVER", "ECOSYSTEM", ...); the matcher treats every range the
// same way, comparing bounds with semantic-version semantics. Events are
// evaluated in their given order.
type VersionRange struct {
	Type   string       `json:"type"`
	Events []RangeEvent `json:"events"`
}

// RangeEvent is one event inside a VersionRange. In OSV JSON each event
// carries exactly one of these keys; the struct keeps all four fields so
// callers can decode JSON or build entries by hand without extra machinery.
type RangeEvent struct {
	// Introduced is the lower bound. Absent or "0" means the beginning of
	// time (OSV schema default).
	Introduced string `json:"introduced,omitempty"`
	// Fixed is an exclusive upper bound: introduced <= v < fixed.
	Fixed string `json:"fixed,omitempty"`
	// LastAffected is an inclusive upper bound: introduced <= v <= last_affected.
	LastAffected string `json:"last_affected,omitempty"`
	// Limit is an exclusive cap: introduced <= v < limit.
	Limit string `json:"limit,omitempty"`
}

// Affected describes one OSV "affected[]" entry.
type Affected struct {
	Ecosystem Ecosystem      `json:"ecosystem"`
	Package   Package        `json:"package"`
	Ranges    []VersionRange `json:"ranges"`
	Versions  []string       `json:"versions"`
}

// VersionAffected reports whether version falls inside aff's affected region.
//
// It is a pure, deterministic function: the same inputs always produce the
// same result, and it never performs I/O. It is exported (rather than the
// brief's lowercase versionAffected) because finding creation runs
// in a different package and must call it across the package boundary.
//
// A version that is empty, unknown, or not parseable as semantic versioning
// is never reported affected (no false positives).
// An entry with neither ranges nor versions is treated as affecting the
// whole package (every parseable version).
func VersionAffected(aff Affected, version string) bool {
	v := normalizeVersion(version)
	if v == "" {
		// Ruling: versions that cannot be parsed with confidence are never
		// reported affected.
		return false
	}
	for _, r := range aff.Ranges {
		if versionInRange(r, v) {
			return true
		}
	}
	for _, av := range aff.Versions {
		if normalizeVersion(av) == v {
			return true
		}
	}
	if len(aff.Ranges) == 0 && len(aff.Versions) == 0 {
		// Whole-package entry: every parseable version is affected.
		return true
	}
	return false
}

// NormalizeAliases picks the primary identifier for an advisory out of its
// id list and returns the remaining identifiers as ordered aliases.
//
// The primary indicator is the CVE id when one is present; otherwise the
// GHSA id; otherwise any other id (for example the OSV id). Prefix
// classification (CVE-/GHSA-) is case-insensitive, so lowercase variants
// still land in their proper buckets instead of falling into the catch-all;
// the id strings themselves are preserved as given. Aliases are deduplicated
// and sorted so finding dimensions (primary id plus dim_key='alias' entries)
// are built deterministically. This is a pure function — no database layer —
// by design by design.
func NormalizeAliases(ids []string) (primary string, aliases []string) {
	var cves, ghsas, others []string
	for _, id := range ids {
		id = strings.TrimSpace(id)
		upper := strings.ToUpper(id)
		switch {
		case strings.HasPrefix(upper, "CVE-"):
			cves = append(cves, id)
		case strings.HasPrefix(upper, "GHSA-"):
			ghsas = append(ghsas, id)
		default:
			if id != "" {
				others = append(others, id)
			}
		}
	}
	sort.Strings(cves)
	sort.Strings(ghsas)
	sort.Strings(others)

	switch {
	case len(cves) > 0:
		primary = cves[0]
		aliases = append(aliases, cves[1:]...)
		aliases = append(aliases, ghsas...)
		aliases = append(aliases, others...)
	case len(ghsas) > 0:
		primary = ghsas[0]
		aliases = append(aliases, ghsas[1:]...)
		aliases = append(aliases, others...)
	case len(others) > 0:
		primary = others[0]
		aliases = append(aliases, others[1:]...)
	default:
		return "", nil
	}

	sort.Strings(aliases)
	seen := make(map[string]bool, len(aliases))
	out := aliases[:0]
	for _, a := range aliases {
		if !seen[a] && a != primary {
			seen[a] = true
			out = append(out, a)
		}
	}
	return primary, out
}

// versionInRange reports whether the canonical version v falls inside any
// interval expressed by the range's events. Events are evaluated in order:
// introduced opens an interval, fixed / last_affected / limit closes it.
func versionInRange(r VersionRange, v string) bool {
	var introduced string // "" means the OSV default lower bound "0"
	haveIntroduced := false
	for _, ev := range r.Events {
		switch {
		case ev.Introduced != "":
			introduced = ev.Introduced
			haveIntroduced = true
		case ev.Fixed != "":
			if intervalContains(introduced, haveIntroduced, ev.Fixed, false, v) {
				return true
			}
			introduced, haveIntroduced = "", false
		case ev.LastAffected != "":
			if intervalContains(introduced, haveIntroduced, ev.LastAffected, true, v) {
				return true
			}
			introduced, haveIntroduced = "", false
		case ev.Limit != "":
			if intervalContains(introduced, haveIntroduced, ev.Limit, false, v) {
				return true
			}
			introduced, haveIntroduced = "", false
		}
	}
	// A trailing introduced leaves the interval open-ended: all versions
	// at or above the lower bound are affected. The lower bound is enforced
	// exactly as in intervalContains: "0" means the beginning of time, an
	// unparseable bound cannot be judged (never a false positive), and
	// anything else requires v >= introduced.
	if haveIntroduced {
		if introduced == "0" {
			return true
		}
		lower := normalizeVersion(introduced)
		if lower == "" {
			return false
		}
		return semver.Compare(v, lower) >= 0
	}
	return false
}

// intervalContains reports whether v falls inside [introduced, upper], or
// [introduced, upper) when inclusiveUpper is false. An absent or "0"
// introduced means the interval starts at the beginning of time. Any bound
// that cannot be parsed as semantic versioning makes the interval
// uninterpretable and yields false — never a false positive.
func intervalContains(introduced string, haveIntroduced bool, upper string, inclusiveUpper bool, v string) bool {
	u := normalizeVersion(upper)
	if u == "" {
		return false
	}
	if haveIntroduced && introduced != "0" {
		l := normalizeVersion(introduced)
		if l == "" {
			return false
		}
		if semver.Compare(v, l) < 0 {
			return false
		}
	}
	cmp := semver.Compare(v, u)
	if inclusiveUpper {
		return cmp <= 0
	}
	return cmp < 0
}

// normalizeVersion canonicalizes a version for semver comparison: it trims
// whitespace, adds the "v" prefix Go module versions use, and returns the
// canonical form (build metadata stripped). It returns "" for any version
// that is not valid semantic versioning — callers treat that as "cannot be
// judged", never as affected. This is what makes Debian epoch versions
// ("1:2.3.4-1"), tilde revisions ("1.2.3~beta1"), four-part forms, and
// other non-SemVer input fall out as not affected (documented limitation).
//
// golang.org/x/mod/semver fills in a missing minor or patch component with
// zeros ("1.2" canonicalizes to "v1.2.0"): those padded forms are accepted,
// matching the library's semantics for Go module versions. The padding is
// conservative for lower-bound comparisons (a two-part "1.1" is the minimum
// possible 1.1.x line), so it does not create false positives.
func normalizeVersion(v string) string {
	v = strings.TrimSpace(v)
	if v == "" {
		return ""
	}
	if !strings.HasPrefix(v, "v") {
		v = "v" + v
	}
	if !semver.IsValid(v) {
		return ""
	}
	return semver.Canonical(v)
}
