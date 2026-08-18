package watcher

import (
	"reflect"
	"testing"
)

// Test fixtures are transcribed from real advisories where noted; they are
// static copies so tests stay deterministic and run fully offline. Version
// strings follow the OSV affected[] shape.

// log4jAffected is CVE-2021-44228 (Log4Shell), GHSA-jfh8-c2jp-5v3q — Maven
// org.apache.logging.log4j:log4j-core, fixed in 2.15.0. The range and
// versions list mirror the published OSV entry (OSV-2021-1627).
var log4jAffected = Affected{
	Ecosystem: "Maven",
	Package:   Package{Name: "org.apache.logging.log4j:log4j-core"},
	Ranges: []VersionRange{{
		Type: "ECOSYSTEM",
		Events: []RangeEvent{
			{Introduced: "0"},
			{Fixed: "2.15.0"},
		},
	}},
	Versions: []string{"2.0-beta9", "2.0-rc1", "2.10.0", "2.14.1"},
}

// jacksonAffected is CVE-2018-7489 — Maven
// com.fasterxml.jackson.core:jackson-databind, "2.x before 2.9.6".
var jacksonAffected = Affected{
	Ecosystem: "Maven",
	Package:   Package{Name: "com.fasterxml.jackson.core:jackson-databind"},
	Ranges: []VersionRange{{
		Type: "ECOSYSTEM",
		Events: []RangeEvent{
			{Introduced: "2.7.0"},
			{Fixed: "2.9.6"},
		},
	}},
}

// ginAffected is CVE-2020-28483 — Go github.com/gin-gonic/gin, fixed in
// v1.7.0. Go OSV entries carry the "v" prefix in range bounds and the
// versions list.
var ginAffected = Affected{
	Ecosystem: "Go",
	Package:   Package{Name: "github.com/gin-gonic/gin"},
	Ranges: []VersionRange{{
		Type: "SEMVER",
		Events: []RangeEvent{
			{Introduced: "0"},
			{Fixed: "v1.7.0"},
		},
	}},
	Versions: []string{"v0.0.0", "v1.0.0", "v1.5.0", "v1.6.3"},
}

// lodashAffected is CVE-2020-8203 (GHSA-35jh-r3h4-6jhm) — npm lodash,
// last_affected 4.17.19, fixed in 4.17.20. Demonstrates the inclusive
// last_affected upper bound.
var lodashAffected = Affected{
	Ecosystem: "npm",
	Package:   Package{Name: "lodash"},
	Ranges: []VersionRange{{
		Type: "ECOSYSTEM",
		Events: []RangeEvent{
			{Introduced: "0"},
			{LastAffected: "4.17.19"},
		},
	}},
}

// limitAffected demonstrates the limit event: an exclusive cap used when a
// range has no fixed version (fork/backport-style ranges). Shape per the
// OSV schema's limit-event examples.
var limitAffected = Affected{
	Ecosystem: "npm",
	Package:   Package{Name: "example-package"},
	Ranges: []VersionRange{{
		Type: "ECOSYSTEM",
		Events: []RangeEvent{
			{Introduced: "2.0.0"},
			{Limit: "2.4.0"},
		},
	}},
}

// multiIntervalAffected shows a reintroduced range: two disjoint intervals
// in one entry, as published for advisories whose fixes were backported into
// later release lines.
var multiIntervalAffected = Affected{
	Ecosystem: "Maven",
	Package:   Package{Name: "org.example:multi"},
	Ranges: []VersionRange{{
		Type: "ECOSYSTEM",
		Events: []RangeEvent{
			{Introduced: "1.0.0"},
			{Fixed: "1.2.0"},
			{Introduced: "2.0.0"},
			{Fixed: "2.1.0"},
		},
	}},
}

// wholePackageAffected has neither ranges nor versions: the entry affects
// the whole package (design: condition 3).
var wholePackageAffected = Affected{
	Ecosystem: "Go",
	Package:   Package{Name: "example.com/wholepkg"},
}

// versionsOnlyAffected has no ranges: only the explicit versions list. It
// isolates the versions[] membership path from range matching and mixes
// v-prefixed and bare entries to prove normalization on both sides.
var versionsOnlyAffected = Affected{
	Ecosystem: "Go",
	Package:   Package{Name: "example.com/listed"},
	Versions:  []string{"v1.0.0", "v1.5.0", "1.6.3"},
}

// openEndedAffected is an introduced-only range with no closing event: the
// OSV shape for unfixed advisories (or reverted fixes) whose affected region
// has no upper bound yet. Everything at or above the introduced bound is
// affected; everything below it is not.
var openEndedAffected = Affected{
	Ecosystem: "Go",
	Package:   Package{Name: "example.com/openended"},
	Ranges: []VersionRange{{
		Type: "SEMVER",
		Events: []RangeEvent{
			{Introduced: "2.0.0"},
		},
	}},
}

func TestVersionAffected(t *testing.T) {
	tests := []struct {
		name    string
		aff     Affected
		version string
		want    bool
	}{
		// log4j (CVE-2021-44228): fixed-range hit and miss.
		{"log4j inside fixed range", log4jAffected, "2.14.1", true},
		{"log4j introduced-sentinel covers 1.x", log4jAffected, "1.2.17", true},
		{"log4j semver pre-release inside range", log4jAffected, "2.0.0-beta9", true},
		{"log4j maven beta notation not semver, safe", log4jAffected, "2.0-beta9", false},
		{"log4j at fixed version is safe", log4jAffected, "2.15.0", false},
		{"log4j past fixed version is safe", log4jAffected, "2.16.0", false},
		{"log4j far future version is safe", log4jAffected, "3.0.0", false},

		// log4j versions[] membership (also covered by the range here).
		{"log4j versions list exact", log4jAffected, "2.10.0", true},

		// jackson (CVE-2018-7489): non-zero introduced bound.
		{"jackson at introduced is affected", jacksonAffected, "2.7.0", true},
		{"jackson below introduced is safe", jacksonAffected, "2.6.7", false},
		{"jackson just below fixed is affected", jacksonAffected, "2.9.5", true},
		{"jackson at fixed is safe", jacksonAffected, "2.9.6", false},
		{"jackson fixed pre-release is affected", jacksonAffected, "2.9.6-rc1", true},

		// gin (CVE-2020-28483): v-prefix normalization for Go.
		{"gin v-prefixed inside range", ginAffected, "v1.6.3", true},
		{"gin bare version normalizes to v-prefix", ginAffected, "1.6.3", true},
		{"gin at fixed v1.7.0 is safe", ginAffected, "v1.7.0", false},
		{"gin bare fixed version is safe", ginAffected, "1.7.0", false},
		{"gin fixed pre-release is affected", ginAffected, "v1.7.0-rc1", true},
		{"gin versions list v-prefix membership", ginAffected, "v1.5.0", true},
		{"gin versions list bare membership", ginAffected, "1.5.0", true},

		// Versions-only entry (no ranges): pure membership.
		{"versions-only exact hit", versionsOnlyAffected, "v1.5.0", true},
		{"versions-only bare hits v-prefixed entry", versionsOnlyAffected, "1.5.0", true},
		{"versions-only v-prefixed hits bare entry", versionsOnlyAffected, "v1.6.3", true},
		{"versions-only miss", versionsOnlyAffected, "1.6.4", false},
		{"versions-only far miss", versionsOnlyAffected, "9.9.9", false},
		{"versions-only unparseable version is safe", versionsOnlyAffected, "2.x", false},

		// lodash (CVE-2020-8203): inclusive last_affected upper bound.
		{"lodash at last_affected is affected", lodashAffected, "4.17.19", true},
		{"lodash below last_affected is affected", lodashAffected, "4.17.18", true},
		{"lodash past last_affected is safe", lodashAffected, "4.17.20", false},
		{"lodash latest is safe", lodashAffected, "4.17.21", false},

		// limit event: exclusive cap without a fixed version.
		{"limit inside interval", limitAffected, "2.3.9", true},
		{"limit at introduced is affected", limitAffected, "2.0.0", true},
		{"limit below introduced is safe", limitAffected, "1.9.9", false},
		{"limit at limit is safe (exclusive)", limitAffected, "2.4.0", false},

		// Open-ended introduced-only range (unfixed advisory shape): the
		// introduced bound must be respected as a lower bound.
		{"open-ended below introduced is safe", openEndedAffected, "1.5.0", false},
		{"open-ended far below introduced is safe", openEndedAffected, "0.9.9", false},
		{"open-ended at introduced is affected", openEndedAffected, "2.0.0", true},
		{"open-ended above introduced is affected", openEndedAffected, "2.1.0", true},
		{"open-ended far above is affected", openEndedAffected, "9.9.9", true},
		{"open-ended v-prefixed version is affected", openEndedAffected, "v3.0.0", true},
		{"open-ended unparseable introduced cannot judge", Affected{Ranges: []VersionRange{{Events: []RangeEvent{{Introduced: "next"}}}}}, "5.0.0", false},

		// Multiple disjoint intervals.
		{"multi-interval first block", multiIntervalAffected, "1.1.0", true},
		{"multi-interval gap is safe", multiIntervalAffected, "1.5.0", false},
		{"multi-interval second block", multiIntervalAffected, "2.0.5", true},
		{"multi-interval second fixed is safe", multiIntervalAffected, "2.1.0", false},

		// Whole-package entries (no ranges, no versions).
		{"whole package parseable version affected", wholePackageAffected, "1.2.3", true},
		{"whole package v-prefixed affected", wholePackageAffected, "v1.2.3", true},
		{"whole package padded version affected", wholePackageAffected, "1.2", true},
		{"whole package unparseable version is safe", wholePackageAffected, "2.x", false},
		{"whole package empty version is safe", wholePackageAffected, "", false},

		// Unknown / messy / non-SemVer versions are never affected (ruling 1).
		{"epoch debian version is safe", log4jAffected, "1:2.14.1-1", false},
		{"debian tilde version is safe", log4jAffected, "1.2.3~beta1", false},
		{"two-part version pads to minor zero", log4jAffected, "2.14", true},
		{"patch-zero line still inside range", jacksonAffected, "2.9", true},
		{"four-part version is safe", jacksonAffected, "2.9.6.1", false},
		{"wildcard version is safe", log4jAffected, "2.x", false},
		{"latest token is safe", log4jAffected, "latest", false},
		{"garbage version is safe", ginAffected, "not-a-version", false},
		{"empty version is safe", log4jAffected, "", false},
		{"whitespace version is safe", ginAffected, "  ", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := VersionAffected(tt.aff, tt.version)
			if got != tt.want {
				t.Errorf("VersionAffected(%q) = %v, want %v", tt.version, got, tt.want)
			}
		})
	}
}

// TestVersionAffectedDeterministic proves the same input produces the same
// result every time (task "done when": determinism proven).
func TestVersionAffectedDeterministic(t *testing.T) {
	affs := []Affected{log4jAffected, jacksonAffected, ginAffected, lodashAffected, limitAffected, openEndedAffected}
	versions := []string{"2.14.1", "2.15.0", "v1.6.3", "4.17.19", "2.4.0", "1:2.14.1-1", ""}
	var first []bool
	for _, aff := range affs {
		for _, v := range versions {
			first = append(first, VersionAffected(aff, v))
		}
	}
	for i := 0; i < 3; i++ {
		for j, aff := range affs {
			for k, v := range versions {
				if got := VersionAffected(aff, v); got != first[j*len(versions)+k] {
					t.Fatalf("nondeterministic result for %q: got %v", v, got)
				}
			}
		}
	}
}

func TestNormalizeAliases(t *testing.T) {
	tests := []struct {
		name      string
		ids       []string
		wantPrim  string
		wantAlias []string
	}{
		{
			"cve preferred over ghsa and osv",
			[]string{"GHSA-jfh8-c2jp-5v3q", "CVE-2021-44228", "OSV-2021-1627"},
			"CVE-2021-44228",
			[]string{"GHSA-jfh8-c2jp-5v3q", "OSV-2021-1627"},
		},
		{
			"ghsa preferred when no cve",
			[]string{"OSV-2021-1627", "GHSA-jfh8-c2jp-5v3q"},
			"GHSA-jfh8-c2jp-5v3q",
			[]string{"OSV-2021-1627"},
		},
		{
			"osv id alone becomes primary",
			[]string{"OSV-2021-1627"},
			"OSV-2021-1627", nil,
		},
		{
			"multiple cves pick deterministically sorted first",
			[]string{"CVE-2021-44228", "CVE-2017-5638"},
			"CVE-2017-5638",
			[]string{"CVE-2021-44228"},
		},
		{
			"whitespace is trimmed",
			[]string{"  CVE-2021-44228  ", " GHSA-jfh8-c2jp-5v3q "},
			"CVE-2021-44228",
			[]string{"GHSA-jfh8-c2jp-5v3q"},
		},
		{
			"lowercase cve outranks ghsa like its uppercase form",
			[]string{"GHSA-jfh8-c2jp-5v3q", "cve-2021-44228"},
			"cve-2021-44228",
			[]string{"GHSA-jfh8-c2jp-5v3q"},
		},
		{
			"lowercase ghsa classifies into ghsa bucket",
			[]string{"ghsa-jfh8-c2jp-5v3q", "CVE-2021-44228"},
			"CVE-2021-44228",
			[]string{"ghsa-jfh8-c2jp-5v3q"},
		},
		{
			"duplicate aliases are deduplicated",
			[]string{"CVE-2021-44228", "GHSA-jfh8-c2jp-5v3q", "GHSA-jfh8-c2jp-5v3q"},
			"CVE-2021-44228",
			[]string{"GHSA-jfh8-c2jp-5v3q"},
		},
		{
			"empty input",
			nil,
			"", nil,
		},
		{
			"blank-only input",
			[]string{"  ", ""},
			"", nil,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotPrim, gotAlias := NormalizeAliases(tt.ids)
			if gotPrim != tt.wantPrim {
				t.Errorf("primary = %q, want %q", gotPrim, tt.wantPrim)
			}
			if !reflect.DeepEqual(gotAlias, tt.wantAlias) {
				t.Errorf("aliases = %v, want %v", gotAlias, tt.wantAlias)
			}
			// Deterministic: same input twice yields identical output.
			gotPrim2, gotAlias2 := NormalizeAliases(tt.ids)
			if gotPrim2 != gotPrim || !reflect.DeepEqual(gotAlias2, gotAlias) {
				t.Errorf("NormalizeAliases not deterministic: (%q, %v) then (%q, %v)",
					gotPrim, gotAlias, gotPrim2, gotAlias2)
			}
		})
	}
}

// TestNormalizeAliasesDeterministicShuffle feeds the same id set in two
// different orders and expects identical output — alias ordering must not
// depend on input order.
func TestNormalizeAliasesDeterministicShuffle(t *testing.T) {
	a := []string{"GHSA-jfh8-c2jp-5v3q", "CVE-2021-44228", "OSV-2021-1627", "CVE-2020-8203"}
	b := []string{"OSV-2021-1627", "CVE-2020-8203", "GHSA-jfh8-c2jp-5v3q", "CVE-2021-44228"}
	p1, al1 := NormalizeAliases(a)
	p2, al2 := NormalizeAliases(b)
	if p1 != p2 || !reflect.DeepEqual(al1, al2) {
		t.Errorf("order-dependent result: (%q, %v) vs (%q, %v)", p1, al1, p2, al2)
	}
}
