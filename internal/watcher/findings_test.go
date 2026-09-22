package watcher

import (
	"context"
	"encoding/json"
	"reflect"
	"strings"
	"testing"
)

// Test fixtures reuse the matcher's real-advisory shapes (see matcher_test.go)
// so findings tests exercise the same severity/gap-fill paths the range
// matcher already proves. All fixtures are static copies: tests are
// deterministic and run fully offline.

// log4jAdvisory is CVE-2021-44228 (Log4Shell) as the watcher sees it from
// OSV: an OSV id with CVE and GHSA aliases, a CVSS_V3 rating, and affected[]
// matching log4jAffected from matcher_test.go.
var log4jAdvisory = Advisory{
	ID:        "OSV-2021-1627",
	Aliases:   []string{"CVE-2021-44228", "GHSA-jfh8-c2jp-5v3q"},
	Summary:   "Log4Shell: remote code execution in log4j-core",
	Details:   "JNDI features in Log4j 2.x before 2.15.0 allow remote code execution.",
	Published: "2021-12-10T00:00:00Z",
	Modified:  "2021-12-17T00:00:00Z",
	Severity: []AdvisorySeverity{
		{Type: "CVSS_V3", Score: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"},
		{Type: "CVSS_V2", Score: "CVSS:2.0/AV:N/AC:L/Au:N/C:C/I:C/A:C"},
	},
	Affected: []Affected{log4jAffected},
	Refs: []AdvisoryRef{
		{URL: "https://nvd.nist.gov/vuln/detail/CVE-2021-44228"},
	},
}

// log4jInput is the inventory-side counterpart: the versioned purl and the
// ecosystem as a parser stored it (mixed case, per the ***REMOVED***).
var log4jInput = DecideInput{
	ProjectID: "6f0f5f2e-8b3a-4c1d-9e7a-2b4c6d8e0f10",
	Advisory:  log4jAdvisory,
	Purl:      "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1",
	Version:   "2.14.1",
	Ecosystem: "Maven",
}

func stubGapCheck(covered bool, calls *[]string) GapCheck {
	return func(_ context.Context, projectID, purlName string, candidateIDs []string) (bool, error) {
		if calls != nil {
			*calls = append(*calls, projectID+"|"+purlName+"|"+strings.Join(candidateIDs, ","))
		}
		return covered, nil
	}
}

func dimsMap(f FindingPayload) map[string][]string {
	m := make(map[string][]string)
	for _, d := range f.Dimensions {
		m[d.Key] = append(m[d.Key], d.Value)
	}
	return m
}

func TestDecideFinding_CreatesFinding(t *testing.T) {
	const wantFingerprint = "de10265a20cf266f2bc7dbb2eff453b5e8fcacdfaaf53a92c5671f55dda567e4"

	var calls []string
	dec, err := DecideFinding(context.Background(), log4jInput, stubGapCheck(false, &calls))
	if err != nil {
		t.Fatalf("DecideFinding: %v", err)
	}
	if !dec.Created {
		t.Fatalf("Created = false, want true (skip reason %q)", dec.SkipReason)
	}
	if dec.SkipReason != "" {
		t.Errorf("SkipReason = %q, want empty on create", dec.SkipReason)
	}

	f := dec.Finding
	assertCreatedFindingFields(t, f, wantFingerprint)
	assertCreatedFindingDims(t, f)

	// Event: auto_rule_applied carrying source/advisory_id.
	if dec.Event == nil || dec.Event.EventType != EventAutoRuleApplied {
		t.Fatalf("event = %+v, want auto_rule_applied", dec.Event)
	}
	var changes map[string]any
	if err := json.Unmarshal(dec.Event.Changes, &changes); err != nil {
		t.Fatalf("unmarshal event changes: %v", err)
	}
	if changes["source"] != "cve_watcher" || changes["advisory_id"] != "OSV-2021-1627" {
		t.Errorf("event changes = %v, want source/advisory_id metadata", changes)
	}
	assertEvidenceRoundTrips(t, dec.Evidence)

	// Gap check ran once with the project, name-level purl, and full
	// candidate id set (primary + aliases).
	if len(calls) != 1 {
		t.Fatalf("gap check calls = %d, want 1", len(calls))
	}
	wantCall := "6f0f5f2e-8b3a-4c1d-9e7a-2b4c6d8e0f10|pkg:maven/org.apache.logging.log4j/log4j-core|CVE-2021-44228,GHSA-jfh8-c2jp-5v3q,OSV-2021-1627"
	if calls[0] != wantCall {
		t.Errorf("gap check call = %q, want %q", calls[0], wantCall)
	}
}

// assertCreatedFindingFields checks the scalar payload of the created finding.
func assertCreatedFindingFields(t *testing.T, f FindingPayload, wantFingerprint string) {
	t.Helper()
	if f.FindingKind != "cve_watcher" {
		t.Errorf("FindingKind = %q, want cve_watcher", f.FindingKind)
	}
	if f.Fingerprint != wantFingerprint {
		t.Errorf("fingerprint = %q, want %q", f.Fingerprint, wantFingerprint)
	}
	if f.Severity != "critical" || f.SeverityRank != 4 || f.Score != 10.0 {
		t.Errorf("severity = %s/%d/%.1f, want critical/4/10.0", f.Severity, f.SeverityRank, f.Score)
	}
	if f.Title != "Log4Shell: remote code execution in log4j-core" {
		t.Errorf("Title = %q", f.Title)
	}
	if !strings.Contains(f.Remediation, "Upgrade to v2.15.0") {
		t.Errorf("remediation = %q, want Upgrade to v2.15.0", f.Remediation)
	}
	if !strings.Contains(f.Remediation, "https://nvd.nist.gov/vuln/detail/CVE-2021-44228") {
		t.Errorf("remediation = %q, want reference URL", f.Remediation)
	}
	if f.Display["advisory_id"] != "OSV-2021-1627" {
		t.Errorf("metadata advisory_id = %v", f.Metadata["advisory_id"])
	}
	if f.Display["cvss_vector"] != "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H" {
		t.Errorf("metadata cvss_vector = %v", f.Metadata["cvss_vector"])
	}
}

// assertCreatedFindingDims checks the exact dimension set of the created finding.
func assertCreatedFindingDims(t *testing.T, f FindingPayload) {
	t.Helper()
	dims := dimsMap(f)
	wantDims := map[string][]string{
		"purl":              {"pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1"},
		"ecosystem":         {"maven"}, // lowercased at the watcher boundary
		"vulnerability_id":  {"CVE-2021-44228"},
		"source":            {"cve_watcher"},
		"installed_version": {"2.14.1"},
		"alias":             {"GHSA-jfh8-c2jp-5v3q", "OSV-2021-1627"}, // primary excluded, sorted
		"fixed_version":     {"v2.15.0"},
	}
	for k, want := range wantDims {
		if got := dims[k]; !reflect.DeepEqual(got, want) {
			t.Errorf("dim %q = %v, want %v", k, got, want)
		}
	}
	if len(dims) != len(wantDims) {
		t.Errorf("dims = %d keys, want %d: %v", len(dims), len(wantDims), dims)
	}
}

// assertEvidenceRoundTrips checks the stored advisory JSON round-trips.
func assertEvidenceRoundTrips(t *testing.T, evidence []byte) {
	t.Helper()
	if len(evidence) == 0 {
		t.Fatal("Evidence is empty, want advisory JSON")
	}
	var back Advisory
	if err := json.Unmarshal(evidence, &back); err != nil {
		t.Fatalf("unmarshal evidence: %v", err)
	}
	if back.ID != "OSV-2021-1627" || len(back.Affected) != 1 {
		t.Errorf("evidence round-trip = %+v", back)
	}
}

func TestDecideFinding_SkipGapFill(t *testing.T) {
	var calls []string
	dec, err := DecideFinding(context.Background(), log4jInput, stubGapCheck(true, &calls))
	if err != nil {
		t.Fatalf("DecideFinding: %v", err)
	}
	if dec.Created {
		t.Fatal("Created = true, want false when a scan-derived finding covers the pair")
	}
	if !strings.Contains(dec.SkipReason, "scan-derived") {
		t.Errorf("SkipReason = %q", dec.SkipReason)
	}
	if len(calls) != 1 {
		t.Fatalf("gap check calls = %d, want 1", len(calls))
	}
	// Event: auto_rule_skipped with reason in the changes payload.
	if dec.Event == nil || dec.Event.EventType != EventAutoRuleSkipped {
		t.Fatalf("event = %+v, want auto_rule_skipped", dec.Event)
	}
	var changes map[string]any
	if err := json.Unmarshal(dec.Event.Changes, &changes); err != nil {
		t.Fatalf("unmarshal event changes: %v", err)
	}
	if changes["source"] != "cve_watcher" || changes["advisory_id"] != "OSV-2021-1627" {
		t.Errorf("event changes = %v", changes)
	}
	if changes["reason"] == nil || changes["reason"] == "" {
		t.Errorf("skipped event changes missing reason: %v", changes)
	}
}

// TestDecideFinding_FixedFindingSuppresses is the "no reopen logic" gate:
// a scan-derived finding in state 'fixed' still suppresses the watcher —
// the decision logic has no notion of reopening (the gap query matches any
// state; the injected callback returning true models exactly that).
func TestDecideFinding_FixedFindingSuppresses(t *testing.T) {
	dec, err := DecideFinding(context.Background(), log4jInput, stubGapCheck(true, nil))
	if err != nil {
		t.Fatalf("DecideFinding: %v", err)
	}
	if dec.Created {
		t.Fatal("Created = true, want false — fixed scan findings are never reopened by the watcher")
	}
}

func TestDecideFinding_IdempotentRepoll(t *testing.T) {
	// Same inputs twice (a re-poll) must produce byte-identical decisions,
	// including fingerprint, dims order, event JSON, and evidence.
	first, err := DecideFinding(context.Background(), log4jInput, stubGapCheck(false, nil))
	if err != nil {
		t.Fatalf("first poll: %v", err)
	}
	second, err := DecideFinding(context.Background(), log4jInput, stubGapCheck(false, nil))
	if err != nil {
		t.Fatalf("second poll: %v", err)
	}
	if !reflect.DeepEqual(first, second) {
		t.Errorf("re-poll decision differs:\nfirst  = %+v\nsecond = %+v", first, second)
	}
	if !reflect.DeepEqual(first.Evidence, second.Evidence) {
		t.Errorf("re-poll evidence differs")
	}
}

func TestDecideFinding_UnknownSeverity(t *testing.T) {
	// An unrated advisory (no severity[] with a parseable CVSS vector)
	// still creates a finding — visibility — but with severity unknown and
	// rank 0, which never gates (design: unrated advisory policy).
	ad := log4jAdvisory
	ad.Severity = nil
	input := log4jInput
	input.Advisory = ad

	dec, err := DecideFinding(context.Background(), input, stubGapCheck(false, nil))
	if err != nil {
		t.Fatalf("DecideFinding: %v", err)
	}
	if !dec.Created {
		t.Fatalf("Created = false, want true even for unrated advisories (skip reason %q)", dec.SkipReason)
	}
	if dec.Finding.Severity != "unknown" || dec.Finding.SeverityRank != 0 || dec.Finding.Score != 0 {
		t.Errorf("severity = %s/%d/%.1f, want unknown/0/0", dec.Finding.Severity, dec.Finding.SeverityRank, dec.Finding.Score)
	}
	dims := dimsMap(dec.Finding)
	if _, ok := dims["severity"]; ok {
		t.Errorf("severity dim must not be emitted for an unrated advisory (canonical keys only)")
	}
	if _, ok := dec.Finding.Display["cvss_vector"]; ok {
		t.Errorf("metadata should not carry a cvss_vector for an unrated advisory")
	}
}

func TestDecideFinding_UnparseableSeverityFallsBackToUnknown(t *testing.T) {
	ad := log4jAdvisory
	ad.Severity = []AdvisorySeverity{{Type: "CVSS_V3", Score: "not-a-vector"}}
	input := log4jInput
	input.Advisory = ad

	dec, err := DecideFinding(context.Background(), input, stubGapCheck(false, nil))
	if err != nil {
		t.Fatalf("DecideFinding: %v", err)
	}
	if !dec.Created {
		t.Fatal("Created = false, want true")
	}
	if dec.Finding.Severity != "unknown" || dec.Finding.SeverityRank != 0 {
		t.Errorf("severity = %s/%d, want unknown/0", dec.Finding.Severity, dec.Finding.SeverityRank)
	}
}

func TestDecideFinding_CVSS20ZeroVectorRanksLow(t *testing.T) {
	// zero-score handling: a legitimate CVSS 2.0 vector that scores
	// exactly 0.0 (all-neutral metrics) must map to low/rank 1 — visible and
	// gating-eligible — NOT unknown/rank 0. The older `best <= 0` threshold
	// conflated "parseable but zero" with "unparseable".
	const zeroVector = "CVSS:2.0/AV:N/AC:L/Au:N/C:N/I:N/A:N"
	ad := log4jAdvisory
	ad.Severity = []AdvisorySeverity{{Type: "CVSS_V2", Score: zeroVector}}
	input := log4jInput
	input.Advisory = ad

	dec, err := DecideFinding(context.Background(), input, stubGapCheck(false, nil))
	if err != nil {
		t.Fatalf("DecideFinding: %v", err)
	}
	if !dec.Created {
		t.Fatal("Created = false, want true")
	}
	if dec.Finding.Severity != "low" || dec.Finding.SeverityRank != 1 {
		t.Errorf("severity = %s/%d, want low/1 for a 0.0 CVSS 2.0 vector", dec.Finding.Severity, dec.Finding.SeverityRank)
	}
	if dec.Finding.Score != 0.0 {
		t.Errorf("score = %v, want 0.0", dec.Finding.Score)
	}
	if got := dimsMap(dec.Finding)["severity"]; len(got) != 0 {
		t.Errorf("severity dim = %v, want none (canonical keys only)", got)
	}
	if dec.Finding.Display["cvss_vector"] != zeroVector {
		t.Errorf("cvss_vector metadata = %v, want %q", dec.Finding.Metadata["cvss_vector"], zeroVector)
	}
}

func TestDecideFinding_EmptyEcosystemDoesNotMatchOtherEcosystem(t *testing.T) {
	// unknown-ecosystem guard: when the inventory ecosystem is empty, a
	// same-named package in another ecosystem must NOT match. Only an
	// affected entry with no ecosystem can match an ecosystem-less row.
	ad := log4jAdvisory
	ad.Severity = nil
	// The advisory is ecosystem-agnostic (same package shape), so without a
	// guard it would match the ecosystem-less inventory row by name at the
	// same version. The guard must reject it.
	input := log4jInput
	input.Advisory = ad
	input.Ecosystem = "" // inventory ecosystem unknown

	dec, err := DecideFinding(context.Background(), input, stubGapCheck(false, nil))
	if err != nil {
		t.Fatalf("DecideFinding: %v", err)
	}
	if dec.Created {
		t.Fatal("Created = true: an ecosystem-less inventory row must not match an ecosystem-scoped affected entry")
	}
	if !strings.Contains(dec.SkipReason, "no affected entry") {
		t.Errorf("SkipReason = %q, want an affected-match skip", dec.SkipReason)
	}

	// A genuinely ecosystem-less affected entry still matches.
	ad2 := log4jAdvisory
	ad2.Severity = nil
	ad2.Affected = []Affected{{Package: log4jAffected.Package, Ranges: log4jAffected.Ranges}}
	ad2.Affected[0].Ecosystem = ""
	input2 := log4jInput
	input2.Advisory = ad2
	input2.Ecosystem = ""
	dec2, err := DecideFinding(context.Background(), input2, stubGapCheck(false, nil))
	if err != nil {
		t.Fatalf("DecideFinding (no-eco affected): %v", err)
	}
	if !dec2.Created {
		t.Fatalf("Created = false for ecosystem-less affected entry (skip %q)", dec2.SkipReason)
	}
}

func TestDecideFinding_GHSAOnlyAdvisoryDedupesViaAlias(t *testing.T) {
	// GHSA-only advisory (no CVE at all): the candidate id set must carry
	// the GHSA id plus any OSV aliases so the gap-fill check dedupes
	// against existing findings that store GHSA ids in vulnerability_id.
	ad := Advisory{
		ID:       "GHSA-jfh8-c2jp-5v3q",
		Aliases:  []string{"OSV-2021-1627"},
		Summary:  "Log4Shell",
		Affected: []Affected{log4jAffected},
	}
	input := log4jInput
	input.Advisory = ad

	var calls []string
	dec, err := DecideFinding(context.Background(), input, stubGapCheck(true, &calls))
	if err != nil {
		t.Fatalf("DecideFinding: %v", err)
	}
	if dec.Created {
		t.Fatal("Created = true, want false — GHSA-only advisory must dedupe via its GHSA/OSV ids")
	}
	if len(calls) != 1 {
		t.Fatalf("gap check calls = %d, want 1", len(calls))
	}
	if !strings.Contains(calls[0], "GHSA-jfh8-c2jp-5v3q,OSV-2021-1627") {
		t.Errorf("gap check candidate ids = %q, want GHSA primary + OSV alias", calls[0])
	}

	// Same advisory, gap open: primary id becomes the GHSA id, and the
	// fingerprint uses it (cve_id dimension and alias dim are GHSA-led).
	dec2, err := DecideFinding(context.Background(), input, stubGapCheck(false, nil))
	if err != nil {
		t.Fatalf("DecideFinding (open): %v", err)
	}
	if !dec2.Created {
		t.Fatal("Created = false, want true when no finding covers the GHSA-only pair")
	}
	if got := dimsMap(dec2.Finding)["vulnerability_id"]; !reflect.DeepEqual(got, []string{"GHSA-jfh8-c2jp-5v3q"}) {
		t.Errorf("vulnerability_id dim = %v, want [GHSA-jfh8-c2jp-5v3q]", got)
	}
	if got := dimsMap(dec2.Finding)["alias"]; !reflect.DeepEqual(got, []string{"OSV-2021-1627"}) {
		t.Errorf("alias dim = %v, want [OSV-2021-1627]", got)
	}
}

func TestDecideFinding_NameLevelPurlMatching(t *testing.T) {
	// The gap-fill check must receive the NAME-LEVEL purl (version
	// stripped) so version-less osv-scanner finding purls dedupe.
	input := DecideInput{
		ProjectID: "6f0f5f2e-8b3a-4c1d-9e7a-2b4c6d8e0f10",
		Advisory: Advisory{
			ID:       "CVE-2020-8203",
			Aliases:  []string{"GHSA-35jh-r3h4-6jhm"},
			Affected: []Affected{lodashAffected},
		},
		Purl:      "pkg:npm/lodash@4.17.19",
		Version:   "4.17.19",
		Ecosystem: "npm",
	}
	var calls []string
	if _, err := DecideFinding(context.Background(), input, stubGapCheck(false, &calls)); err != nil {
		t.Fatalf("DecideFinding: %v", err)
	}
	if len(calls) != 1 {
		t.Fatalf("gap check calls = %d, want 1", len(calls))
	}
	want := "6f0f5f2e-8b3a-4c1d-9e7a-2b4c6d8e0f10|pkg:npm/lodash|CVE-2020-8203,GHSA-35jh-r3h4-6jhm"
	if calls[0] != want {
		t.Errorf("gap check call = %q, want %q (name-level purl, no @version)", calls[0], want)
	}
}

func TestDecideFinding_EcosystemLowercase(t *testing.T) {
	// Mixed-case storage (Go / Maven / npm / Alpine) must normalize to
	// lowercase in the ecosystem dimension — one normalization point in
	// watcher code (single normalization point). The affine ecosystem is given in a
	// different case than the inventory row to also prove the watcher's
	// case-insensitive ecosystem matching.
	for _, tc := range []struct {
		affEco   string
		inputEco string
		want     string
	}{
		{"npm", "npm", "npm"},
		{"Maven", "MAVEN", "maven"},
		{"Go", "go", "go"},
		{"Alpine", "ALPINE", "alpine"},
		{"PyPI", "pypi", "pypi"},
		{"", "", ""}, // empty ecosystem: no dim row
	} {
		input := log4jInput
		aff := log4jAffected
		aff.Ecosystem = Ecosystem(tc.affEco)
		input.Advisory.Affected = []Affected{aff}
		input.Ecosystem = tc.inputEco
		dec, err := DecideFinding(context.Background(), input, stubGapCheck(false, nil))
		if err != nil {
			t.Fatalf("DecideFinding(%q): %v", tc.inputEco, err)
		}
		if !dec.Created {
			t.Fatalf("Created = false for ecosystem %q (skip %q)", tc.inputEco, dec.SkipReason)
		}
		got := dimsMap(dec.Finding)["ecosystem"]
		if tc.want == "" {
			if len(got) != 0 {
				t.Errorf("ecosystem %q: dims = %v, want no ecosystem dim", tc.inputEco, got)
			}
			continue
		}
		if !reflect.DeepEqual(got, []string{tc.want}) {
			t.Errorf("ecosystem %q: dims = %v, want [%s]", tc.inputEco, got, tc.want)
		}
		if dec.Finding.Display["ecosystem"] != tc.want {
			t.Errorf("ecosystem %q: display = %v, want %q", tc.inputEco, dec.Finding.Display["ecosystem"], tc.want)
		}
	}
}

func TestDecideFinding_NotAffected(t *testing.T) {
	// A version outside the affected region must be skipped without even
	// consulting the gap check (no finding title exists yet).
	input := log4jInput
	input.Version = "2.16.0" // fixed in 2.15.0
	calls := []string{"should-not-be-touched"}
	gap := func(_ context.Context, _, _ string, _ []string) (bool, error) {
		calls = append(calls, "called")
		return false, nil
	}
	dec, err := DecideFinding(context.Background(), input, gap)
	if err != nil {
		t.Fatalf("DecideFinding: %v", err)
	}
	if dec.Created {
		t.Fatal("Created = true for a safe version")
	}
	if !strings.Contains(dec.SkipReason, "no affected entry") {
		t.Errorf("SkipReason = %q", dec.SkipReason)
	}
	if dec.Event != nil {
		t.Errorf("Event = %+v, want nil when nothing is created or suppressed", dec.Event)
	}
	for _, c := range calls {
		if c == "called" {
			t.Error("gap check was called for a not-affected pair")
		}
	}
}

func TestDecideFinding_NoIdentifiers(t *testing.T) {
	input := log4jInput
	input.Advisory = Advisory{Summary: "mystery", Affected: []Affected{log4jAffected}}
	dec, err := DecideFinding(context.Background(), input, stubGapCheck(false, nil))
	if err != nil {
		t.Fatalf("DecideFinding: %v", err)
	}
	if dec.Created {
		t.Fatal("Created = true for an advisory with no identifiers")
	}
	if !strings.Contains(dec.SkipReason, "identifiers") {
		t.Errorf("SkipReason = %q", dec.SkipReason)
	}
}

func TestDecideFinding_EmptyPurl(t *testing.T) {
	input := log4jInput
	input.Purl = ""
	dec, err := DecideFinding(context.Background(), input, stubGapCheck(false, nil))
	if err != nil {
		t.Fatalf("DecideFinding: %v", err)
	}
	if dec.Created {
		t.Fatal("Created = true for an empty purl")
	}
}

func TestDecideFinding_GapCheckErrorPropagates(t *testing.T) {
	gap := func(context.Context, string, string, []string) (bool, error) {
		return false, context.DeadlineExceeded
	}
	_, err := DecideFinding(context.Background(), log4jInput, gap)
	if err == nil {
		t.Fatal("DecideFinding returned nil error, want the gap check error")
	}
}

func TestDecideFinding_NilGapCheck(t *testing.T) {
	if _, err := DecideFinding(context.Background(), log4jInput, nil); err == nil {
		t.Fatal("DecideFinding returned nil error with a nil gap check")
	}
}

func TestPurlNameLevel(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want string
	}{
		{"versioned npm purl", "pkg:npm/lodash@4.17.19", "pkg:npm/lodash"},
		{"versionless purl passes through", "pkg:npm/lodash", "pkg:npm/lodash"},
		{"maven namespace purl", "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1", "pkg:maven/org.apache.logging.log4j/log4j-core"},
		{"golang module purl", "pkg:golang/github.com/gin-gonic/gin@v1.6.3", "pkg:golang/github.com/gin-gonic/gin"},
		{"qualifiers stripped by caller, version kept", "pkg:apk/alpine/libcrypto3@3.3.2-r0", "pkg:apk/alpine/libcrypto3"},
		{"non-purl with version cuts at last at", "python:setuptools@57.5.0", "python:setuptools"},
		{"non-purl without version unchanged", "binutils", "binutils"},
		// ***REMOVED***: the SQL side of the gap-fill join (findings.sql
		// FindScaFindingIdForPurlAndCve) must align with this LAST-'@' cut, so
		// a non-purl fallback with '@' in its name resolves the same way.
		{"non-purl with at in name cuts at last at", "corp@vendor/pkg@1.0.0", "corp@vendor/pkg"},
		{"empty input", "", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := purlNameLevel(tt.in); got != tt.want {
				t.Errorf("purlNameLevel(%q) = %q, want %q", tt.in, got, tt.want)
			}
		})
	}
}

func TestFingerprint(t *testing.T) {
	// Known-answer test for the design formula sha256(purl@version|cve_id).
	const want = "98136555043f269d8a9d667eefdf1da8a0760e4d48adb1e00c598da98b16f825"
	if got := fingerprint("pkg:npm/lodash@4.17.19", "CVE-2020-8203"); got != want {
		t.Errorf("fingerprint = %q, want %q", got, want)
	}
}

func TestFixedVersions(t *testing.T) {
	got := fixedVersions(log4jAdvisory.Affected)
	if !reflect.DeepEqual(got, []string{"v2.15.0"}) {
		t.Errorf("fixedVersions = %v, want [v2.15.0]", got)
	}

	// Two ranges, same fix, plus an unparseable bound: deduped and the
	// unparseable one dropped. ("1.2.3-1" is NOT used here: it parses as
	// semver prerelease, so it is a legitimate fix version.)
	affs := []Affected{
		{Ranges: []VersionRange{{Events: []RangeEvent{{Introduced: "0"}, {Fixed: "2.15.0"}}}}},
		{Ranges: []VersionRange{{Events: []RangeEvent{{Introduced: "0"}, {Fixed: "2.15.0"}}}}},
		{Ranges: []VersionRange{{Events: []RangeEvent{{Introduced: "0"}, {Fixed: "not-a-version"}}}}},
	}
	if got := fixedVersions(affs); !reflect.DeepEqual(got, []string{"v2.15.0"}) {
		t.Errorf("fixedVersions dedupe = %v, want [v2.15.0]", got)
	}
}

func TestAdvisorySeverity(t *testing.T) {
	tests := []struct {
		name      string
		ratings   []AdvisorySeverity
		wantStr   string
		wantRank  int16
		wantScore float64
	}{
		{"empty ratings", nil, "unknown", 0, 0},
		{"v3 critical", []AdvisorySeverity{{Type: "CVSS_V3", Score: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}}, "critical", 4, 9.8},
		{"v4 score picked", []AdvisorySeverity{{Type: "CVSS_V4", Score: "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"}}, "critical", 4, 9.3},
		{"high from v2", []AdvisorySeverity{{Type: "CVSS_V2", Score: "CVSS:2.0/AV:N/AC:L/Au:N/C:P/I:P/A:P"}}, "high", 3, 7.5},
		{"medium band", []AdvisorySeverity{{Type: "CVSS_V3", Score: "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N"}}, "medium", 2, 5.4},
		{"low band", []AdvisorySeverity{{Type: "CVSS_V3", Score: "CVSS:3.1/AV:L/AC:H/PR:H/UI:N/S:U/C:L/I:N/A:N"}}, "low", 1, 1.9},
		{"highest of several wins", []AdvisorySeverity{
			{Type: "CVSS_V2", Score: "CVSS:2.0/AV:N/AC:L/Au:N/C:P/I:P/A:P"},
			{Type: "CVSS_V3", Score: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"},
		}, "critical", 4, 9.8},
		{"unparseable ignored", []AdvisorySeverity{{Type: "CVSS_V3", Score: "garbage"}}, "unknown", 0, 0},
		{"blank scores ignored", []AdvisorySeverity{{Type: "CVSS_V3", Score: "  "}}, "unknown", 0, 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			str, rank, score, _ := advisorySeverity(tt.ratings)
			if str != tt.wantStr || rank != tt.wantRank || score != tt.wantScore {
				t.Errorf("advisorySeverity = (%s, %d, %.1f), want (%s, %d, %.1f)",
					str, rank, score, tt.wantStr, tt.wantRank, tt.wantScore)
			}
		})
	}
}
