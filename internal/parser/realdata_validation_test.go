// Package parser_test holds the real-data validation sweep: every
// built-in adapter parses its realistic fixture through the same
// Parser.Builtins() composition the ingest path uses, and the normalized
// output must honor the domain contract (canonical dimension keys, stable
// unique fingerprints, in-range severities, descriptor-kind agreement).
package parser_test

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/minh-tg/specht/internal/domain"
	"github.com/minh-tg/specht/internal/parser"
	"github.com/minh-tg/specht/internal/scanner"
)

var canonicalDims = map[string]struct{}{
	domain.DimVulnerabilityID: {},
	domain.DimAlias:           {},
	domain.DimPURL:            {},
	domain.DimPackageName:     {},
	domain.DimEcosystem:       {},
	domain.DimInstalledVer:    {},
	domain.DimFixedVersion:    {},
	domain.DimRuleID:          {},
	domain.DimFile:            {},
	domain.DimLine:            {},
	domain.DimResource:        {},
	domain.DimSource:          {},
	domain.DimURL:             {},
	domain.DimParameter:       {},
}

type realdataCase struct {
	scanner string
	fixture string // relative to internal/parser/<adapter>/testdata
	min     int
	minPkg  int
	// allowDupFingerprints documents adapters whose reports legitimately
	// carry two observations under one identity (e.g. nuclei matchers on
	// one URL): ingest upserts one row with two occurrences.
	allowDupFingerprints bool
}

func TestRealDataValidationSweep(t *testing.T) {
	byName := map[string]scanner.Scanner{}
	for _, s := range parser.Builtins() {
		byName[s.Descriptor().Name] = s
	}

	cases := []realdataCase{
		{"trivy", "trivy/testdata/alpine-full.json", 8, 100, false},
		{"trivy", "trivy/testdata/multi-type-scan.json", 4, 0, false},
		{"osv-scanner", "osvscanner/testdata/go-full.json", 12, 100, false},
		{"checkov", "checkov/testdata/checkov-terraform.json", 3, 0, false},
		{"checkov", "checkov/testdata/checkov-kubernetes.json", 2, 0, false},
		{"checkov", "checkov/testdata/checkov-cloudformation.json", 1, 0, false},
		{"dependency-check", "dependencycheck/testdata/dependency-check-report.json", 2, 0, false},
		{"semgrep", "semgrep/testdata/semgrep-sarif.json", 2, 0, false},
		{"tfsec", "tfsec/testdata/tfsec.json", 2, 0, false},
		{scanner: "nuclei", fixture: "nuclei/testdata/nuclei.jsonl", min: 3, allowDupFingerprints: true},
		{"grype", "grype/testdata/grype-full.json", 105, 100, false},
		{"sbom", "sbom/testdata/cyclonedx.json", 0, 3, false},
		{"sbom", "sbom/testdata/spdx.json", 0, 2, false},
		{"gitleaks", "gitleaks/testdata/gitleaks.json", 3, 0, false},
		{"sarif", "sarif/testdata/multi-tool.sarif.json", 3, 0, false},
	}

	for _, tc := range cases {
		t.Run(tc.scanner+"/"+filepath.Base(tc.fixture), func(t *testing.T) {
			s, ok := byName[tc.scanner]
			require.True(t, ok, "scanner %q not in Builtins()", tc.scanner)
			desc := s.Descriptor()
			data, err := os.ReadFile(tc.fixture)

			require.NoError(t, err)

			rep, err := s.Parse(context.Background(), data)
			require.NoError(t, err)
			require.NotNil(t, rep)
			require.GreaterOrEqual(t, len(rep.Findings), tc.min)
			require.GreaterOrEqual(t, len(rep.Packages), tc.minPkg)
			t.Logf("%s/%s: %d findings, %d packages, completeness=%q",
				tc.scanner, filepath.Base(tc.fixture), len(rep.Findings), len(rep.Packages), rep.Completeness)

			declared := map[string]struct{}{}
			for _, k := range desc.FindingKinds {
				declared[string(k)] = struct{}{}
			}

			seen := map[string]string{}
			for i, f := range rep.Findings {
				validateSweepFinding(t, f, i, &sweepState{seen: seen, declared: declared, desc: desc, allowDups: tc.allowDupFingerprints})
			}
		})
	}
}

// sweepState carries the cross-finding sweep bookkeeping: fingerprints seen
// so far, the descriptor's declared kinds, and the duplicate policy.
type sweepState struct {
	seen      map[string]string
	declared  map[string]struct{}
	desc      scanner.Descriptor
	allowDups bool
}

// validateSweepFinding applies the per-finding invariants of the sweep:
// non-empty unique fingerprint, in-range severity, declared finding kind,
// and canonical non-empty dimensions.
func validateSweepFinding(t *testing.T, f domain.NormalizedFinding, i int, st *sweepState) {
	t.Helper()
	require.NotEmpty(t, f.Fingerprint, "finding %d missing fingerprint", i)
	if prev, dup := st.seen[f.Fingerprint]; dup && !st.allowDups {
		t.Fatalf("duplicate fingerprint %q (findings %q and %q)", f.Fingerprint, prev, f.Title)
	}
	st.seen[f.Fingerprint] = f.Title
	assert.GreaterOrEqual(t, int(f.Severity), int(domain.SeverityUnknown))
	assert.LessOrEqual(t, int(f.Severity), int(domain.SeverityCritical))
	_, ok := st.declared[f.FindingKind]
	assert.True(t, ok, "finding kind %q not in descriptor %v", f.FindingKind, st.desc.FindingKinds)
	for _, d := range f.Dimensions {
		_, ok := canonicalDims[d.Key]
		assert.True(t, ok, "non-canonical dimension key %q", d.Key)
		assert.NotEmpty(t, d.Value, "empty value for dimension %q", d.Key)
	}
}
