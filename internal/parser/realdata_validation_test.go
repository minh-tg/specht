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

	"github.com/xMinhx/specht/internal/domain"
	"github.com/xMinhx/specht/internal/parser"
	"github.com/xMinhx/specht/internal/scanner"
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
}

type realdataCase struct {
	scanner string
	fixture string // relative to internal/parser/<adapter>/testdata
	min     int
	minPkg  int
}

func TestRealDataValidationSweep(t *testing.T) {
	byName := map[string]scanner.Scanner{}
	for _, s := range parser.Builtins() {
		byName[s.Descriptor().Name] = s
	}

	cases := []realdataCase{
		{"trivy", "trivy/testdata/alpine-full.json", 8, 100},
		{"trivy", "trivy/testdata/multi-type-scan.json", 4, 0},
		{"osv-scanner", "osvscanner/testdata/go-full.json", 12, 100},
		{"checkov", "checkov/testdata/checkov-terraform.json", 3, 0},
		{"checkov", "checkov/testdata/checkov-kubernetes.json", 2, 0},
		{"checkov", "checkov/testdata/checkov-cloudformation.json", 1, 0},
		{"tfsec", "tfsec/testdata/tfsec.json", 2, 0},
		{"dependency-check", "dependencycheck/testdata/dependency-check-full.json", 12, 100},
		{"grype", "grype/testdata/grype-full.json", 105, 100},
		{"sbom", "sbom/testdata/cyclonedx.json", 0, 3},
		{"sbom", "sbom/testdata/spdx.json", 0, 2},
		{"sarif", "sarif/testdata/multi-tool.sarif.json", 3, 0},
		{"gitleaks", "gitleaks/testdata/gitleaks.json", 3, 0},
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
				require.NotEmpty(t, f.Fingerprint, "finding %d missing fingerprint", i)
				if prev, dup := seen[f.Fingerprint]; dup {
					t.Fatalf("duplicate fingerprint %q (findings %q and %q)", f.Fingerprint, prev, f.Title)
				}
				seen[f.Fingerprint] = f.Title
				assert.GreaterOrEqual(t, int(f.Severity), int(domain.SeverityUnknown))
				assert.LessOrEqual(t, int(f.Severity), int(domain.SeverityCritical))
				_, ok := declared[f.FindingKind]
				assert.True(t, ok, "finding kind %q not in descriptor %v", f.FindingKind, desc.FindingKinds)
				for _, d := range f.Dimensions {
					_, ok := canonicalDims[d.Key]
					assert.True(t, ok, "non-canonical dimension key %q", d.Key)
					assert.NotEmpty(t, d.Value, "empty value for dimension %q", d.Key)
				}
			}
		})
	}
}
