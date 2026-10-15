package parser_test

import (
	"context"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/minh-tg/specht/internal/domain"
	"github.com/minh-tg/specht/internal/parser/grype"
	"github.com/minh-tg/specht/internal/parser/sbom"
	"github.com/minh-tg/specht/internal/scanner"
)

func parseWith(t *testing.T, s scanner.Scanner, path string) *domain.NormalizedReport {
	t.Helper()
	data, err := os.ReadFile(path)
	require.NoError(t, err)
	nr, err := s.Parse(context.Background(), data)
	require.NoError(t, err)
	return nr
}

// A project can run grype -o json one week and grype -o cyclonedx-json the next. The two files
// describe the same scan, and the same vulnerability in the same package has to be the same
// finding in both, with the same severity, so its triage history carries over.
func TestGrypeJSONAndGrypeCycloneDXAreTheSameFindings(t *testing.T) {
	native := parseWith(t, grype.NewScanner(), "grype/testdata/grype-same-scan.json")
	bom := parseWith(t, sbom.NewScanner(), "sbom/testdata/grype-cyclonedx.json")

	require.Len(t, native.Findings, 3)
	require.Len(t, bom.Findings, len(native.Findings))

	byFingerprint := map[string]domain.NormalizedFinding{}
	for _, f := range native.Findings {
		byFingerprint[f.Fingerprint] = f
	}
	for _, f := range bom.Findings {
		n, ok := byFingerprint[f.Fingerprint]
		require.True(t, ok, "the CycloneDX finding %s has no counterpart in Grype's JSON", f.Fingerprint)
		assert.Equal(t, n.Severity, f.Severity, f.Fingerprint)
		assert.Equal(t, n.Title, f.Title)
		assert.Equal(t, n.Resource, f.Resource)
	}
}
