package usecase

import (
	"encoding/json"
	"testing"

	"github.com/minh-tg/specht/internal/domain"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestScopeHashMaterial_StableAndSensitive(t *testing.T) {
	base := func() IngestReportInput {
		return IngestReportInput{
			Scanner:         "trivy",
			ArtifactName:    "myapp",
			ArtifactVersion: "1.2.3",
			Branch:          "main",
			CommitSha:       "abc123",
			Environment:     "prod",
		}
	}
	nr := &domain.NormalizedReport{Target: &domain.TargetInfo{Identifier: "img:latest"}}
	ctxInfo := reportContext{}

	// Deterministic: identical inputs hash identically.
	assert.Equal(t,
		scopeHashMaterial(base(), nr, ctxInfo),
		scopeHashMaterial(base(), nr, ctxInfo),
	)

	// Every scope attribute must change the material (thus the hash).
	sensitive := []struct {
		name string
		mut  func(*IngestReportInput)
	}{
		{"scanner", func(i *IngestReportInput) { i.Scanner = "grype" }},
		{"artifact name", func(i *IngestReportInput) { i.ArtifactName = "other" }},
		{"artifact version", func(i *IngestReportInput) { i.ArtifactVersion = "2.0.0" }},
		{"branch", func(i *IngestReportInput) { i.Branch = "dev" }},
		{"commit sha", func(i *IngestReportInput) { i.CommitSha = "def456" }},
		{"environment", func(i *IngestReportInput) { i.Environment = "dev" }},
	}
	for _, tt := range sensitive {
		t.Run(tt.name, func(t *testing.T) {
			in := base()
			tt.mut(&in)
			assert.NotEqual(t, scopeHashMaterial(base(), nr, ctxInfo), scopeHashMaterial(in, nr, ctxInfo),
				"scope material must change when %s changes", tt.name)
		})
	}
}

func TestScopeHashMaterial_TargetChanges(t *testing.T) {
	a := scopeHashMaterial(IngestReportInput{Scanner: "trivy"}, &domain.NormalizedReport{Target: &domain.TargetInfo{Identifier: "img:a"}}, reportContext{})
	b := scopeHashMaterial(IngestReportInput{Scanner: "trivy"}, &domain.NormalizedReport{Target: &domain.TargetInfo{Identifier: "img:b"}}, reportContext{})
	assert.NotEqual(t, a, b)
}

func TestBuildOccurrenceDocument_NamespacesAndPreserves(t *testing.T) {
	f := domain.NormalizedFinding{
		Aliases:      []string{"CVE-2021-3121"},
		Resource:     "pkg@1.0",
		Extensions:   map[string]any{"cwe_ids": []any{"CWE-798"}, "status": "fixed"},
		Reachability: &domain.ReachabilityHint{State: domain.ReachabilityNotReachable, Evidence: "no path", Source: "osv"},
		CVSS:         &domain.CVSSInfo{Version: "3.1", Vector: "CVSS:3.1/AV:N", Score: 7.5},
		Fix:          &domain.FixInfo{Summary: "1.2.4"},
		CodeLocation: &domain.CodeLocation{File: "a.go", StartLine: 3},
	}
	doc := buildOccurrenceDocument(f, "trivy")

	// Producer payload namespaced under the source name; a producer's own
	// "specht" extension key is dropped (reserved), while the canonical
	// specht namespace holds the core's enrichment data.
	assert.Equal(t, []any{"CWE-798"}, doc.Metadata["trivy.cwe_ids"])
	assert.Equal(t, "fixed", doc.Metadata["trivy.status"])
	// The canonical specht namespace is present with enrichment data.
	assert.Contains(t, doc.Metadata, spechtNamespace)

	// Canonical specht namespace carries aliases/CVSS/fix/location/resource/hint.
	specht := doc.Metadata[spechtNamespace].(map[string]any)
	assert.Equal(t, []string{"CVE-2021-3121"}, specht["aliases"])
	assert.Equal(t, "pkg@1.0", specht["resource"])
	assert.Equal(t, "3.1", specht["cvss"].(*domain.CVSSInfo).Version)
	assert.Equal(t, "1.2.4", specht["fix"].(*domain.FixInfo).Summary)
	assert.Equal(t, "a.go", specht["code_location"].(*domain.CodeLocation).File)
	hint := specht["reachability_hint"].(map[string]any)
	assert.Equal(t, "not_reachable", hint["state"])
	assert.Equal(t, "osv", hint["source"])
}

func TestBuildOccurrenceDocument_DisplayEmpty(t *testing.T) {
	doc := buildOccurrenceDocument(domain.NormalizedFinding{}, "trivy")
	assert.Empty(t, doc.Display)
	data, err := json.Marshal(doc.Metadata)
	require.NoError(t, err)
	assert.JSONEq(t, `{}`, string(data), "no canonical payload -> empty metadata object")
}

func TestToOccurrenceParams_Lossless(t *testing.T) {
	f := domain.NormalizedFinding{
		Title:       "t",
		Description: "d",
		Severity:    domain.SeverityHigh,
		Score:       7.5,
		Location:    "/a/b",
		Extensions:  map[string]any{"k": "v"},
	}
	p := toOccurrenceParams(f, "grype")
	assert.Equal(t, "t", p.Title)
	assert.Equal(t, "high", p.Severity)
	assert.Equal(t, int16(3), p.SeverityRank)
	require.NotNil(t, p.LocationSummary)
	assert.Equal(t, "/a/b", *p.LocationSummary)
	assert.Equal(t, "grype", p.ToolName)
	var meta map[string]any
	require.NoError(t, json.Unmarshal(p.Metadata, &meta))
	assert.Equal(t, "v", meta["grype.k"])
}

func TestCanonicalDimensionFilter(t *testing.T) {
	assert.True(t, isCanonicalDimension(domain.DimVulnerabilityID))
	assert.True(t, isCanonicalDimension(domain.DimAlias))
	assert.True(t, isCanonicalDimension(domain.DimSource))
	assert.True(t, isCanonicalDimension("file_name") == false, "file_name is not a canonical key")
	assert.True(t, isCanonicalDimension("cve_id") == false, "cve_id is not a canonical key")
	assert.True(t, isCanonicalDimension("component.identity") == false)
	assert.True(t, isCanonicalDimension("severity") == false)
}
