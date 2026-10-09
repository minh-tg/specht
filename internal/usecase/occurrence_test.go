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

	// Deterministic: identical inputs hash identically.
	assert.Equal(t,
		scopeHashMaterial(base(), nr),
		scopeHashMaterial(base(), nr),
	)

	// Every scope attribute must change the material (thus the hash).
	sensitive := []struct {
		name string
		mut  func(*IngestReportInput)
	}{
		{"scanner", func(i *IngestReportInput) { i.Scanner = "grype" }},
		{"artifact name", func(i *IngestReportInput) { i.ArtifactName = "other" }},
		{"branch", func(i *IngestReportInput) { i.Branch = "dev" }},
		{"environment", func(i *IngestReportInput) { i.Environment = "dev" }},
	}
	for _, tt := range sensitive {
		t.Run(tt.name, func(t *testing.T) {
			in := base()
			tt.mut(&in)
			assert.NotEqual(t, scopeHashMaterial(base(), nr), scopeHashMaterial(in, nr),
				"scope material must change when %s changes", tt.name)
		})
	}

	// Commit and artifact version are not scope: a later commit on the same
	// branch must stay in the scope its predecessor established.
	stable := []struct {
		name string
		mut  func(*IngestReportInput)
	}{
		{"artifact version", func(i *IngestReportInput) { i.ArtifactVersion = "2.0.0" }},
		{"commit sha", func(i *IngestReportInput) { i.CommitSha = "def456" }},
	}
	for _, tt := range stable {
		t.Run(tt.name+" is not scope", func(t *testing.T) {
			in := base()
			tt.mut(&in)
			assert.Equal(t, scopeHashMaterial(base(), nr), scopeHashMaterial(in, nr),
				"scope material must not change when %s changes", tt.name)
		})
	}

	// Image tags change on every build, so two tags of one image share a scope.
	// Different image names stay apart.
	image := func(identifier string) *domain.NormalizedReport {
		return &domain.NormalizedReport{Target: &domain.TargetInfo{Kind: "container_image", Identifier: identifier}}
	}
	assert.Equal(t,
		scopeHashMaterial(base(), image("img:1")),
		scopeHashMaterial(base(), image("img:2")),
		"scope material must not change when only the image tag changes")
	assert.NotEqual(t,
		scopeHashMaterial(base(), image("img-a:1")),
		scopeHashMaterial(base(), image("img-b:1")),
		"scope material must change when the image name changes")
}

func TestScopeTargetIdentifier(t *testing.T) {
	const digest = "sha256:9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"
	cases := []struct {
		name       string
		kind       string
		identifier string
		want       string
	}{
		{"image tag is dropped", "container_image", "registry/app:1.2", "registry/app"},
		{"image without tag is unchanged", "container_image", "registry/app", "registry/app"},
		{"image digest is dropped", "container_image", "registry/app@" + digest, "registry/app"},
		{"image tag and digest are dropped", "container_image", "registry/app:sha-abc@" + digest, "registry/app"},
		{"registry port kept with tag", "container_image", "registry.local:5000/team/app:1.2", "registry.local:5000/team/app"},
		{"registry port kept without tag", "container_image", "registry.local:5000/team/app", "registry.local:5000/team/app"},
		{"registry port kept with digest", "container_image", "registry.local:5000/team/app@" + digest, "registry.local:5000/team/app"},
		{"bare image tag is dropped", "container_image", "app:latest", "app"},
		{"sbom name without version", "package", "left-pad", "left-pad"},
		{"sbom version is dropped", "package", "left-pad@1.3.0", "left-pad"},
		{"sbom scoped name keeps its scope", "package", "@scope/pkg@2.0.0", "@scope/pkg"},
		{"sbom scoped name without version", "package", "@scope/pkg", "@scope/pkg"},
		{"sbom empty version", "package", "left-pad@", "left-pad"},
		{"filesystem path with @ is unchanged", "filesystem", "vendor/pkg@v1/app", "vendor/pkg@v1/app"},
		{"filesystem path with colon is unchanged", "filesystem", "dir/file:1", "dir/file:1"},
		{"iac target is unchanged", "iac", "main.tf", "main.tf"},
		{"empty identifier", "container_image", "", ""},
	}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, scopeTargetIdentifier(tt.kind, tt.identifier))
		})
	}
}

func TestScopeHashMaterial_TargetChanges(t *testing.T) {
	a := scopeHashMaterial(IngestReportInput{Scanner: "trivy"}, &domain.NormalizedReport{Target: &domain.TargetInfo{Identifier: "img:a"}})
	b := scopeHashMaterial(IngestReportInput{Scanner: "trivy"}, &domain.NormalizedReport{Target: &domain.TargetInfo{Identifier: "img:b"}})
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
