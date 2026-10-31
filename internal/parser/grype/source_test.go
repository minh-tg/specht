package grype

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/minh-tg/specht/internal/domain"
)

const configuration = `"configuration":{"only-fixed":false,"only-notfixed":false,"ignore":[],"exclude":[]}`

func grypeDocWithSource(source string, withMatch bool) []byte {
	matches := `[]`
	if withMatch {
		matches = `[{"vulnerability":{"id":"CVE-2031-1000","severity":"High"},"artifact":{"name":"lodash","version":"4.17.20","type":"npm","purl":"pkg:npm/lodash@4.17.20","locations":[{"path":"/app/package-lock.json"}]}}]`
	}
	src := ""
	if source != "" {
		src = `"source":` + source + `,`
	}
	return []byte(fmt.Sprintf(`{"matches":%s,%s"descriptor":{"name":"grype","version":"0.120.1",%s}}`, matches, src, configuration))
}

func parseTarget(t *testing.T, doc []byte) *domain.NormalizedReport {
	t.Helper()
	nr, err := NewScanner().Parse(context.Background(), doc)
	require.NoError(t, err)
	return nr
}

func TestTargetComesFromTheSourceNotFromTheMatches(t *testing.T) {
	cases := []struct {
		name     string
		source   string
		kind     string
		target   string
		scanType domain.ScanType
	}{
		{
			"image", `{"type":"image","target":{"userInput":"registry.example.com/app:1.4","imageID":"sha256:aa","tags":["registry.example.com/app:1.4"]}}`,
			"container_image", "registry.example.com/app:1.4", domain.ScanTypeImage,
		},
		{
			"image fetched through a named transport", `{"type":"image","target":{"userInput":"docker:app:1.4"}}`,
			"container_image", "app:1.4", domain.ScanTypeImage,
		},
		{
			"image without user input", `{"type":"image","target":{"tags":["app:1.4"],"repoDigests":["app@sha256:bb"]}}`,
			"container_image", "app:1.4", domain.ScanTypeImage,
		},
		{
			"image archive on disk", `{"type":"image","target":{"userInput":"docker-archive:build/app.tar"}}`,
			"filesystem", "docker-archive:build/app.tar", domain.ScanTypeImage,
		},
		{
			"directory", `{"type":"directory","target":{"userInput":"."}}`,
			"filesystem", ".", domain.ScanTypeFilesystem,
		},
		{
			"directory written as a string", `{"type":"directory","target":"/work/src"}`,
			"filesystem", "/work/src", domain.ScanTypeFilesystem,
		},
		{
			"file", `{"type":"file","target":{"path":"build/app.sbom.json"}}`,
			"filesystem", "build/app.sbom.json", domain.ScanTypeFilesystem,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			withMatch := parseTarget(t, grypeDocWithSource(tc.source, true))
			clean := parseTarget(t, grypeDocWithSource(tc.source, false))
			for _, nr := range []*domain.NormalizedReport{withMatch, clean} {
				require.NotNil(t, nr.Target)
				assert.Equal(t, tc.kind, nr.Target.Kind)
				assert.Equal(t, tc.target, nr.Target.Identifier)
				assert.Equal(t, tc.scanType, nr.ScanType)
			}
			assert.Equal(t, withMatch.Target, clean.Target, "a clean scan names the same target as one with findings")
		})
	}
}

func TestTargetFallsBackToTheFirstMatchWithoutASource(t *testing.T) {
	for _, source := range []string{``, `{}`, `{"type":"image"}`, `{"type":"image","target":{"imageID":"sha256:aa"}}`, `{"type":"directory","target":""}`} {
		t.Run(source, func(t *testing.T) {
			nr := parseTarget(t, grypeDocWithSource(source, true))
			require.NotNil(t, nr.Target)
			assert.Equal(t, "filesystem", nr.Target.Kind)
			assert.Equal(t, "/app/package-lock.json", nr.Target.Identifier)
			assert.Equal(t, domain.ScanTypeFilesystem, nr.ScanType)

			assert.Nil(t, parseTarget(t, grypeDocWithSource(source, false)).Target, "a clean report with no source names no target")
		})
	}
}

// grype-same-scan.json is a real directory scan, and a scan of the same
// directory with every match removed must keep its target.
func TestRealDirectoryScanKeepsItsTargetWhenClean(t *testing.T) {
	raw, err := os.ReadFile("testdata/grype-same-scan.json")
	require.NoError(t, err)
	nr := parseTarget(t, raw)
	require.Len(t, nr.Findings, 3)
	require.NotNil(t, nr.Target)
	assert.Equal(t, "filesystem", nr.Target.Kind)
	assert.Equal(t, ".", nr.Target.Identifier)

	clean := parseTarget(t, grypeDocWithSource(`{"type":"directory","target":{"userInput":"."}}`, false))
	assert.Equal(t, nr.Target, clean.Target)
}

// withoutMatches returns the report with its matches array emptied and every
// other field, source included, left as Grype wrote it.
func withoutMatches(t *testing.T, raw []byte) []byte {
	t.Helper()
	var doc map[string]json.RawMessage
	require.NoError(t, json.Unmarshal(raw, &doc))
	doc["matches"] = json.RawMessage(`[]`)
	out, err := json.Marshal(doc)
	require.NoError(t, err)
	return out
}

// The fixtures below are Grype 0.120.0 output trimmed to three matches.
// grype-image.json is `grype registry:docker.io/library/alpine:3.18`.
// grype-sbom.json is `grype sbom:` on a Syft CycloneDX SBOM of a directory
// holding a package-lock.json, scanned with --source-name grype-fixture-lock.
func TestRealImageAndSBOMSourcesDeriveTheirTargets(t *testing.T) {
	cases := []struct {
		name     string
		fixture  string
		kind     string
		target   string
		scanType domain.ScanType
	}{
		{
			"image pulled from a registry", "testdata/grype-image.json",
			"container_image", "docker.io/library/alpine:3.18", domain.ScanTypeImage,
		},
		{
			"SBOM file scan", "testdata/grype-sbom.json",
			"filesystem", "grype-fixture-lock", domain.ScanTypeFilesystem,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			raw, err := os.ReadFile(tc.fixture)
			require.NoError(t, err)

			withFindings := parseTarget(t, raw)
			require.Len(t, withFindings.Findings, 3)
			require.NotNil(t, withFindings.Target)
			assert.Equal(t, tc.kind, withFindings.Target.Kind)
			assert.Equal(t, tc.target, withFindings.Target.Identifier)
			assert.Equal(t, tc.scanType, withFindings.ScanType)

			clean := parseTarget(t, withoutMatches(t, raw))
			assert.Empty(t, clean.Findings)
			assert.Equal(t, withFindings.Target, clean.Target, "a clean scan of the same source names the same target")
			assert.Equal(t, withFindings.ScanType, clean.ScanType)
		})
	}
}
