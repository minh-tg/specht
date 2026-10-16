package parser_test

import (
	"encoding/json"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/minh-tg/specht/internal/domain"
	"github.com/minh-tg/specht/internal/parser/parseutil"
)

// assertNestedFieldsBounded checks the report-level and nested fields that
// HardenFinding's flat string bounds do not reach.
func assertNestedFieldsBounded(t *testing.T, rep *domain.NormalizedReport) {
	t.Helper()
	if rep.Target != nil {
		assert.LessOrEqual(t, len(rep.Target.Identifier), parseutil.MaxTargetIdentifierLength, "target identifier")
		assert.LessOrEqual(t, len(rep.Target.Kind), parseutil.MaxTargetKindLength, "target kind")
		assert.True(t, utf8.ValidString(rep.Target.Identifier))
	}
	if rep.Artifact != nil {
		assert.LessOrEqual(t, len(rep.Artifact.Identifier), parseutil.MaxTargetIdentifierLength)
		assert.LessOrEqual(t, len(rep.Artifact.Kind), parseutil.MaxTargetKindLength)
		assert.LessOrEqual(t, serialized(t, rep.Artifact.Metadata), parseutil.MaxExtensionsBytes)
	}
	if rep.ScanScope != nil {
		for k, v := range rep.ScanScope.Ext {
			assert.LessOrEqual(t, len(k), parseutil.MaxScopeKeyLength, "scope key")
			assert.LessOrEqual(t, len(v), parseutil.MaxScopeValueLength, "scope value %s", k)
			assert.NotContains(t, v, "\x00")
		}
	}
	for i, f := range rep.Findings {
		assert.LessOrEqual(t, serialized(t, f.Extensions), parseutil.MaxExtensionsBytes, "finding %d extensions", i)
	}
}

func serialized(t *testing.T, v any) int {
	t.Helper()
	b, err := json.Marshal(v)
	require.NoError(t, err)
	return len(b)
}

// The audit measured 3 MiB per upload copied into the database through these
// fields, and an oversized target name made the target upsert fail silently.
func TestNestedFieldsAreBoundedForEveryParser(t *testing.T) {
	big := strings.Repeat("Z", 3<<20)
	docs := map[string]struct{ scanner, doc string }{
		"trivy":            {"trivy", `{"SchemaVersion":2,"ArtifactName":"` + big + `","ArtifactType":"` + big + `","Results":[{"Target":"t","Class":"os-pkgs","Vulnerabilities":[{"VulnerabilityID":"CVE-1","PkgName":"p","PkgIdentifier":{"PURL":"pkg:apk/a@1"},"Severity":"HIGH","CweIDs":["` + big + `"],"PrimaryURL":"` + big + `"}]}]}`},
		"osv-scanner":      {"osv-scanner", `{"results":[{"source":{"path":"` + big + `","type":"` + big + `"},"packages":[]}]}`},
		"checkov":          {"checkov", `{"check_type":"` + big + `","results":{"failed_checks":[{"check_id":"C","check_name":"n","file_path":"f","code_block":[[1,"` + big + `"]]}]}}`},
		"semgrep":          {"semgrep", `{"results":[{"check_id":"a","path":"b","extra":{"message":"m","metadata":{"cwe":"` + big + `","category":{"deep":{"deeper":"` + big + `"}}}}}],"errors":[],"paths":{}}`},
		"cyclonedx":        {"sbom", `{"bomFormat":"CycloneDX","serialNumber":"` + big + `","metadata":{"component":{"name":"` + big + `","version":"1","type":"` + big + `"}},"components":[{"bom-ref":"r","name":"a","purl":"pkg:npm/a@1"}],"vulnerabilities":[{"id":"V","affects":[{"ref":"r"}],"analysis":{"state":"` + big + `","detail":"` + big + `","response":["` + big + `"]}}]}`},
		"spdx":             {"sbom", `{"spdxVersion":"SPDX-2.3","name":"` + big + `","packages":[]}`},
		"sarif":            {"sarif", `{"version":"2.1.0","runs":[{"tool":{"driver":{"name":"x","version":"` + big + `","rules":[{"id":"r","properties":{"tags":["` + big + `"]}}]}},"results":[{"ruleId":"r","message":{"text":"m"}}]}]}`},
		"semgrep-sarif":    {"semgrep", `{"version":"2.1.0","runs":[{"tool":{"driver":{"name":"semgrep","rules":[{"id":"r","properties":{"cwe":"` + big + `","tags":["` + big + `"]}}]}},"results":[{"ruleId":"r","message":{"text":"m"}}]}]}`},
		"dependency-check": {"dependency-check", `{"reportSchema":"1.1","dependencies":[{"fileName":"a","filePath":"` + big + `","vulnerabilities":[{"name":"CVE-1","severity":"HIGH","source":"` + big + `"}]}]}`},
		"grype":            {"grype", `{"descriptor":{"name":"grype"},"matches":[{"vulnerability":{"id":"CVE-1","severity":"High","namespace":"` + big + `"},"artifact":{"name":"a","version":"1","purl":"pkg:npm/a@1","locations":[{"path":"` + big + `"}]}}]}`},
	}
	for name, d := range docs {
		t.Run(name, func(t *testing.T) {
			rep, err := scannerByName(t, d.scanner).Parse(testCtx(), []byte(d.doc))
			require.NoError(t, err)
			assertNestedFieldsBounded(t, rep)
		})
	}
}
