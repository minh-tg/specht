package sbom_test

import (
	"context"
	"encoding/json"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/minh-tg/specht/internal/domain"
	"github.com/minh-tg/specht/internal/parser/sbom"
	"github.com/minh-tg/specht/internal/scanner"
)

func parseDoc(t *testing.T, doc string) *domain.NormalizedReport {
	t.Helper()
	nr, err := sbom.NewScanner().Parse(context.Background(), []byte(doc))
	require.NoError(t, err)
	return nr
}

func TestGrypeCycloneDXVulnerabilitiesBecomeFindings(t *testing.T) {
	data, err := os.ReadFile("testdata/grype-cyclonedx.json")
	require.NoError(t, err)
	nr, err := sbom.NewScanner().Parse(context.Background(), data)
	require.NoError(t, err)

	require.Len(t, nr.Findings, 3, "one finding per vulnerability and affected component")
	require.Len(t, nr.Packages, 3, "the component inventory is still kept")

	django := nr.Findings[0]
	assert.Equal(t, "sca", django.FindingKind)
	assert.Equal(t, "GHSA-hmr4-m2h5-33qx in django", django.Title)
	assert.Equal(t, domain.SeverityCritical, django.Severity)
	assert.Equal(t, "SQL injection in Django", django.Description)
	assert.Equal(t, "django@2.2.0", django.Resource)
	assert.Equal(t, string(domain.SCAFingerprint("GHSA-hmr4-m2h5-33qx", "pkg:pypi/django@2.2.0")), django.Fingerprint)

	require.NotNil(t, django.CVSS)
	assert.Equal(t, "3.1", django.CVSS.Version)
	assert.Equal(t, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", django.CVSS.Vector)
	assert.InDelta(t, 9.8, django.CVSS.Score, 0.001)
}

func TestACycloneDXWithVulnerabilitiesIsNotAProofOfAbsence(t *testing.T) {
	data, err := os.ReadFile("testdata/grype-cyclonedx.json")
	require.NoError(t, err)
	withVulns, err := sbom.NewScanner().Parse(context.Background(), data)
	require.NoError(t, err)
	assert.Equal(t, domain.CompletenessUnknown, withVulns.Completeness,
		"the producer's analysis is unknown, so a later report cannot close its findings")
	assert.Equal(t, "included", withVulns.ScanScope.Ext["sbom_vulnerabilities"])

	plain := parseDoc(t, `{"bomFormat":"CycloneDX","specVersion":"1.5","components":[{"name":"a","version":"1","purl":"pkg:npm/a@1"}]}`)
	assert.Equal(t, domain.CompletenessComplete, plain.Completeness, "a plain SBOM is unchanged")
	assert.NotContains(t, plain.ScanScope.Ext, "sbom_vulnerabilities")
}

func TestARatingWithoutASeverityDoesNotLowerTheSeverity(t *testing.T) {
	nr := parseDoc(t, `{"bomFormat":"CycloneDX","components":[{"bom-ref":"c1","name":"lib","version":"1.0","purl":"pkg:npm/lib@1.0"}],
	"vulnerabilities":[{"id":"CVE-2024-0001","affects":[{"ref":"c1"}],"ratings":[
		{"score":5.0,"severity":"medium","method":"CVSSv31","vector":"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L"},
		{"score":9.1,"severity":"critical","method":"CVSSv4","vector":"CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"},
		{"source":{"name":"FIRST","url":"https://www.first.org/epss/"},"score":0.7,"method":"other"}]}]}`)
	require.Len(t, nr.Findings, 1)
	f := nr.Findings[0]
	assert.Equal(t, domain.SeverityCritical, f.Severity, "the highest rated severity wins; the EPSS entry has none")
	require.NotNil(t, f.CVSS)
	assert.Equal(t, "4.0", f.CVSS.Version, "the highest scoring vector is kept")
	assert.InDelta(t, 9.1, f.CVSS.Score, 0.001)
}

func TestVulnerabilityAffectingTwoComponentsGivesTwoFindings(t *testing.T) {
	nr := parseDoc(t, `{"bomFormat":"CycloneDX","components":[
		{"bom-ref":"a","name":"x","version":"1","purl":"pkg:npm/x@1"},{"bom-ref":"b","name":"y","version":"2","purl":"pkg:npm/y@2"}],
	"vulnerabilities":[{"id":"CVE-1","ratings":[{"severity":"high"}],"affects":[{"ref":"a"},{"ref":"b"}]}]}`)
	require.Len(t, nr.Findings, 2)
	assert.NotEqual(t, nr.Findings[0].Fingerprint, nr.Findings[1].Fingerprint)
}

func TestNestedComponentsAreFoundAndListed(t *testing.T) {
	nr := parseDoc(t, `{"bomFormat":"CycloneDX","components":[
		{"bom-ref":"outer","name":"app","version":"1","purl":"pkg:npm/app@1","components":[
			{"bom-ref":"inner","name":"dep","version":"3","purl":"pkg:npm/dep@3"}]}],
	"vulnerabilities":[{"id":"CVE-2","ratings":[{"severity":"low"}],"affects":[{"ref":"inner"}]}]}`)
	require.Len(t, nr.Findings, 1, "a vulnerability can name a component inside another")
	assert.Equal(t, "dep@3", nr.Findings[0].Resource)
	assert.Len(t, nr.Packages, 2, "nested components belong to the inventory")
}

func TestAComponentWithoutAPurlStillGetsADistinctIdentity(t *testing.T) {
	nr := parseDoc(t, `{"bomFormat":"CycloneDX","components":[
		{"bom-ref":"a","name":"one","version":"1"},{"bom-ref":"b","name":"two","version":"1"}],
	"vulnerabilities":[{"id":"CVE-3","ratings":[{"severity":"high"}],"affects":[{"ref":"a"},{"ref":"b"}]}]}`)
	require.Len(t, nr.Findings, 2)
	assert.NotEqual(t, nr.Findings[0].Fingerprint, nr.Findings[1].Fingerprint, "two packages do not collapse into one finding")
}

func TestUnresolvedReferencesAreCountedNotSilentlyDropped(t *testing.T) {
	nr := parseDoc(t, `{"bomFormat":"CycloneDX","components":[{"bom-ref":"a","name":"x","version":"1","purl":"pkg:npm/x@1"}],
	"vulnerabilities":[{"id":"CVE-4","ratings":[{"severity":"high"}],"affects":[{"ref":"a"},{"ref":"missing"}]},
	                   {"id":"CVE-5","ratings":[{"severity":"low"}],"affects":[{"ref":"pkg:npm/z@9"}]}]}`)
	require.Len(t, nr.Findings, 2, "a reference that is itself a package URL needs no component")
	assert.Equal(t, "1", nr.ScanScope.Ext["sbom_unresolved_references"])
}

func TestTheProducersAnalysisIsKeptForLater(t *testing.T) {
	nr := parseDoc(t, `{"bomFormat":"CycloneDX","components":[{"bom-ref":"a","name":"x","version":"1","purl":"pkg:npm/x@1"}],
	"vulnerabilities":[{"id":"CVE-6","ratings":[{"severity":"high"}],"affects":[{"ref":"a"}],
	"analysis":{"state":"not_affected","justification":"code_not_reachable","detail":"never called"}}]}`)
	require.Len(t, nr.Findings, 1)
	analysis, ok := nr.Findings[0].Extensions["cyclonedx_analysis"].(map[string]any)
	require.True(t, ok)
	assert.Equal(t, "not_affected", analysis["state"])
	assert.Equal(t, "code_not_reachable", analysis["justification"])
	assert.Equal(t, domain.SeverityHigh, nr.Findings[0].Severity, "the state is recorded, not acted on")
}

func TestRecommendationBecomesTheFix(t *testing.T) {
	nr := parseDoc(t, `{"bomFormat":"CycloneDX","components":[{"bom-ref":"a","name":"x","version":"1","purl":"pkg:npm/x@1"}],
	"vulnerabilities":[{"id":"CVE-7","ratings":[{"severity":"high"}],"affects":[{"ref":"a"}],"recommendation":"Upgrade to 1.2.3"}]}`)
	require.NotNil(t, nr.Findings[0].Fix)
	assert.Equal(t, "Upgrade to 1.2.3", nr.Findings[0].Fix.Summary)
}

func TestARecommendationIsNotAFixedVersion(t *testing.T) {
	nr := parseDoc(t, `{"bomFormat":"CycloneDX","components":[{"bom-ref":"a","name":"lodash","version":"4.17.20","purl":"pkg:npm/lodash@4.17.20"}],
	"vulnerabilities":[{"id":"CVE-2021-23337","ratings":[{"severity":"high"}],"affects":[{"ref":"a"}],"recommendation":"Upgrade lodash to version 4.17.21 or later."}]}`)
	require.Len(t, nr.Findings, 1)
	for _, d := range nr.Findings[0].Dimensions {
		assert.NotEqual(t, domain.DimFixedVersion, d.Key,
			"free text in fixed_version becomes the version an upgrade proposal writes into the manifest")
	}
	require.NotNil(t, nr.Findings[0].Fix)
	assert.Equal(t, "Upgrade lodash to version 4.17.21 or later.", nr.Findings[0].Fix.Summary)
}

func TestACleanCycloneDXWithAnEmptyVulnerabilityListIsStillSBOM(t *testing.T) {
	nr := parseDoc(t, `{"bomFormat":"CycloneDX","components":[{"name":"x","version":"1","purl":"pkg:npm/x@1"}],"vulnerabilities":[]}`)
	assert.Empty(t, nr.Findings)
	assert.Equal(t, domain.CompletenessUnknown, nr.Completeness, "the file says it was analysed, so it is not a bare inventory")
}

func TestAnUnreadableVulnerabilityListIsMalformed(t *testing.T) {
	_, err := sbom.NewScanner().Parse(context.Background(), []byte(`{"bomFormat":"CycloneDX","vulnerabilities":"oops"}`))
	require.ErrorIs(t, err, scanner.ErrMalformedReport)
}

func TestCVSSAllKeepsEveryRatingWithAVector(t *testing.T) {
	nr := parseDoc(t, `{"bomFormat":"CycloneDX","components":[{"bom-ref":"c1","name":"lib","version":"1.0","purl":"pkg:npm/lib@1.0"}],
	"vulnerabilities":[{"id":"CVE-2024-0001","affects":[{"ref":"c1"}],"ratings":[
		{"source":{"name":"NVD"},"score":9.8,"severity":"critical","method":"CVSSv3","vector":"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"},
		{"source":{"name":"NVD"},"score":7.5,"severity":"high","method":"CVSSv2","vector":"AV:N/AC:L/Au:N/C:P/I:P/A:P"},
		{"source":{"name":"GitHub"},"score":9.1,"severity":"critical","method":"CVSSv4","vector":"CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"},
		{"source":{"name":"FIRST","url":"https://www.first.org/epss/"},"score":0.7,"method":"other"},
		{"score":5.0,"severity":"medium","method":"CVSSv31","vector":"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L"}]}]}`)
	require.Len(t, nr.Findings, 1)
	all := nr.Findings[0].CVSSAll

	require.Len(t, all, 4, "the EPSS rating has no vector, so it is not a CVSS record")
	assert.Equal(t, domain.CVSSRecord{Version: "3.0", Vector: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", Score: 9.8, Source: "nvd"}, all[0])
	assert.Equal(t, domain.CVSSRecord{Version: "2.0", Vector: "CVSS:2.0/AV:N/AC:L/Au:N/C:P/I:P/A:P", Score: 7.5, Source: "nvd"}, all[1], "a bare v2 vector gains its prefix")
	assert.Equal(t, "4.0", all[2].Version)
	assert.Equal(t, "github", all[2].Source)
	assert.Equal(t, domain.CVSSRecord{Version: "3.1", Vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L", Score: 5}, all[3], "a rating that names no source has an empty one")

	// The preferred vector and the occurrence score keep their choice.
	require.NotNil(t, nr.Findings[0].CVSS)
	assert.Equal(t, "3.0", nr.Findings[0].CVSS.Version)
	assert.InDelta(t, 9.8, nr.Findings[0].CVSS.Score, 0.001)
}

func TestCVSSAllIsEmptyWithoutVectors(t *testing.T) {
	nr := parseDoc(t, `{"bomFormat":"CycloneDX","components":[{"bom-ref":"c1","name":"lib","version":"1.0","purl":"pkg:npm/lib@1.0"}],
	"vulnerabilities":[{"id":"CVE-2024-0002","affects":[{"ref":"c1"}],"ratings":[{"severity":"high","score":7.1}]}]}`)
	require.Len(t, nr.Findings, 1)
	assert.Empty(t, nr.Findings[0].CVSSAll)
}

// qualified rewrites the component purls of the Grype fixture the way Syft and
// Trivy write them: a package-id, build qualifiers and a subpath.
func qualified(t *testing.T, suffix string) []byte {
	t.Helper()
	data, err := os.ReadFile("testdata/grype-cyclonedx.json")
	require.NoError(t, err)
	var doc map[string]any
	require.NoError(t, json.Unmarshal(data, &doc))
	for _, c := range doc["components"].([]any) {
		component := c.(map[string]any)
		component["purl"] = component["purl"].(string) + suffix
	}
	out, err := json.Marshal(doc)
	require.NoError(t, err)
	return out
}

func TestVulnerabilityIdentityIgnoresPURLQualifiersAndSubpath(t *testing.T) {
	plain, err := os.ReadFile("testdata/grype-cyclonedx.json")
	require.NoError(t, err)
	want, err := sbom.NewScanner().Parse(context.Background(), plain)
	require.NoError(t, err)
	require.Len(t, want.Findings, 3)

	for name, suffix := range map[string]string{
		"package-id":         "?package-id=0123456789abcdef",
		"jar type":           "?type=jar",
		"arch and distro":    "?arch=amd64&distro=debian-12",
		"classifier":         "?classifier=sources&type=jar",
		"subpath":            "#src/main",
		"qualifiers+subpath": "?arch=arm64#pkg",
	} {
		t.Run(name, func(t *testing.T) {
			got, err := sbom.NewScanner().Parse(context.Background(), qualified(t, suffix))
			require.NoError(t, err)
			require.Len(t, got.Findings, len(want.Findings))
			for i, f := range got.Findings {
				assert.Equal(t, want.Findings[i].Fingerprint, f.Fingerprint,
					"the same package exported with %s is the same finding", suffix)
				assert.Equal(t, want.Findings[i].Dimensions, f.Dimensions)
				assert.Equal(t, want.Findings[i].Extensions["purl"], f.Extensions["purl"])
			}
			for i, p := range got.Packages {
				assert.Equal(t, want.Packages[i].PURL, p.PURL, "the inventory and the findings share one purl")
			}
		})
	}
}

func TestAReferenceThatIsAPURLIsNormalizedToo(t *testing.T) {
	a := parseDoc(t, `{"bomFormat":"CycloneDX","components":[],
		"vulnerabilities":[{"id":"CVE-9","ratings":[{"severity":"high"}],"affects":[{"ref":"pkg:maven/org.acme/lib@1.0?type=jar&classifier=sources"}]}]}`)
	b := parseDoc(t, `{"bomFormat":"CycloneDX","components":[],
		"vulnerabilities":[{"id":"CVE-9","ratings":[{"severity":"high"}],"affects":[{"ref":"pkg:maven/org.acme/lib@1.0"}]}]}`)
	require.Len(t, a.Findings, 1)
	assert.Equal(t, "CVE-9:pkg:maven/org.acme/lib@1.0", a.Findings[0].Fingerprint)
	assert.Equal(t, b.Findings[0].Fingerprint, a.Findings[0].Fingerprint)
}

func TestTheScannerSaysItsIdentitiesChanged(t *testing.T) {
	assert.EqualValues(t, 2, sbom.NewScanner().Descriptor().FingerprintVersion)
	assert.EqualValues(t, 2, parseDoc(t, `{"bomFormat":"CycloneDX","components":[]}`).FingerprintVersion)
	assert.EqualValues(t, 2, parseDoc(t, `{"spdxVersion":"SPDX-2.3","packages":[]}`).FingerprintVersion)
}
