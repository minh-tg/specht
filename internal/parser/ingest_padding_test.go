package parser_test

import (
	"bytes"
	"cmp"
	"fmt"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/minh-tg/specht/internal/scanner"
)

// paddingBound is the most a refused padding document may allocate while the
// parser looks at it. Refusal happens in a scan that allocates a few hundred
// bytes; the bound is generous because the runtime may allocate for its own
// reasons. Decoding the same documents used to allocate 1 to 11 GiB.
const paddingBound = 64 << 20

// paddedDoc is a document whose head opens a finding array (or a finding's
// field), unit is the padding repeated until the document is size bytes, and
// tail closes the structure.
type paddedDoc struct {
	name, scanner, head, unit, tail string
	// sep joins the units; the default is a comma.
	sep string
	// size is the document size in bytes; the default is paddingSize.
	size int
}

func (d paddedDoc) build(size int) []byte {
	sep := d.sep
	if sep == "" {
		sep = ","
	}
	var b bytes.Buffer
	b.Grow(size + len(d.head) + len(d.tail) + len(d.unit) + len(sep))
	b.WriteString(d.head)
	for i := 0; b.Len() < size; i++ {
		if i > 0 {
			b.WriteString(sep)
		}
		b.WriteString(d.unit)
	}
	b.WriteString(d.tail)
	return b.Bytes()
}

// esc spells r as a JSON unicode escape.
func esc(r rune) string { return fmt.Sprintf("%cu%04x", 92, r) }

const paddingSize = 25 << 20

// underTheObjectCeiling is a document size of 1.5 million empty objects, just
// under the 1.6 million objects the default limit allows, so only the
// array-element count can refuse it.
const underTheObjectCeiling = 3 * 1_500_000

var paddedDocs = []paddedDoc{
	// Elements that are not objects, in every parser's finding arrays.
	{name: "trivy null vulnerabilities", scanner: "trivy", head: `{"ArtifactName":"a","Results":[{"Target":"t","Vulnerabilities":[`, unit: `null`, tail: `]}]}`},
	{name: "trivy null results", scanner: "trivy", head: `{"ArtifactName":"a","Results":[{"Target":"t"},`, unit: `null`, tail: `]}`},
	{name: "trivy null packages", scanner: "trivy", head: `{"ArtifactName":"a","Results":[{"Target":"t","Packages":[`, unit: `null`, tail: `]}]}`},
	{name: "trivy string vulnerabilities", scanner: "trivy", head: `{"ArtifactName":"a","Results":[{"Target":"t","Vulnerabilities":[`, unit: `""`, tail: `]}]}`},
	{name: "trivy number vulnerabilities", scanner: "trivy", head: `{"ArtifactName":"a","Results":[{"Target":"t","Vulnerabilities":[`, unit: `0`, tail: `]}]}`},
	{name: "trivy array vulnerabilities", scanner: "trivy", head: `{"ArtifactName":"a","Results":[{"Target":"t","Vulnerabilities":[`, unit: `[]`, tail: `]}]}`},
	{name: "sarif null results", scanner: "sarif", head: `{"version":"2.1.0","runs":[{"tool":{"driver":{"name":"x"}},"results":[`, unit: `null`, tail: `]}]}`},
	{name: "sarif null runs", scanner: "sarif", head: `{"version":"2.1.0","runs":[{"tool":{"driver":{"name":"x"}},"results":[]},`, unit: `null`, tail: `]}`},
	{name: "sarif number results", scanner: "sarif", head: `{"version":"2.1.0","runs":[{"tool":{"driver":{"name":"x"}},"results":[`, unit: `0`, tail: `]}]}`},
	{name: "semgrep null results", scanner: "semgrep", head: `{"results":[`, unit: `null`, tail: `],"errors":[],"paths":{}}`},
	{name: "cyclonedx null components", scanner: "sbom", head: `{"bomFormat":"CycloneDX","components":[{"bom-ref":"r","name":"a"},`, unit: `null`, tail: `]}`},
	{name: "cyclonedx string components", scanner: "sbom", head: `{"bomFormat":"CycloneDX","components":[{"bom-ref":"r","name":"a"},`, unit: `""`, tail: `]}`},
	{name: "spdx null packages", scanner: "sbom", head: `{"spdxVersion":"SPDX-2.3","packages":[{"name":"a","versionInfo":"1"},`, unit: `null`, tail: `]}`},
	{name: "grype null matches", scanner: "grype", head: `{"descriptor":{"name":"grype"},"matches":[`, unit: `null`, tail: `]}`},
	{name: "osv null packages", scanner: "osv-scanner", head: `{"results":[{"source":{"path":"p"},"packages":[`, unit: `null`, tail: `]}]}`},
	{name: "osv null results", scanner: "osv-scanner", head: `{"results":[{"source":{"path":"p"},"packages":[]},`, unit: `null`, tail: `]}`},
	{name: "dependency-check null dependencies", scanner: "dependency-check", head: `{"reportSchema":"1","dependencies":[`, unit: `null`, tail: `]}`},
	{name: "checkov null failed checks", scanner: "checkov", head: `{"check_type":"t","results":{"failed_checks":[`, unit: `null`, tail: `]}}`},
	{name: "tfsec null results", scanner: "tfsec", head: `{"results":[`, unit: `null`, tail: `]}`},
	{name: "gitleaks null root elements", scanner: "gitleaks", head: `[{"RuleID":"r","File":"f"},`, unit: `null`, tail: `]`},
	{name: "gitleaks null lines", scanner: "gitleaks", head: `{"RuleID":"r","File":"f"}` + "\n", unit: `null`, sep: "\n"},
	{name: "nuclei null root elements", scanner: "nuclei", head: `[{"template-id":"t","host":"h"},`, unit: `null`, tail: `]`},
	{name: "nuclei null lines", scanner: "nuclei", head: `{"template-id":"t","host":"h"}` + "\n", unit: `null`, sep: "\n"},

	// A finding array under a key that encoding/json still maps onto the field.
	{name: "trivy lowercase key", scanner: "trivy", head: `{"ArtifactName":"a","Results":[{"Target":"t","vulnerabilities":[`, unit: `{}`, tail: `]}]}`, size: underTheObjectCeiling},
	{name: "trivy escaped key", scanner: "trivy", head: `{"ArtifactName":"a","Results":[{"Target":"t","Vulnerabilit` + esc('i') + `es":[`, unit: `{}`, tail: `]}]}`, size: underTheObjectCeiling},
	{name: "trivy escaped results key", scanner: "trivy", head: `{"ArtifactName":"a","R` + esc('e') + `sults":[{"Target":"t"},`, unit: `null`, tail: `]}`},
	{name: "semgrep escaped results key", scanner: "semgrep", head: `{"r` + esc('e') + `sults":[`, unit: `{}`, tail: `],"errors":[],"paths":{}}`, size: underTheObjectCeiling},
	{name: "sarif upper-case key", scanner: "sarif", head: `{"version":"2.1.0","runs":[{"tool":{"driver":{"name":"x"}},"RESULTS":[`, unit: `{}`, tail: `]}]}`, size: underTheObjectCeiling},
	{name: "cyclonedx capitalised key", scanner: "sbom", head: `{"bomFormat":"CycloneDX","Components":[`, unit: `{}`, tail: `]}`, size: underTheObjectCeiling},
	{name: "grype upper-case key", scanner: "grype", head: `{"descriptor":{"name":"grype"},"MATCHES":[`, unit: `{}`, tail: `]}`, size: underTheObjectCeiling},
	{name: "dependency-check capitalised key", scanner: "dependency-check", head: `{"reportSchema":"1","Dependencies":[`, unit: `null`, tail: `]}`},

	// Scalar padding inside one finding's fields: no finding array grows, the
	// total value count is what stops it.
	{name: "trivy CweIDs of strings", scanner: "trivy", head: `{"ArtifactName":"a","Results":[{"Target":"t","Type":"npm","Vulnerabilities":[{"VulnerabilityID":"CVE-2024-1","PkgName":"p","InstalledVersion":"1","Severity":"HIGH","CweIDs":[`, unit: `""`, tail: `]}]}]}`},
	{name: "gitleaks Tags of strings", scanner: "gitleaks", head: `[{"RuleID":"r","File":"f","StartLine":1,"Secret":"s","Tags":[`, unit: `""`, tail: `]}]`},
	{name: "semgrep metadata array of numbers", scanner: "semgrep", head: `{"results":[{"check_id":"c","path":"p","start":{"line":1},"end":{"line":1},"extra":{"message":"m","severity":"ERROR","metadata":{"x":[`, unit: `0`, tail: `]}}}],"errors":[]}`},
	{name: "semgrep metadata array of arrays", scanner: "semgrep", head: `{"results":[{"check_id":"c","path":"p","start":{"line":1},"end":{"line":1},"extra":{"message":"m","severity":"ERROR","metadata":{"x":[`, unit: `[]`, tail: `]}}}],"errors":[]}`},
	{name: "sarif notifications of numbers", scanner: "sarif", head: `{"version":"2.1.0","runs":[{"tool":{"driver":{"name":"x","notifications":[`, unit: `0`, tail: `]}},"results":[{"ruleId":"r","message":{"text":"m"},"locations":[{"physicalLocation":{"artifactLocation":{"uri":"a"},"region":{"startLine":1}}}]}]}]}`},
	{name: "sarif rule properties array of numbers", scanner: "sarif", head: `{"version":"2.1.0","runs":[{"tool":{"driver":{"name":"x","rules":[{"id":"r","properties":{"x":[`, unit: `0`, tail: `]}}]}},"results":[{"ruleId":"r","message":{"text":"m"},"locations":[{"physicalLocation":{"artifactLocation":{"uri":"a"},"region":{"startLine":1}}}]}]}]}`},
}

// A 25 MiB document of padding that is not a finding is refused with
// too_many_findings before any decoder allocates for it. Before the scan
// counted every element and value, each of these was accepted or decoded in
// full: 0.8 to 6.6 GiB of heap per request.
func TestPaddingDocumentsAreRefusedBeforeDecoding(t *testing.T) {
	for _, d := range paddedDocs {
		t.Run(d.name, func(t *testing.T) {
			size := cmp.Or(d.size, paddingSize)
			doc := d.build(size)
			require.GreaterOrEqual(t, len(doc), size)
			s := scannerByName(t, d.scanner)

			var err error
			allocated := allocatedDuring(func() { _, err = s.Parse(testCtx(), doc) })

			require.ErrorIs(t, err, scanner.ErrTooManyFindings)
			assert.Less(t, allocated, uint64(paddingBound), "allocated %d MiB", allocated>>20)

			// The pre-parse check that ingest runs, which knows no array keys,
			// refuses the padding that sits inside one finding by value count.
			if strings.Contains(d.name, "of ") || strings.Contains(d.name, "array of") || strings.Contains(d.name, "properties") {
				assert.ErrorIs(t, scanner.CheckDocument(doc, scanner.DefaultMaxFindings), scanner.ErrTooManyFindings)
			}
		})
	}
}

// A document that is genuinely small keeps working: a few null entries are
// still accepted, as they always were.
func TestAFewNullElementsAreStillAccepted(t *testing.T) {
	cases := []struct{ scanner, doc string }{
		{"trivy", `{"ArtifactName":"a","Results":[null,{"Target":"t","Vulnerabilities":[null,{"VulnerabilityID":"CVE-1","PkgName":"p","Severity":"HIGH"}]}]}`},
		{"gitleaks", `[{"RuleID":"r","File":"f","Secret":"s"},null]`},
		{"nuclei", `[{"template-id":"t","host":"h","info":{"name":"n","severity":"high"}},null]`},
		{"semgrep", `{"results":[null,{"check_id":"c","path":"p","start":{"line":1},"end":{"line":1},"extra":{"message":"m","severity":"ERROR"}}],"errors":[]}`},
	}
	for _, c := range cases {
		t.Run(c.scanner, func(t *testing.T) {
			rep, err := scannerByName(t, c.scanner).Parse(testCtx(), []byte(c.doc))
			require.NoError(t, err)
			assert.NotEmpty(t, rep.Findings)
		})
	}
}
