package parser_test

import (
	"bytes"
	"context"
	"runtime"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/minh-tg/specht/internal/parser"
	"github.com/minh-tg/specht/internal/scanner"
)

// perFindingBytes is what one parsed finding held in memory when the limit was
// sized (about 1.4 KB), and the figure deploy/README.md quotes.
const perFindingBytes = 1355

// minimalDoc is a report made of the smallest unit that still yields one finding
// or package, repeated until the document reaches size bytes.
type minimalDoc struct {
	name, scanner, head, unit, tail string
	// fixed is how many findings or packages the head adds, and per how many
	// each unit adds (zero means one).
	fixed, per int
}

// atTheLimit is how many units make a report that holds exactly limit items.
func (d minimalDoc) atTheLimit(limit int) int {
	return (limit - d.fixed) / max(d.per, 1)
}

func (d minimalDoc) build(size int) []byte {
	var b bytes.Buffer
	b.Grow(size + len(d.tail) + len(d.unit))
	b.WriteString(d.head)
	for i := 0; b.Len() < size; i++ {
		if i > 0 {
			b.WriteByte(',')
		}
		b.WriteString(d.unit)
	}
	b.WriteString(d.tail)
	return b.Bytes()
}

// units returns a document with exactly n repetitions of the unit.
func (d minimalDoc) units(n int) []byte {
	var b bytes.Buffer
	b.WriteString(d.head)
	for i := range n {
		if i > 0 {
			b.WriteByte(',')
		}
		b.WriteString(d.unit)
	}
	b.WriteString(d.tail)
	return b.Bytes()
}

var minimalDocs = []minimalDoc{
	{"trivy", "trivy", `{"ArtifactName":"a","Results":[{"Target":"t","Vulnerabilities":[`, `{}`, `]}]}`, 0, 0},
	{"grype", "grype", `{"descriptor":{"name":"grype"},"matches":[`, `{}`, `]}`, 0, 0},
	{"osv-scanner", "osv-scanner", `{"results":[{"source":{"path":"p"},"packages":[`, `{"vulnerabilities":[{}]}`, `]}]}`, 0, 2},
	{"checkov", "checkov", `{"check_type":"t","results":{"failed_checks":[`, `{}`, `]}}`, 0, 0},
	{"semgrep", "semgrep", `{"results":[`, `{"check_id":"a","path":"b"}`, `],"errors":[],"paths":{}}`, 0, 0},
	{"semgrep-sarif", "semgrep", `{"version":"2.1.0","runs":[{"tool":{"driver":{"name":"semgrep","rules":[{"id":"r"}]}},"results":[`, `{"ruleId":"r"}`, `]}]}`, 0, 0},
	{"sarif", "sarif", `{"version":"2.1.0","runs":[{"tool":{"driver":{"name":"x"}},"results":[`, `{"ruleId":"r"}`, `]}]}`, 0, 0},
	{"cyclonedx", "sbom", `{"bomFormat":"CycloneDX","components":[`, `{"bom-ref":"r","name":"a"}`, `]}`, 0, 0},
	{"cyclonedx-vulnerabilities", "sbom", `{"bomFormat":"CycloneDX","components":[{"bom-ref":"r","name":"a"}],"vulnerabilities":[`, `{"id":"v","affects":[{"ref":"r"}]}`, `]}`, 1, 1},
	{"spdx", "sbom", `{"spdxVersion":"SPDX-2.3","packages":[`, `{"name":"a","versionInfo":"1"}`, `]}`, 0, 0},
	{"dependency-check", "dependency-check", `{"reportSchema":"1","dependencies":[`, `{"vulnerabilities":[{}]}`, `]}`, 0, 1},
	{"gitleaks", "gitleaks", `[`, `{"RuleID":"r","File":"f"}`, `]`, 0, 0},
	{"tfsec", "tfsec", `{"results":[`, `{"rule_id":"r","long_id":"l","status":0}`, `]}`, 0, 0},
	{"nuclei", "nuclei", `[`, `{"template-id":"t","host":"h"}`, `]`, 0, 0},
}

func allocatedDuring(f func()) uint64 {
	runtime.GC()
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	f()
	runtime.ReadMemStats(&after)
	return after.TotalAlloc - before.TotalAlloc
}

// A 25 MiB upload of the smallest possible findings used to become about 8.7
// million findings and 11 GiB. At the default limit it is refused quickly and
// allocates no more than the limit's worth of findings.
func TestA25MiBReportOfMinimalFindingsIsRefusedEarly(t *testing.T) {
	const size = 25 << 20
	for _, d := range minimalDocs {
		t.Run(d.name, func(t *testing.T) {
			doc := d.build(size)
			s := scannerByName(t, d.scanner)

			var err error
			start := time.Now()
			allocated := allocatedDuring(func() { _, err = s.Parse(testCtx(), doc) })
			elapsed := time.Since(start)

			require.ErrorIs(t, err, scanner.ErrTooManyFindings)
			assert.Less(t, elapsed, 5*time.Second, "the refusal must not wait for the whole document to be converted")
			bound := uint64(3 * scanner.DefaultMaxFindings * perFindingBytes)
			assert.Less(t, allocated, bound, "allocated %d MiB, bound %d MiB", allocated>>20, bound>>20)
		})
	}
}

// A document one item past the finding limit is below every structural ceiling,
// so it is decoded and the loop count is what stops it. Parsing must stop at the
// limit with the typed error, and the memory it held must stay in proportion to
// the limit. A document three times past the limit is refused before decoding.
func TestParsersStopAtTheFindingLimit(t *testing.T) {
	const limit = 2000
	for _, d := range minimalDocs {
		t.Run(d.name, func(t *testing.T) {
			s := scannerByName(t, d.scanner)
			ctx := scanner.WithMaxFindings(testCtx(), limit)

			at := d.units(d.atTheLimit(limit))
			rep, err := s.Parse(ctx, at)
			require.NoError(t, err, "exactly the limit is allowed")
			require.NotNil(t, rep)

			over := d.units(d.atTheLimit(limit) + 1)
			var overErr error
			allocated := allocatedDuring(func() { _, overErr = s.Parse(ctx, over) })

			require.ErrorIs(t, overErr, scanner.ErrTooManyFindings)
			var tooMany *scanner.TooManyFindingsError
			require.ErrorAs(t, overErr, &tooMany)
			assert.Equal(t, limit, tooMany.Limit)
			bound := uint64(3*limit*perFindingBytes) + 16<<20
			assert.Less(t, allocated, bound, "allocated %d KiB, bound %d KiB", allocated>>10, bound>>10)

			_, farOver := s.Parse(ctx, d.units(d.atTheLimit(limit)*3))
			require.ErrorIs(t, farOver, scanner.ErrTooManyFindings)
		})
	}
}

// Packages count against the limit like findings.
func TestPackagesCountAgainstTheFindingLimit(t *testing.T) {
	ctx := scanner.WithMaxFindings(testCtx(), 3)
	doc := `{"bomFormat":"CycloneDX","components":[{"name":"a"},{"name":"b"},{"name":"c"},{"name":"d"}]}`
	_, err := scannerByName(t, "sbom").Parse(ctx, []byte(doc))
	require.ErrorIs(t, err, scanner.ErrTooManyFindings)
}

func testCtx() context.Context {
	return scanner.WithFingerprintKey(context.Background(), []byte("limits-test-key-0123456789abcdef"))
}

func scannerByName(t *testing.T, name string) scanner.Scanner {
	t.Helper()
	for _, s := range parser.Builtins() {
		if s.Descriptor().Name == name {
			return s
		}
	}
	t.Fatalf("no scanner %q", name)
	return nil
}
