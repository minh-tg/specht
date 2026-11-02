package parser_test

// The ingest admission charges 64 bytes of memory per byte of the report. These
// tests build the densest report each shape allows that scanner.CheckIngestDocument
// still accepts, run the steps IngestReport runs on it in the same order, and
// check the peak heap stays under that charge. Set INGEST_MEMORY_MIB (for
// example 1,5,10) for the heavy form; the default run uses one small size.

import (
	"bytes"
	"os"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/minh-tg/specht/internal/parser"
	"github.com/minh-tg/specht/internal/scanner"
)

// ingestBytesCharged is what internal/server charges per byte of the report.
const ingestBytesCharged = 64

// ingestPipeline runs the steps IngestReport runs on raw_data, keeping every
// result alive the way the use case does (the body, the parsed report and the
// redacted copy are all live when redaction returns).
func ingestPipeline(t *testing.T, reg *scanner.Registry, name string, data []byte) error {
	t.Helper()
	sc, _ := reg.Get(name)
	if err := scanner.CheckIngestDocument(data, scanner.DefaultMaxFindings, findingKeys(sc)...); err != nil {
		return err
	}
	data, err := scanner.SanitizeNUL(data)
	if err != nil {
		return err
	}
	if err := reg.CheckFormat(name, data); err != nil {
		return err
	}
	ctx := scanner.WithMaxFindings(testCtx(), scanner.DefaultMaxFindings)
	nr, err := sc.Parse(ctx, data)
	if err != nil {
		return err
	}
	var redacted []byte
	if r, ok := sc.(scanner.Redactor); ok {
		redacted, _ = r.RedactRaw(data)
	}
	runtime.KeepAlive(nr)
	runtime.KeepAlive(redacted)
	runtime.KeepAlive(data)
	return nil
}

// findingKeys is what the ingest passes to the document check for sc.
func findingKeys(sc scanner.Scanner) []string {
	if fa, ok := sc.(scanner.FindingArrayer); ok {
		return fa.FindingArrays()
	}
	return nil
}

// peakDuring returns the highest HeapInuse seen while f runs.
func peakDuring(f func()) uint64 {
	var peak atomic.Uint64
	stop := make(chan struct{})
	done := make(chan struct{})
	go func() {
		defer close(done)
		var m runtime.MemStats
		for {
			runtime.ReadMemStats(&m)
			if m.HeapInuse > peak.Load() {
				peak.Store(m.HeapInuse)
			}
			select {
			case <-stop:
				return
			case <-time.After(time.Millisecond):
			}
		}
	}()
	f()
	close(stop)
	<-done
	return peak.Load()
}

// memoryShape is a report whose body repeats one unit between a head and a
// tail. unit takes the length of a padding string it carries in its innermost
// value, so the shape can be made as dense as the document check allows.
type memoryShape struct {
	name, scanner string
	head, tail    string
	unit          func(pad string) string
}

// maxShapeUnits keeps a shape of findings under the default finding limit, so
// the finding count is never what refuses it (a unit of the OSV shape is two).
const maxShapeUnits = 45000

func (s memoryShape) build(size int, pad string) []byte {
	unit := s.unit(pad)
	var b bytes.Buffer
	b.Grow(size + len(unit) + len(s.tail) + len(s.head))
	b.WriteString(s.head)
	for i := 0; b.Len()+len(unit)+len(s.tail) < size && i < maxShapeUnits; i++ {
		if i > 0 {
			b.WriteByte(',')
		}
		b.WriteString(unit)
	}
	b.WriteString(s.tail)
	return b.Bytes()
}

// densest builds the shape at size with the shortest padding the document check
// accepts. Acceptance only gets easier as the padding grows, so it bisects.
func (s memoryShape) densest(keys []string, size int) []byte {
	accepts := func(n int) bool {
		return scanner.CheckIngestDocument(s.build(size, strings.Repeat("x", n)), scanner.DefaultMaxFindings, keys...) == nil
	}
	lo, hi := 0, 4096
	if accepts(0) {
		return s.build(size, "")
	}
	for hi-lo > 1 {
		mid := (lo + hi) / 2
		if accepts(mid) {
			hi = mid
		} else {
			lo = mid
		}
	}
	return s.build(size, strings.Repeat("x", hi))
}

// chain nests n single-key objects around v: {"a":{"a":...v...}}.
func chain(n int, v string) string {
	return strings.Repeat(`{"a":`, n) + v + strings.Repeat("}", n)
}

// alt alternates n objects and arrays around v.
func alt(n int, v string) string {
	return strings.Repeat(`{"n":[`, n) + v + strings.Repeat("]}", n)
}

func quoted(pad string) string { return `"` + pad + `"` }

var shapeCounter atomic.Int64

// uid is a short id that differs on every call, so repeated findings are not
// equal and a parser has no duplicate to drop.
func uid() string { return strconv.FormatInt(shapeCounter.Add(1), 36) }

// findingShapes are reports of minimal findings: each element of the finding
// array is a finding, package or result with the fewest fields its parser
// needs. They cost little JSON per element and a parsed finding each.
func findingShapes() []memoryShape {
	trivyVulns := `{"SchemaVersion":2,"ArtifactName":"a","ArtifactType":"container_image","Results":[{"Target":"t","Class":"os-pkgs","Type":"alpine","Vulnerabilities":[`
	return []memoryShape{
		{"trivy id-only findings", "trivy", trivyVulns, `]}]}`, func(p string) string {
			return `{"VulnerabilityID":"` + uid() + p + `"}`
		}},
		{"trivy two-field findings", "trivy", trivyVulns, `]}]}`, func(p string) string {
			return `{"VulnerabilityID":"` + uid() + p + `","PkgName":"p"}`
		}},
		{"trivy four-field findings", "trivy", trivyVulns, `]}]}`, func(p string) string {
			return `{"VulnerabilityID":"` + uid() + p + `","PkgName":"p","InstalledVersion":"1","Severity":"HIGH"}`
		}},
		{"sarif minimal results", "sarif", `{"version":"2.1.0","runs":[{"tool":{"driver":{"name":"x","rules":[{"id":"r"}]}},"results":[`, `]}]}`, func(p string) string {
			return `{"ruleId":"r","message":{"text":"` + uid() + p + `"}}`
		}},
		{"checkov minimal failed checks", "checkov", `{"check_type":"terraform","results":{"failed_checks":[`, `]},"summary":{}}`, func(p string) string {
			return `{"check_id":"CKV_` + uid() + p + `","file_path":"/m.tf","resource":"r"}`
		}},
		{"semgrep minimal results", "semgrep", `{"errors":[],"paths":{},"results":[`, `]}`, func(p string) string {
			return `{"check_id":"c` + uid() + p + `","path":"p","start":{"line":1},"end":{"line":1},"extra":{"message":"m","severity":"ERROR"}}`
		}},
		{"grype minimal matches", "grype", `{"descriptor":{"name":"grype","version":"0.80.0"},"source":{"type":"image"},"matches":[`, `]}`, func(p string) string {
			return `{"vulnerability":{"id":"C` + uid() + p + `","severity":"High"},"artifact":{"name":"p","version":"1","type":"apk"}}`
		}},
		{"cyclonedx minimal components", "sbom", `{"bomFormat":"CycloneDX","specVersion":"1.5","components":[`, `]}`, func(p string) string {
			return `{"type":"library","name":"a` + uid() + p + `","version":"1"}`
		}},
		{"osv minimal packages", "osv-scanner", `{"results":[{"source":{"path":"p","type":"lockfile"},"packages":[`, `]}]}`, func(p string) string {
			return `{"package":{"name":"a` + uid() + p + `","version":"1","ecosystem":"npm"},"vulnerabilities":[{"id":"G` + uid() + `"}]}`
		}},
	}
}

func allMemoryShapes() []memoryShape { return append(memoryShapes(), findingShapes()...) }

func memoryShapes() []memoryShape {
	trivyHead := `{"SchemaVersion":2,"ArtifactName":"a","ArtifactType":"container_image","Results":[{"Target":"t","Class":"os-pkgs","Type":"alpine","Vulnerabilities":[{"VulnerabilityID":"CVE-2024-1","PkgName":"p","InstalledVersion":"1","Severity":"HIGH"}]}],"X":[`
	sarifHead := `{"version":"2.1.0","runs":[{"tool":{"driver":{"name":"x","rules":[{"id":"r"}]}},"results":[`
	semgrepHead := `{"errors":[],"paths":{},"results":[`
	checkovHead := `{"check_type":"terraform","results":{"failed_checks":[{"check_id":"CKV_1","check_name":"n","file_path":"/m.tf","file_line_range":[1,2],"resource":"r"}]},"summary":{},"X":[`
	sarifResult := func(props string) string {
		return `{"ruleId":"r","message":{"text":"m"},"properties":{"x":` + props + `}}`
	}
	return []memoryShape{
		{"trivy one-key objects", "trivy", trivyHead, `]}`, func(p string) string { return `{"a":` + quoted(p) + `}` }},
		{"trivy empty objects", "trivy", trivyHead, `]}`, func(p string) string { return `{"a":{},"b":` + quoted(p) + `}` }},
		{"trivy object chain 60", "trivy", trivyHead, `]}`, func(p string) string { return chain(60, quoted(p)) }},
		{"trivy alt object-array 30", "trivy", trivyHead, `]}`, func(p string) string { return alt(30, quoted(p)) }},
		{"trivy nested arrays 60", "trivy", trivyHead, `]}`, func(p string) string {
			return strings.Repeat("[", 60) + quoted(p) + strings.Repeat("]", 60)
		}},
		{"trivy wide object", "trivy", trivyHead, `]}`, func(p string) string {
			return `{"a":0,"b":0,"c":0,"d":0,"e":0,"f":0,"g":0,"h":0,"i":` + quoted(p) + `}`
		}},
		{"trivy number list", "trivy", trivyHead, `]}`, func(p string) string {
			return `[0,1,2,3,4,5,6,7,8,9,0,1,2,3,4,5,6,7,8,9,` + quoted(p) + `]`
		}},
		{"checkov one-key objects", "checkov", checkovHead, `]}`, func(p string) string { return `{"a":` + quoted(p) + `}` }},
		{"checkov object chain 60", "checkov", checkovHead, `]}`, func(p string) string { return chain(60, quoted(p)) }},
		{"semgrep metadata chain 58", "semgrep", semgrepHead, `]}`, func(p string) string {
			return `{"check_id":"c","path":"p","start":{"line":1},"end":{"line":1},"extra":{"message":"m","severity":"ERROR","metadata":{"x":` + chain(56, quoted(p)) + `}}}`
		}},
		{"sarif properties chain 58", "sarif", sarifHead, `]}]}`, func(p string) string { return sarifResult(chain(56, quoted(p))) }},
		{"sarif properties alt 28", "sarif", sarifHead, `]}]}`, func(p string) string { return sarifResult(alt(28, quoted(p))) }},
		{"sarif properties one-key list", "sarif", sarifHead, `]}]}`, func(p string) string {
			return sarifResult(`[` + strings.TrimSuffix(strings.Repeat(`{"a":0},`, 200), ",") + `,` + quoted(p) + `]`)
		}},
	}
}

func keysOf(t *testing.T, reg *scanner.Registry, name string) []string {
	t.Helper()
	sc, err := reg.Get(name)
	require.NoError(t, err)
	return findingKeys(sc)
}

func ingestMemoryRegistry(t *testing.T) *scanner.Registry {
	t.Helper()
	reg := scanner.NewRegistry()
	for _, s := range parser.Builtins() {
		require.NoError(t, reg.Register(s))
	}
	return reg
}

// peakFactor is the peak heap growth of the ingest pipeline per byte of body.
func peakFactor(t *testing.T, reg *scanner.Registry, s memoryShape, doc []byte) float64 {
	t.Helper()
	runtime.GC()
	runtime.GC()
	var base runtime.MemStats
	runtime.ReadMemStats(&base)
	var err error
	peak := peakDuring(func() { err = ingestPipeline(t, reg, s.scanner, doc) })
	require.NoError(t, err, "%s: the densest accepted document must pass the pipeline", s.name)
	return float64(max(peak, base.HeapInuse)-base.HeapInuse) / float64(len(doc))
}

// The densest document of every shape that the ingest check accepts must peak
// below the memory the admission charges for it. A shape the check lets through
// at a denser packing than its cost estimate allows fails here.
func TestDensestAcceptedReportsStayUnderTheIngestCharge(t *testing.T) {
	sizes := []int{512 << 10}
	if v := os.Getenv("INGEST_MEMORY_MIB"); v != "" {
		sizes = nil
		for _, f := range strings.Split(v, ",") {
			n, err := strconv.Atoi(f)
			require.NoError(t, err)
			sizes = append(sizes, n<<20-4096)
		}
	}
	reg := ingestMemoryRegistry(t)
	worst, worstName := 0.0, ""
	for _, size := range sizes {
		for _, s := range allMemoryShapes() {
			doc := s.densest(keysOf(t, reg, s.scanner), size)
			factor := peakFactor(t, reg, s, doc)
			t.Logf("%-32s %6d KiB factor=%5.1fx", s.name, len(doc)>>10, factor)
			if factor > worst {
				worst, worstName = factor, s.name
			}
		}
	}
	t.Logf("worst %.1fx (%s) against a charge of %dx", worst, worstName, ingestBytesCharged)
	if worst > ingestBytesCharged {
		t.Errorf("%s peaks at %.1fx, above the %dx charge", worstName, worst, ingestBytesCharged)
	}
}

// The shapes the depth cap alone let through at 75x to 99x of the body, and
// reports of minimal findings, are refused once packed without padding, with the error that
// says the document is too dense.
func TestUnpaddedDenseShapesAreRefusedAsTooDense(t *testing.T) {
	reg := ingestMemoryRegistry(t)
	// These two shapes cost under 40 bytes per body byte as they are.
	fits := []string{"trivy wide object", "trivy number list"}
	for _, s := range allMemoryShapes() {
		t.Run(s.name, func(t *testing.T) {
			keys := keysOf(t, reg, s.scanner)
			doc := s.build(1<<20, "")
			if slices.Contains(fits, s.name) {
				require.NoError(t, scanner.CheckIngestDocument(doc, scanner.DefaultMaxFindings, keys...))
				return
			}
			err := scanner.CheckIngestDocument(doc, scanner.DefaultMaxFindings, keys...)
			var tooMany *scanner.TooManyFindingsError
			require.ErrorAs(t, err, &tooMany)
			require.True(t, tooMany.Dense)
		})
	}
}

// The ingest prices each element of a scanner's finding arrays as a finding, so
// every built-in parser must name them. A parser that does not is checked as a
// pile of small JSON values, which undercounts minimal findings.
func TestEveryBuiltinParserNamesItsFindingArrays(t *testing.T) {
	for _, s := range parser.Builtins() {
		fa, ok := s.(scanner.FindingArrayer)
		require.True(t, ok, "%s does not implement scanner.FindingArrayer", s.Descriptor().Name)
		require.NotEmpty(t, fa.FindingArrays(), s.Descriptor().Name)
	}
}
