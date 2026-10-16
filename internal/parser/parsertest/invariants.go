// Package parsertest holds the invariant checks and seed loader the parser fuzz
// targets share. It is test support only.
package parsertest

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/minh-tg/specht/internal/domain"
	"github.com/minh-tg/specht/internal/parser/parseutil"
)

// Seeds adds every file under dir (non-recursive) as a fuzz seed.
func Seeds(f *testing.F, dir string) {
	f.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		f.Fatalf("read seeds: %v", err)
	}
	for _, e := range entries {
		if e.IsDir() || strings.HasSuffix(e.Name(), ".md") {
			continue
		}
		data, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err != nil {
			f.Fatalf("read seed %s: %v", e.Name(), err)
		}
		f.Add(data)
	}
	// Hostile shapes every parser must survive.
	f.Add([]byte(""))
	f.Add([]byte("null"))
	f.Add([]byte("[]"))
	f.Add([]byte("{}"))
	f.Add([]byte("\xef\xbb\xbf{}"))
	f.Add([]byte(strings.Repeat("[", 5000) + strings.Repeat("]", 5000)))
	f.Add([]byte(`{"a":"\u0000\u001b[31m\u202e"}`))
	f.Add([]byte(`{"results":[{"source":{"path":"../../x"},"packages":[{"package":{"name":"a","version":"1"},"vulnerabilities":[{"id":"X","severity":[{"type":"CVSS_V3","score":"CVSS:3.1/AV:N"}]}]}]}]}`))
}

// Check asserts the hardening invariants HardenFinding promises on every
// finding and package of a report. It never fails on an error from Parse;
// the caller decides what an error means.
func Check(t testing.TB, rep *domain.NormalizedReport) {
	t.Helper()
	if rep == nil {
		return
	}
	if rep.Target != nil {
		bounded(t, "target.identifier", rep.Target.Identifier, parseutil.MaxTargetIdentifierLength)
		bounded(t, "target.kind", rep.Target.Kind, parseutil.MaxTargetKindLength)
	}
	if rep.ScanScope != nil {
		for k, v := range rep.ScanScope.Ext {
			bounded(t, "scope.key", k, parseutil.MaxScopeKeyLength)
			bounded(t, "scope.value", v, parseutil.MaxScopeValueLength)
		}
	}
	for i, f := range rep.Findings {
		if b, err := json.Marshal(f.Extensions); err != nil || len(b) > parseutil.MaxExtensionsBytes || strings.Contains(string(b), `\u0000`) {
			t.Fatalf("finding %d: extensions are %d bytes (err %v) or hold a NUL", i, len(b), err)
		}
		if len(f.Fingerprint) > parseutil.MaxFingerprintLength {
			t.Fatalf("finding %d: fingerprint %d bytes exceeds %d", i, len(f.Fingerprint), parseutil.MaxFingerprintLength)
		}
		noNUL(t, "fingerprint", f.Fingerprint)
		bounded(t, "title", f.Title, parseutil.MaxTitleLength)
		bounded(t, "description", f.Description, parseutil.MaxDescriptionLength)
		bounded(t, "location", f.Location, parseutil.MaxPathLength)
		bounded(t, "resource", f.Resource, parseutil.MaxTitleLength)
		if f.Severity < domain.SeverityUnknown || f.Severity > domain.SeverityCritical {
			t.Fatalf("finding %d: severity %d outside 0..4", i, f.Severity)
		}
		if f.Score < 0 || f.Score > 10 || f.Score != f.Score {
			t.Fatalf("finding %d: score %v outside 0..10", i, f.Score)
		}
		if f.CVSS != nil {
			if f.CVSS.Score < 0 || f.CVSS.Score > 10 || f.CVSS.Score != f.CVSS.Score {
				t.Fatalf("finding %d: cvss score %v outside 0..10", i, f.CVSS.Score)
			}
			bounded(t, "cvss.vector", f.CVSS.Vector, 256)
		}
		if len(f.CVSSAll) > domain.MaxCVSSRecords {
			t.Fatalf("finding %d: %d cvss records", i, len(f.CVSSAll))
		}
		for _, r := range f.CVSSAll {
			if r.Score < 0 || r.Score > 10 || r.Score != r.Score {
				t.Fatalf("finding %d: cvss_all score %v", i, r.Score)
			}
			bounded(t, "cvss_all.vector", r.Vector, domain.MaxCVSSVectorLength)
		}
		if f.CodeLocation != nil {
			c := f.CodeLocation
			bounded(t, "code.file", c.File, parseutil.MaxPathLength)
			if strings.HasPrefix(c.File, "../") || strings.Contains(c.File, "/../") {
				t.Fatalf("finding %d: file escapes root: %q", i, c.File)
			}
			if c.StartLine < 0 || c.EndLine < c.StartLine || c.StartColumn < 0 || c.EndColumn < 0 {
				t.Fatalf("finding %d: bad lines %+v", i, *c)
			}
			bounded(t, "code.snippet", c.Snippet, 4096)
		}
		for _, d := range f.Dimensions {
			bounded(t, "dim.key", d.Key, 64)
			bounded(t, "dim.value", d.Value, parseutil.MaxDimensionValueLength)
		}
		for _, a := range f.Aliases {
			bounded(t, "alias", a, 256)
		}
		if f.Fix != nil {
			bounded(t, "fix.summary", f.Fix.Summary, parseutil.MaxTitleLength)
			bounded(t, "fix.url", f.Fix.URL, parseutil.MaxPathLength)
			bounded(t, "fix.description", f.Fix.Description, parseutil.MaxDescriptionLength)
		}
	}
	for i, p := range rep.Packages {
		bounded(t, "pkg.name", p.Name, parseutil.MaxTitleLength)
		bounded(t, "pkg.version", p.Version, 256)
		bounded(t, "pkg.ecosystem", p.Ecosystem, 128)
		bounded(t, "pkg.purl", p.PURL, parseutil.MaxPathLength)
		bounded(t, "pkg.manifest", p.ManifestPath, parseutil.MaxPathLength)
		if strings.HasPrefix(p.ManifestPath, "../") {
			t.Fatalf("package %d: manifest escapes root: %q", i, p.ManifestPath)
		}
	}
}

func noNUL(t testing.TB, field, s string) {
	t.Helper()
	if strings.ContainsRune(s, 0) {
		t.Fatalf("%s contains NUL", field)
	}
	if !utf8.ValidString(s) {
		t.Fatalf("%s is not valid UTF-8", field)
	}
}

func bounded(t testing.TB, field, s string, max int) {
	t.Helper()
	noNUL(t, field, s)
	if len(s) > max {
		t.Fatalf("%s is %d bytes, limit %d", field, len(s), max)
	}
}
