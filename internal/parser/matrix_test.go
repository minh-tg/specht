package parser_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/minh-tg/specht/internal/parser"
	"github.com/minh-tg/specht/internal/scanner"
)

// The matrix test holds one promise: a document is accepted only by the scanner
// that owns its format. Every fixture in the repository, real output of every
// supported tool and of tools Specht has no parser for, is checked against
// every registered scanner the way ingest checks an upload. The owner passes;
// everyone else refuses. A parser that answers "success, zero findings" to
// another tool's output fails here.

func builtinRegistry(t *testing.T) *scanner.Registry {
	t.Helper()
	reg := scanner.NewRegistry()
	for _, s := range parser.Builtins() {
		require.NoError(t, reg.Register(s))
	}
	return reg
}

// directoryOwner names the scanner whose fixtures live in internal/parser/<dir>/testdata.
var directoryOwner = map[string]string{
	"trivy": "trivy", "osvscanner": "osv-scanner", "grype": "grype", "dependencycheck": "dependency-check",
	"semgrep": "semgrep", "checkov": "checkov", "tfsec": "tfsec", "gitleaks": "gitleaks", "nuclei": "nuclei",
	"sbom": "sbom", "sarif": "sarif",
}

// e2eOwner names the scanner for each file in e2e/testdata, by file name prefix.
var e2ePrefixOwner = []struct{ prefix, owner string }{
	{"trivy-", "trivy"},
	{"osv-", "osv-scanner"},
	{"grype-", "grype"},
	{"dependency-check", "dependency-check"},
	{"semgrep-", "semgrep"},
	{"checkov-", "checkov"},
	{"tfsec", "tfsec"},
	{"gitleaks", "gitleaks"},
	{"nuclei", "nuclei"},
	{"sbom-", "sbom"},
	{"high", "sarif"},
	{"medium", "sarif"},
}

type fixture struct {
	path   string
	owners []string
}

// withGenericSARIF adds the generic sarif scanner to the owners of a SARIF log:
// it reads every SARIF 2.1 document, whichever tool wrote it.
func withGenericSARIF(owners ...string) []string {
	for _, o := range owners {
		if o == "sarif" {
			return owners
		}
	}
	return append(owners, "sarif")
}

func collectFixtures(t *testing.T) []fixture {
	t.Helper()
	var out []fixture
	add := func(path string, owners ...string) { out = append(out, fixture{path: path, owners: owners}) }

	for dir, owner := range directoryOwner {
		files, err := filepath.Glob(filepath.Join(dir, "testdata", "*"))
		require.NoError(t, err)
		for _, f := range files {
			if strings.HasSuffix(f, ".json") || strings.HasSuffix(f, ".jsonl") {
				if owner == "semgrep" {
					add(f, withGenericSARIF(owner)...)
				} else {
					add(f, owner)
				}
			}
		}
	}
	// multi-tool.sarif.json starts with a Semgrep run, so Semgrep reads it too.
	for i := range out {
		if filepath.Base(out[i].path) == "multi-tool.sarif.json" {
			out[i].owners = []string{"sarif", "semgrep"}
		}
	}

	raw, err := os.ReadFile("testdata/captured/manifest.json")
	require.NoError(t, err)
	var manifest struct {
		Fixtures []struct{ File, Scanner string } `json:"fixtures"`
	}
	require.NoError(t, json.Unmarshal(raw, &manifest))
	for _, f := range manifest.Fixtures {
		owners := []string{f.Scanner}
		if f.Scanner == "semgrep" {
			owners = withGenericSARIF(owners...)
		}
		add(filepath.Join("testdata", "captured", f.File), owners...)
	}

	e2e, err := filepath.Glob("../../e2e/testdata/*")
	require.NoError(t, err)
	for _, f := range e2e {
		base := filepath.Base(f)
		var owner string
		for _, p := range e2ePrefixOwner {
			if strings.HasPrefix(base, p.prefix) {
				owner = p.owner
				break
			}
		}
		require.NotEmpty(t, owner, "no owner is declared for e2e/testdata/%s: add it to e2ePrefixOwner", base)
		if owner == "semgrep" {
			add(f, withGenericSARIF(owner)...)
		} else {
			add(f, owner)
		}
	}

	foreign, err := filepath.Glob("testdata/foreign/*.json")
	require.NoError(t, err)
	for _, f := range foreign {
		if filepath.Base(f) != "manifest.json" {
			add(f) // no scanner owns it
		}
	}
	return out
}

func TestEveryScannerRefusesEveryFormatThatIsNotItsOwn(t *testing.T) {
	reg := builtinRegistry(t)
	var names []string
	for _, d := range reg.List() {
		names = append(names, d.Name)
	}
	sort.Strings(names)

	fixtures := collectFixtures(t)
	require.Greater(t, len(fixtures), 40, "the matrix should cover every fixture in the repository")

	for _, fx := range fixtures {
		t.Run(filepath.ToSlash(fx.path), func(t *testing.T) {
			data, err := os.ReadFile(fx.path)
			require.NoError(t, err)
			owns := map[string]bool{}
			for _, o := range fx.owners {
				owns[o] = true
			}
			for _, name := range names {
				err := reg.CheckFormat(name, data)
				if owns[name] {
					assert.NoError(t, err, "%s should accept its own fixture", name)
				} else {
					assert.ErrorIs(t, err, scanner.ErrUnrecognizedFormat, "%s should refuse a fixture that is not its format", name)
				}
			}
		})
	}
}

func TestEveryBuiltinGradesItsOwnDocuments(t *testing.T) {
	for _, s := range parser.Builtins() {
		name := s.Descriptor().Name
		t.Run(name, func(t *testing.T) {
			_, ok := s.(scanner.Recognizer)
			assert.True(t, ok, "%s must implement scanner.Recognizer", name)
			for _, doc := range []string{`[]`, `{}`, `null`, `not json`, ``, `42`} {
				assert.Equal(t, scanner.Recognize(s, []byte(doc)) == scanner.Definite, s.DetectFormat([]byte(doc)),
					"DetectFormat must equal the definite grade for %q", doc)
			}
		})
	}
}
