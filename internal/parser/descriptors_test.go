package parser_test

import (
	"os"
	"regexp"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/minh-tg/specht/internal/parser"
)

// uploadExtensions are the file extensions the upload page accepts. A format that names one
// outside this set could not be sent through the page.
var uploadExtensions = map[string]bool{".json": true, ".jsonl": true, ".ndjson": true, ".sarif": true}

func TestEveryScannerDescribesItselfForPeople(t *testing.T) {
	seenNames := map[string]string{}
	for _, s := range parser.Builtins() {
		d := s.Descriptor()
		t.Run(d.Name, func(t *testing.T) {
			require.NotEmpty(t, d.DisplayName, "the picker shows a name a person recognises")
			if other, dup := seenNames[d.DisplayName]; dup {
				t.Errorf("display name %q is used by %s and %s", d.DisplayName, other, d.Name)
			}
			seenNames[d.DisplayName] = d.Name

			require.NotEmpty(t, d.Formats, "a scanner says what files it takes")
			for _, f := range d.Formats {
				assert.NotEmpty(t, f.Name)
				assert.NotEmpty(t, f.Command, "%s: say how to produce the file", f.Name)
				assert.NotEmpty(t, f.TestedWith, "%s: say which version was checked", f.Name)
				require.NotEmpty(t, f.Extensions, f.Name)
				for _, ext := range f.Extensions {
					assert.True(t, uploadExtensions[ext], "%s: %q cannot be uploaded through the page", f.Name, ext)
				}
				assert.NotContains(t, f.Command+f.Note+f.TestedWith, "—", "no em dash in copy")
			}
		})
	}
}

// The README lists the scanners from the same descriptors, so the two cannot disagree.
// Run UPDATE_DOCS=1 go test ./internal/parser -run TestReadmeScannerTable to rewrite it.
func TestReadmeScannerTableIsCurrent(t *testing.T) {
	const start, end = "<!-- scanners:start -->", "<!-- scanners:end -->"
	readme, err := os.ReadFile("../../README.md")
	require.NoError(t, err)
	text := string(readme)

	want := start + "\n" + parser.ScannerTable() + end
	re := regexp.MustCompile(`(?s)` + regexp.QuoteMeta(start) + `.*?` + regexp.QuoteMeta(end))
	require.True(t, re.MatchString(text), "README.md needs the %s and %s markers", start, end)

	if os.Getenv("UPDATE_DOCS") != "" {
		require.NoError(t, os.WriteFile("../../README.md", []byte(re.ReplaceAllLiteralString(text, want)), 0o644))
		return
	}
	got := re.FindString(text)
	assert.Equal(t, strings.TrimSpace(want), strings.TrimSpace(got),
		"README.md is out of date: run UPDATE_DOCS=1 go test ./internal/parser -run TestReadmeScannerTable")
}

func TestScannerTableListsEveryScannerOnce(t *testing.T) {
	table := parser.ScannerTable()
	for _, s := range parser.Builtins() {
		d := s.Descriptor()
		assert.Equal(t, 1, strings.Count(table, "| **"+d.DisplayName+"** |"), d.DisplayName)
	}
}
