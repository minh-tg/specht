// Package parser is the composition point for the built-in scanner parser
// adapters. It exposes the concrete built-in scanners; registering them into
// a scanner.Registry is a composition-root concern, so this package never
// imports the registry package.
package parser

import (
	"fmt"
	"slices"
	"strings"

	"github.com/minh-tg/specht/internal/parser/checkov"
	"github.com/minh-tg/specht/internal/parser/dependencycheck"
	"github.com/minh-tg/specht/internal/parser/gitleaks"
	"github.com/minh-tg/specht/internal/parser/grype"
	"github.com/minh-tg/specht/internal/parser/nuclei"
	"github.com/minh-tg/specht/internal/parser/osvscanner"
	"github.com/minh-tg/specht/internal/parser/sarif"
	"github.com/minh-tg/specht/internal/parser/sbom"
	"github.com/minh-tg/specht/internal/parser/semgrep"
	"github.com/minh-tg/specht/internal/parser/tfsec"
	"github.com/minh-tg/specht/internal/parser/trivy"
	"github.com/minh-tg/specht/internal/scanner"
)

// Builtins returns the concrete built-in scanner parser adapters in a stable
// order. Only the composition root registers these into a Registry and
// handles registration errors.
func Builtins() []scanner.Scanner {
	return []scanner.Scanner{
		trivy.NewScanner(),
		osvscanner.NewScanner(),
		semgrep.NewScanner(),
		checkov.NewScanner(),
		dependencycheck.NewScanner(),
		grype.NewScanner(),
		sbom.NewScanner(),
		sarif.NewScanner(),
		gitleaks.NewScanner(),
		tfsec.NewScanner(),
		nuclei.NewScanner(),
	}
}

// ScannerTable renders the built-in scanners as the markdown the README shows: what each
// reads, how to produce the file, and the version it was checked with, followed by the
// notes worth knowing. It is written from the descriptors, so the README cannot
// say something the parsers do not.
func ScannerTable() string {
	var table, notes strings.Builder
	table.WriteString("| Scanner | Files it reads | How to produce one | Checked with |\n")
	table.WriteString("|---|---|---|---|\n")
	for _, s := range Builtins() {
		d := s.Descriptor()
		var files, commands, tested []string
		for _, f := range d.Formats {
			files = append(files, fmt.Sprintf("%s (`%s`)", f.Name, strings.Join(f.Extensions, "`, `")))
			commands = append(commands, "`"+f.Command+"`")
			if !slices.Contains(tested, f.TestedWith) {
				tested = append(tested, f.TestedWith)
			}
			if f.Note != "" {
				fmt.Fprintf(&notes, "- **%s**: %s\n", d.ShownName(), f.Note)
			}
		}
		fmt.Fprintf(&table, "| **%s** | %s | %s | %s |\n",
			d.ShownName(), strings.Join(files, "<br>"), strings.Join(commands, "<br>"), strings.Join(tested, "<br>"))
	}
	if notes.Len() == 0 {
		return table.String()
	}
	return table.String() + "\n" + notes.String()
}
