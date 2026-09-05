// Package parser is the composition point for the built-in scanner parser
// adapters. It exposes the concrete built-in scanners; registering them into
// a scanner.Registry is a composition-root concern, so this package never
// imports the registry package.
package parser

import (
	"github.com/xMinhx/specht/internal/parser/checkov"
	"github.com/xMinhx/specht/internal/parser/dependencycheck"
	"github.com/xMinhx/specht/internal/parser/gitleaks"
	"github.com/xMinhx/specht/internal/parser/grype"
	"github.com/xMinhx/specht/internal/parser/nuclei"
	"github.com/xMinhx/specht/internal/parser/osvscanner"
	"github.com/xMinhx/specht/internal/parser/sarif"
	"github.com/xMinhx/specht/internal/parser/sbom"
	"github.com/xMinhx/specht/internal/parser/semgrep"
	"github.com/xMinhx/specht/internal/parser/tfsec"
	"github.com/xMinhx/specht/internal/parser/trivy"
	"github.com/xMinhx/specht/internal/scanner"
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
