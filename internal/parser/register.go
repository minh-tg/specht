package parser

import (
	"github.com/xMinhx/specht/internal/parser/checkov"
	"github.com/xMinhx/specht/internal/parser/dependencycheck"
	"github.com/xMinhx/specht/internal/parser/grype"
	"github.com/xMinhx/specht/internal/parser/osvscanner"
	"github.com/xMinhx/specht/internal/parser/semgrep"
	"github.com/xMinhx/specht/internal/parser/trivy"
	"github.com/xMinhx/specht/internal/scanner"
)

func RegisterAll(reg *scanner.Registry) {
	reg.Register(trivy.NewScanner())
	reg.Register(osvscanner.NewScanner())
	reg.Register(semgrep.NewScanner())
	reg.Register(checkov.NewScanner())
	reg.Register(dependencycheck.NewScanner())
	reg.Register(grype.NewScanner())
}
