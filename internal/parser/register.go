package parser

import (
	"github.com/vulnserve/vulnserve/internal/parser/osvscanner"
	"github.com/vulnserve/vulnserve/internal/parser/trivy"
	"github.com/vulnserve/vulnserve/internal/scanner"
)

func RegisterAll(reg *scanner.Registry) {
	reg.Register(trivy.NewParser())
	reg.Register(osvscanner.NewParser())
}
