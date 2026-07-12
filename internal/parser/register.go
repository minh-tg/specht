package parser

import (
	"github.com/xMinhx/specht/internal/parser/osvscanner"
	"github.com/xMinhx/specht/internal/parser/trivy"
	"github.com/xMinhx/specht/internal/scanner"
)

func RegisterAll(reg *scanner.Registry) {
	reg.Register(trivy.NewScanner())
	reg.Register(osvscanner.NewScanner())
}
