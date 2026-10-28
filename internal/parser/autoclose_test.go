package parser

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/minh-tg/specht/internal/scanner"
)

// Only scanners whose report can show a finding was looked for may close one
// by absence. The rest stay manual.
func TestOnlyProvingScannersSupportAutoClose(t *testing.T) {
	want := map[string]bool{
		"trivy": true, "grype": true, "sarif": true, "checkov": true,
	}
	for _, s := range Builtins() {
		name := s.Descriptor().Name
		assert.Equal(t, want[name], scanner.SupportsAutoClose(s), name)
	}
}
