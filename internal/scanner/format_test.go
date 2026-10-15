package scanner_test

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/minh-tg/specht/internal/scanner"
)

func TestShownNameFallsBackToTheRegisteredName(t *testing.T) {
	assert.Equal(t, "OSV-Scanner", scanner.Descriptor{Name: "osv-scanner", DisplayName: "OSV-Scanner"}.ShownName())
	assert.Equal(t, "osv-scanner", scanner.Descriptor{Name: "osv-scanner"}.ShownName(),
		"a scanner registered without a display name still has one")
}

func TestExtensionsListsEachOnceInOrder(t *testing.T) {
	d := scanner.Descriptor{Formats: []scanner.Format{
		{Name: "JSON", Extensions: []string{".json"}},
		{Name: "SARIF", Extensions: []string{".sarif", ".json"}},
	}}
	assert.Equal(t, []string{".json", ".sarif"}, d.Extensions())
}
