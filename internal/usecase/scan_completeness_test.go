package usecase

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/minh-tg/specht/internal/domain"
)

func TestToReport_EmitsTheStoredCompleteness(t *testing.T) {
	for _, stored := range []string{"complete", "partial", "unknown"} {
		t.Run(stored, func(t *testing.T) {
			r := makeReport()
			r.ScanCompleteness = stored

			resp := toReport(r, 0)
			assert.Equal(t, stored, resp.ScanCompleteness)

			body, err := json.Marshal(resp)
			require.NoError(t, err)
			assert.Contains(t, string(body), `"scan_completeness":"`+stored+`"`)
		})
	}
}

func TestToReport_CompletenessIsNeverEmpty(t *testing.T) {
	r := makeReport()
	r.ScanCompleteness = ""

	resp := toReport(r, 0)
	assert.Equal(t, string(domain.CompletenessUnknown), resp.ScanCompleteness)
}

func TestToReport_DeclaredFilterDoesNotChangeCompleteness(t *testing.T) {
	r := makeReport()
	r.ScanCompleteness = "complete"
	r.FilterSeverities = []string{"critical"}

	resp := toReport(r, 0)
	assert.Equal(t, "complete", resp.ScanCompleteness)
	assert.NotNil(t, resp.ScanFilter)
}
