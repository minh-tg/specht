//go:build e2e

package e2e

import (
	"encoding/json"
	"net/http"
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestE2E_CleanScanRetiresScopeSeverity(t *testing.T) {
	slug := newProject(t, "retired-severity")
	key := mintKey(t, slug)
	data, err := os.ReadFile("testdata/trivy-alpine-scan.json")
	require.NoError(t, err)
	var raw map[string]any
	require.NoError(t, json.Unmarshal(data, &raw))
	result := raw["Results"].([]any)[0].(map[string]any)
	vulnerability := result["Vulnerabilities"].([]any)[1].(map[string]any)

	scan := func(index int, branch, severity string) {
		t.Helper()
		result["Vulnerabilities"] = []any{}
		if severity != "" {
			vulnerability["Severity"] = severity
			result["Vulnerabilities"] = []any{vulnerability}
		}
		request[ingestResponse](t, http.MethodPost, "/api/v1/reports", key, map[string]any{
			"project": slug, "scanner": "trivy", "branch": branch,
			"commit_sha": strings.Repeat(string(rune('1'+index)), 40), "raw_data": raw,
		}, http.StatusCreated)
	}
	scan(0, "main", "CRITICAL")
	scan(1, "main", "")
	require.Equal(t, "fixed", listFindings(t, slug)[0].State)
	scan(2, "feature", "MEDIUM")
	require.Equal(t, "medium", listFindings(t, slug)[0].CurrentSeverity)
	require.False(t, getGate(t, slug, "").ThresholdBreached)

	// Absence in feature cannot retire main's currently critical evidence.
	scan(3, "main", "CRITICAL")
	scan(4, "feature", "")
	require.Equal(t, "critical", listFindings(t, slug)[0].CurrentSeverity)
	require.True(t, getGate(t, slug, "").ThresholdBreached)
}
