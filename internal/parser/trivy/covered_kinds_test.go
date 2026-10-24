package trivy

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestParseRecordsTheClassesTheScanExamined(t *testing.T) {
	report := func(results []map[string]any) []byte {
		raw, err := json.Marshal(map[string]any{
			"SchemaVersion": 2, "ArtifactName": "app:1", "ArtifactType": "container_image",
			"Results": results,
		})
		require.NoError(t, err)
		return raw
	}
	for _, tc := range []struct {
		name    string
		results []map[string]any
		want    []string
	}{
		{"vulnerabilities", []map[string]any{{"Target": "app:1", "Class": "os-pkgs"}}, []string{"sca"}},
		{"secrets", []map[string]any{{"Target": "Dockerfile", "Class": "secret"}}, []string{"secret"}},
		{"configuration", []map[string]any{{"Target": "main.tf", "Class": "config"}}, []string{"iac"}},
		{"no result class", nil, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			parsed, err := NewScanner().Parse(context.Background(), report(tc.results))
			require.NoError(t, err)
			require.Equal(t, tc.want, parsed.CoveredFindingKinds)
		})
	}
}
