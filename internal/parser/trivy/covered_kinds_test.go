package trivy

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/minh-tg/specht/internal/domain"
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
		{"unrecognized result class", []map[string]any{{"Target": "x", "Class": "license"}}, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			parsed, err := NewScanner().Parse(context.Background(), report(tc.results))
			require.NoError(t, err)
			require.Equal(t, tc.want, parsed.CoveredFindingKinds)
			if len(tc.want) == 0 {
				require.Equal(t, domain.CompletenessUnknown, parsed.Completeness,
					"a document that lists no result class does not show the scan was complete")
			} else {
				require.Equal(t, domain.CompletenessComplete, parsed.Completeness)
			}
		})
	}
}
