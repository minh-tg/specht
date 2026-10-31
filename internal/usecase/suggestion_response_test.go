package usecase

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/minh-tg/specht/internal/domain"
	"github.com/minh-tg/specht/internal/port"
)

func TestSuggestionFromEvidence_FixFields(t *testing.T) {
	scaDims := []port.FindingDimension{
		{Key: domain.DimPackageName, Value: "lodash"},
		{Key: domain.DimEcosystem, Value: "npm"},
		{Key: domain.DimInstalledVer, Value: "4.17.20"},
		{Key: domain.DimFixedVersion, Value: "4.17.21"},
	}
	tests := []struct {
		name string
		kind string
		dims []port.FindingDimension
		rem  *RemediationResponse
		want SuggestionResponse
	}{
		{
			name: "sca with fixed version",
			kind: "sca", dims: scaDims,
			want: SuggestionResponse{
				Action: "upgrade", Target: "lodash", Fallback: false, Package: "lodash",
				Ecosystem: "npm", InstalledVersion: "4.17.20", FixedVersion: "4.17.21",
			},
		},
		{
			name: "sca without fixed version",
			kind: "sca", dims: scaDims[:3],
			rem: &RemediationResponse{Fallback: true},
			want: SuggestionResponse{
				Action: "review", Target: "lodash", Fallback: true, Package: "lodash",
				Ecosystem: "npm", InstalledVersion: "4.17.20",
			},
		},
		{
			name: "sast fallback",
			kind: "sast", dims: []port.FindingDimension{{Key: "file", Value: "db.go"}},
			rem:  &RemediationResponse{Fallback: true},
			want: SuggestionResponse{Action: "review", Target: "db.go", Fallback: true},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := suggestionFromEvidence(
				port.Finding{ID: "f1", FindingKind: tt.kind}, tt.dims, "scanner", tt.rem)
			require.NotNil(t, got)
			assert.Equal(t, tt.want.Action, got.Action)
			assert.Equal(t, tt.want.Target, got.Target)
			assert.Equal(t, tt.want.Fallback, got.Fallback)
			assert.Equal(t, tt.want.Package, got.Package)
			assert.Equal(t, tt.want.Ecosystem, got.Ecosystem)
			assert.Equal(t, tt.want.InstalledVersion, got.InstalledVersion)
			assert.Equal(t, tt.want.FixedVersion, got.FixedVersion)
		})
	}
}

func TestSuggestionResponse_JSONOmitsEmptyFixFields(t *testing.T) {
	b, err := json.Marshal(SuggestionResponse{Action: "review", Confidence: "low", Fallback: true})
	require.NoError(t, err)
	var m map[string]any
	require.NoError(t, json.Unmarshal(b, &m))
	assert.Equal(t, true, m["fallback"])
	for _, k := range []string{"package", "ecosystem", "installed_version", "fixed_version"} {
		assert.NotContains(t, m, k)
	}
}
