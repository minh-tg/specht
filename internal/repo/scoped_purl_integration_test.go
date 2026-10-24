//go:build integration

package repo

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/minh-tg/specht/internal/port"
)

func TestWatcherDedupPreservesUnversionedScopedPackage(t *testing.T) {
	for _, tc := range []struct{ purl, name string }{
		{"pkg:npm/@angular/core", "pkg:npm/@angular/core"},
		{"pkg:npm/@angular/core@14.0.0", "pkg:npm/@angular/core"},
		{"pkg:npm/%40angular/core", "pkg:npm/%40angular/core"},
		{"corp@vendor/pkg@1.0.0", "corp@vendor/pkg"},
	} {
		t.Run(tc.purl, func(t *testing.T) {
			s, cleanup := newScopeSeverityScenario(t)
			defer cleanup()
			for _, d := range []port.DimensionInput{{FindingID: s.findingID, Key: "purl", Value: tc.purl}, {FindingID: s.findingID, Key: "vulnerability_id", Value: "CVE-2030-1234"}} {
				require.NoError(t, s.stores.Findings.UpsertDimension(s.ctx, d))
			}
			id, err := s.stores.Findings.FindScaFindingIDForPurlAndCve(s.ctx, s.projectID, tc.name, []string{"CVE-2030-1234"})
			require.NoError(t, err)
			require.Equal(t, s.findingID, id)
		})
	}
}
