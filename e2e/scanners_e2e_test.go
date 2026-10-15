//go:build e2e

package e2e

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/require"
)

// TestE2E_EveryScannerTellsPeopleWhatItReads checks the catalog the upload page is built from:
// each scanner has a name a person knows and says which files it reads and how to make them.
func TestE2E_EveryScannerTellsPeopleWhatItReads(t *testing.T) {
	scanners := request[[]struct {
		Name        string `json:"name"`
		DisplayName string `json:"display_name"`
		Formats     []struct {
			Name       string   `json:"name"`
			Extensions []string `json:"extensions"`
			Command    string   `json:"command"`
			TestedWith string   `json:"tested_with"`
		} `json:"formats"`
	}](t, http.MethodGet, "/api/v1/scanners", adminToken, nil, http.StatusOK)

	require.Len(t, scanners, 11)
	names := map[string]bool{}
	for _, s := range scanners {
		require.NotEmpty(t, s.DisplayName, s.Name)
		require.False(t, names[s.DisplayName], "display name %q is shared", s.DisplayName)
		names[s.DisplayName] = true
		require.NotEmpty(t, s.Formats, s.Name)
		for _, f := range s.Formats {
			require.NotEmpty(t, f.Extensions, "%s %s", s.Name, f.Name)
			require.NotEmpty(t, f.Command, "%s %s", s.Name, f.Name)
			require.NotEmpty(t, f.TestedWith, "%s %s", s.Name, f.Name)
		}
	}
}
