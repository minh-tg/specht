//go:build e2e

package e2e

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/require"
)

// A PUT naming another project's waiver and a PUT naming an id that does not
// exist answer alike, whatever the body holds.
func TestUpdateForeignAndMissingWaiverAnswerAlike(t *testing.T) {
	slug := newProject(t, "waiver-ids")
	other := newProject(t, "waiver-ids-other")
	ingestFixture(t, other, mintKey(t, other), "high.sarif.json")
	foreign := createWaiver(t, other, "foreign", highFinding(t, other).ID, "")
	const missing = "00000000-0000-4000-8000-00000000dead"
	base := "/api/v1/projects/" + slug + "/waivers/"

	for _, body := range []map[string]any{
		{"description": "x"},
		{"conditions": []any{}},
		{"contexts": []any{}},
		{"conditions": []any{map[string]any{"field": "severity", "operator": "eq", "value": "HIGH"}}},
	} {
		fs, fb := doJSON(t, http.MethodPut, base+foreign.ID, adminToken, body)
		ms, mb := doJSON(t, http.MethodPut, base+missing, adminToken, body)
		require.Equalf(t, http.StatusNotFound, ms, "body %v: missing=%d %s", body, ms, mb)
		require.Equalf(t, ms, fs, "body %v: foreign=%d %s missing=%d %s", body, fs, fb, ms, mb)
		require.JSONEq(t, string(mb), string(fb))
	}
	// The foreign waiver survived every call.
	request[waiverDetail](t, http.MethodGet, "/api/v1/projects/"+other+"/waivers/"+foreign.ID, adminToken, nil, http.StatusOK)
}
