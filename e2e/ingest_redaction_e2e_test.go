//go:build e2e

package e2e

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"

	"github.com/stretchr/testify/require"
)

// postedReportID ingests document and returns the id of the stored report.
func postedReportID(t *testing.T, slug, scannerName string, document []byte) string {
	t.Helper()
	status, body := doJSON(t, http.MethodPost, "/api/v1/reports", adminToken, map[string]any{
		"project": slug, "scanner": scannerName, "raw_data": json.RawMessage(document),
	})
	require.Equal(t, http.StatusCreated, status, string(body))
	var resp ingestResponse
	require.NoError(t, json.Unmarshal(body, &resp))
	require.NotEmpty(t, resp.ReportID)
	return resp.ReportID
}

// TestE2E_RedactionHoldsWhenTheDocumentCarriesAnOutOfRangeNumber walks the story
// behind fail-closed redaction. A number that overflows a float64 in a field the
// parser ignores used to make the redaction step give up and store the report
// as it came, with the secret in reports.raw_data. The redactor now reads any
// valid JSON, so the secret is replaced while the report is still ingested.
func TestE2E_RedactionHoldsWhenTheDocumentCarriesAnOutOfRangeNumber(t *testing.T) {
	slug := newProject(t, "redaction")
	db := openE2EDB(t)

	cases := []struct {
		name, scanner, document, secret string
	}{
		{"gitleaks", "gitleaks", `[{"RuleID":"aws-access-token","File":"a.env","StartLine":1,"Secret":"AKIAE2EFAILCLOSED0001","Match":"key=AKIAE2EFAILCLOSED0001","x":1e400}]`, "AKIAE2EFAILCLOSED0001"},
		{"gitleaks with a negative overflow in a list", "gitleaks", `[{"RuleID":"aws-access-token","File":"b.env","StartLine":2,"Secret":"AKIAE2EFAILCLOSED0002","Match":"m=AKIAE2EFAILCLOSED0002","extra":{"y":[-1e999]}}]`, "AKIAE2EFAILCLOSED0002"},
		{"gitleaks control without an overflow", "gitleaks", `[{"RuleID":"aws-access-token","File":"c.env","StartLine":3,"Secret":"AKIAE2ECONTROL00003","Match":"m=AKIAE2ECONTROL00003"}]`, "AKIAE2ECONTROL00003"},
		{"nuclei array", "nuclei", `[{"template-id":"t","host":"http://h","matched-at":"http://h/","info":{"name":"n","severity":"high"},"request":"GET / HTTP/1.1\r\nAuthorization: Bearer E2ENUCLEITOKEN0004\r\n","x":1e400}]`, "E2ENUCLEITOKEN0004"},
		{"nuclei lines", "nuclei", `{"template-id":"t2","host":"http://h2","matched-at":"http://h2/","info":{"name":"n","severity":"high"},"response":"Set-Cookie: s=E2ENUCLEITOKEN0005","x":1e400}` + "\n", "E2ENUCLEITOKEN0005"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			id := postedReportID(t, slug, c.scanner, []byte(c.document))

			var leaked bool
			var stored string
			require.NoError(t, db.QueryRow(context.Background(),
				`SELECT position($2 in raw_data::text) > 0, raw_data::text FROM reports WHERE id = $1`, id, c.secret).Scan(&leaked, &stored))
			require.False(t, leaked, "the secret must not be stored in reports.raw_data: %s", stored)
			require.Contains(t, stored, `REDACTED`, "the evidence is stored redacted, not dropped")
		})
	}
}
