//go:build e2e

package e2e

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// nul is the JSON escape for the NUL character. PostgreSQL refuses it in text
// and jsonb values, so a report that carries one used to fail the whole ingest
// with a generic 422 ingest_failed.
var nul = fmt.Sprintf("%cu0000", 92)

// TestE2E_AReportWithNULCharactersIsIngestedWithoutThem walks the story behind
// NUL handling: a scanner that quotes a file with an embedded NUL byte, or a
// hostile document, no longer fails the ingest. The NUL is dropped from every
// stored string and from the stored evidence, and the findings stay readable.
func TestE2E_AReportWithNULCharactersIsIngestedWithoutThem(t *testing.T) {
	slug := newProject(t, "nul")
	db := openE2EDB(t)
	s := func(parts ...string) string { return strings.Join(parts, nul) }

	cases := []struct {
		name, scanner, document string
	}{
		{"trivy title, path, id and nested fields", "trivy", `{"ArtifactName":"a","Results":[{"Target":"` + s("src/ma", "in.go") + `","Vulnerabilities":[{` +
			`"VulnerabilityID":"` + s("CVE-2026-", "0001") + `","PkgName":"` + s("p", "kg") + `","InstalledVersion":"1","Severity":"HIGH",` +
			`"Title":"` + s("ti", "tle") + `","Description":"` + s("de", "scription") + `","References":["` + s("http://x/", "") + `"],` +
			`"Unread":{"nested":{"deep":["` + s("a", "b") + `"]}}}]}]}`},
		{"semgrep rule id, path and message", "semgrep", `{"results":[{"check_id":"` + s("rules.no", "nul") + `","path":"` + s("app/m", "ain.py") + `",` +
			`"start":{"line":1},"end":{"line":1},"extra":{"message":"` + s("mess", "age") + `","severity":"ERROR","lines":"` + s("l", "ine") + `",` +
			`"metadata":{"nested":{"k":["` + s("v", "v") + `"]}}}}],"errors":[]}`},
		{"gitleaks description and file", "gitleaks", `[{"RuleID":"` + s("aws-", "key") + `","File":"` + s("a", ".env") + `","StartLine":1,"Secret":"` + s("AKIA", "NULSECRET0001") + `",` +
			`"Match":"` + s("k=AKIA", "NULSECRET0001") + `","Description":"` + s("de", "sc") + `","Tags":["` + s("t", "ag") + `"]}]`},
		{"nuclei request and name", "nuclei", `[{"template-id":"` + s("t", "id") + `","host":"http://h","matched-at":"http://h/","info":{"name":"` + s("n", "ame") + `","severity":"high"},` +
			`"request":"` + s("GET /", " HTTP/1.1") + `"}]`},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			status, got := postReport(t, slug, c.scanner, []byte(c.document))
			require.Equal(t, http.StatusCreated, status, "%s: %s", got.Error.Code, got.Error.Message)

			var stored int
			require.NoError(t, db.QueryRow(context.Background(), `
				SELECT count(*) FROM reports r WHERE r.project_id = (SELECT id FROM projects WHERE slug = $1)
				  AND r.raw_data::text LIKE '%\\u0000%'`, slug).Scan(&stored))
			require.Zero(t, stored, "no stored evidence holds a NUL escape")
		})
	}

	for _, f := range listFindings(t, slug) {
		require.NotContains(t, f.CurrentTitle, "\x00", "title of %s", f.ID)
	}
}

// A NUL inside an object key is refused: dropping it would rename the field,
// which would change what the parser reads and what redaction matches.
func TestE2E_ANULInAFieldNameIsRefused(t *testing.T) {
	slug := newProject(t, "nul-key")
	doc := `{"ArtifactName":"a","Resu` + nul + `lts":[{"Target":"t","Vulnerabilities":[{"VulnerabilityID":"CVE-1","PkgName":"p","Severity":"HIGH"}]}]}`

	status, got := postReport(t, slug, "trivy", []byte(doc))

	require.Equal(t, http.StatusUnprocessableEntity, status)
	require.Equal(t, "malformed_report", got.Error.Code)
	require.Empty(t, listFindings(t, slug), "nothing is stored")
}

// The request's own text fields reach PostgreSQL too. A NUL in one of them is
// refused with a message that names the field, before the database.
func TestE2E_ANULInARequestFieldIsRefusedByName(t *testing.T) {
	slug := newProject(t, "nul-field")
	report := `{"ArtifactName":"a","Results":[{"Target":"t","Vulnerabilities":[{"VulnerabilityID":"CVE-1","PkgName":"p","Severity":"HIGH"}]}]}`

	for _, field := range []string{"project", "scanner", "scanner_version", "parser_version", "branch", "commit_sha", "base_revision", "scan_mode", "gate_severity", "gate_status", "environment", "owner", "digest", "artifact_name", "artifact_version", "artifact_type"} {
		t.Run(field, func(t *testing.T) {
			status, body := doJSON(t, http.MethodPost, "/api/v1/reports", adminToken, map[string]any{
				"project": slug, "scanner": "trivy", "raw_data": json.RawMessage(report),
				field: "a" + "\x00" + "b",
			})
			var got refusal
			require.NoError(t, json.Unmarshal(body, &got))

			require.Equal(t, http.StatusBadRequest, status, string(body))
			require.Equal(t, "invalid_field", got.Error.Code)
			require.Contains(t, got.Error.Message, field)
		})
	}
	t.Run("changed_files", func(t *testing.T) {
		status, body := doJSON(t, http.MethodPost, "/api/v1/reports", adminToken, map[string]any{
			"project": slug, "scanner": "trivy", "raw_data": json.RawMessage(report),
			"changed_files": []string{"ok.go", "bad\x00.go"},
		})
		require.Equal(t, http.StatusBadRequest, status, string(body))
		require.Contains(t, string(body), "changed_files")
	})
	require.Empty(t, listFindings(t, slug), "nothing is stored")
}
