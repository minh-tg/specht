//go:build integration

package repo

import (
	"encoding/json"
	"fmt"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/minh-tg/specht/internal/usecase"
)

// verifyAfter ingests a scan with one finding, then the clean scan, and asks
// VerifyFix about the finding. Ingest-time auto-fix may already have closed it,
// so a closed finding is put back to open first: the analyst check must reach
// its verdict from the stored report, not from what auto-fix did.
func (h *evidenceHarness) verifyAfter(slug string) (*usecase.VerifyResponse, string) {
	h.t.Helper()
	var id string
	require.NoError(h.t, h.pool.QueryRow(h.ctx,
		`SELECT f.id FROM findings f JOIN projects p ON p.id = f.project_id WHERE p.slug = $1`, slug).Scan(&id))
	_, err := h.pool.Exec(h.ctx, `UPDATE findings SET state = 'open' WHERE id = $1`, id)
	require.NoError(h.t, err)
	user, err := h.stores.Users.Create(h.ctx, fmt.Sprintf("verify-%s@example.com", slug), nil, nil)
	require.NoError(h.t, err)
	resp, err := h.uc.VerifyFix(globalAdminCtx(user.ID), id)
	require.NoError(h.t, err)
	return resp, h.onlyState(slug)
}

func TestVerifyFixHonoursExaminedKeys(t *testing.T) {
	h, cleanup := newEvidenceHarness(t)
	defer cleanup()
	hit := [][2]string{{"go/sql-injection", "pkg/db.go"}}
	suppressed := func() []byte {
		var doc map[string]any
		require.NoError(t, json.Unmarshal(sarifDoc(t, "CodeQL", []string{"go/sql-injection"}, hit, []string{"pkg/db.go"}, nil), &doc))
		run := doc["runs"].([]any)[0].(map[string]any)
		for _, r := range run["results"].([]any) {
			r.(map[string]any)["suppressions"] = []map[string]any{{"kind": "inSource", "status": "accepted"}}
		}
		out, err := json.Marshal(doc)
		require.NoError(t, err)
		return out
	}
	cases := []struct {
		name    string
		scanner string
		first   []byte
		clean   []byte
		outcome string
		state   string
	}{
		{
			"semgrep rule listed, no file list", "semgrep",
			sarifDoc(t, "Semgrep OSS", []string{"go/sql-injection"}, hit, nil, nil),
			sarifDoc(t, "Semgrep OSS", []string{"go/sql-injection", "go/xss"}, nil, nil, nil),
			usecase.VerifyInconclusive, "open",
		},
		{
			"semgrep rule listed and file scanned", "semgrep",
			sarifDoc(t, "Semgrep OSS", []string{"go/sql-injection"}, hit, nil, nil),
			sarifDoc(t, "Semgrep OSS", []string{"go/sql-injection", "go/xss"}, nil, []string{"pkg/db.go"}, nil),
			usecase.VerifyFixed, "fixed",
		},
		{
			"sarif rule listed and file scanned", "sarif",
			sarifDoc(t, "CodeQL", []string{"go/sql-injection"}, hit, nil, nil),
			sarifDoc(t, "CodeQL", []string{"go/sql-injection"}, nil, []string{"pkg/db.go"}, nil),
			usecase.VerifyFixed, "fixed",
		},
		{
			"sarif rule not listed", "sarif",
			sarifDoc(t, "CodeQL", []string{"go/sql-injection"}, hit, nil, nil),
			sarifDoc(t, "CodeQL", []string{"go/xss"}, nil, []string{"pkg/db.go"}, nil),
			usecase.VerifyInconclusive, "open",
		},
		{
			"sarif rule listed, file not scanned", "sarif",
			sarifDoc(t, "CodeQL", []string{"go/sql-injection"}, hit, nil, nil),
			sarifDoc(t, "CodeQL", []string{"go/sql-injection"}, nil, []string{"pkg/other.go"}, nil),
			usecase.VerifyInconclusive, "open",
		},
		{
			"sarif rule listed by a run that never scanned the file", "sarif",
			sarifDoc(t, "CodeQL", []string{"go/sql-injection"}, hit, nil, nil),
			mergeRuns(t,
				sarifDoc(t, "CodeQL", []string{"go/sql-injection"}, nil, []string{"pkg/other.go"}, nil),
				sarifDoc(t, "CodeQL", []string{"go/xss"}, nil, []string{"pkg/db.go"}, nil)),
			usecase.VerifyInconclusive, "open",
		},
		{
			"sarif run failed", "sarif",
			sarifDoc(t, "CodeQL", []string{"go/sql-injection"}, hit, nil, nil),
			sarifDoc(t, "CodeQL", []string{"go/sql-injection"}, nil, []string{"pkg/db.go"},
				map[string]any{"invocations": []map[string]any{{"executionSuccessful": false}}}),
			usecase.VerifyInconclusive, "open",
		},
		{
			"sarif result suppressed", "sarif",
			sarifDoc(t, "CodeQL", []string{"go/sql-injection"}, hit, nil, nil),
			suppressed(),
			usecase.VerifyInconclusive, "open",
		},
		{
			"sarif without a rule list", "sarif",
			sarifDoc(t, "Gosec", []string{"go/sql-injection"}, hit, nil, nil),
			sarifDoc(t, "Gosec", nil, nil, nil, nil),
			usecase.VerifyInconclusive, "open",
		},
		{
			"checkov passed check", "checkov",
			checkovDoc(t, [][3]string{{"CKV_AWS_18", "aws_s3_bucket.a", "/main.tf"}}, nil, false),
			checkovDoc(t, nil, [][3]string{{"CKV_AWS_18", "aws_s3_bucket.a", "/main.tf"}}, false),
			usecase.VerifyFixed, "fixed",
		},
		{
			"checkov check passed for another resource", "checkov",
			checkovDoc(t, [][3]string{{"CKV_AWS_18", "aws_s3_bucket.a", "/main.tf"}}, nil, false),
			checkovDoc(t, nil, [][3]string{{"CKV_AWS_18", "aws_s3_bucket.b", "/main.tf"}}, false),
			usecase.VerifyInconclusive, "open",
		},
		{
			"checkov quiet run", "checkov",
			checkovDoc(t, [][3]string{{"CKV_AWS_18", "aws_s3_bucket.a", "/main.tf"}}, nil, false),
			checkovDoc(t, nil, nil, true),
			usecase.VerifyInconclusive, "open",
		},
	}
	for i, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			slug := h.project()
			h.ingest(slug, tc.scanner, fmt.Sprintf("aaaa%04d", i), tc.first)
			h.ingest(slug, tc.scanner, fmt.Sprintf("bbbb%04d", i), tc.clean)
			resp, state := h.verifyAfter(slug)
			assert.Equal(t, tc.outcome, resp.Outcome, resp.Detail)
			assert.Equal(t, tc.state, state)
			if tc.outcome == usecase.VerifyFixed {
				var events int
				require.NoError(t, h.pool.QueryRow(h.ctx,
					`SELECT count(*) FROM finding_events e JOIN findings f ON f.id = e.finding_id JOIN projects p ON p.id = f.project_id WHERE p.slug = $1 AND e.event_type = 'verified_fixed'`, slug).Scan(&events))
				assert.Equal(t, 1, events)
			}
		})
	}
}

// TestVerifyFixTrivyCompleteScanUnchanged keeps the complete-scan path: a
// Trivy report has no examined keys and verifies through its completeness.
func TestVerifyFixTrivyCompleteScanUnchanged(t *testing.T) {
	h, cleanup := newEvidenceHarness(t)
	defer cleanup()
	raw, err := os.ReadFile("../parser/trivy/testdata/multi-type-scan.json")
	require.NoError(t, err)
	clean, err := rewriteTrivyReport(raw, func(results []map[string]any) {
		for _, r := range results {
			if class, _ := r["Class"].(string); class == "lang-pkgs" {
				r["Vulnerabilities"] = []any{}
			}
		}
	})
	require.NoError(t, err)
	slug := h.project()
	h.ingest(slug, "trivy", "aaaa0001", raw)
	h.ingest(slug, "trivy", "bbbb0001", clean)

	var id string
	require.NoError(t, h.pool.QueryRow(h.ctx,
		`SELECT f.id FROM findings f JOIN projects p ON p.id = f.project_id WHERE p.slug = $1 AND f.fingerprint LIKE '%lodash%'`, slug).Scan(&id))
	_, err = h.pool.Exec(h.ctx, `UPDATE findings SET state = 'open' WHERE id = $1`, id)
	require.NoError(t, err)
	user, err := h.stores.Users.Create(h.ctx, "verify-trivy@example.com", nil, nil)
	require.NoError(t, err)
	resp, err := h.uc.VerifyFix(globalAdminCtx(user.ID), id)
	require.NoError(t, err)
	assert.Equal(t, usecase.VerifyFixed, resp.Outcome, resp.Detail)
}
