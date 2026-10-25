//go:build integration

package repo

import (
	"context"
	"encoding/json"
	"fmt"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/require"

	"github.com/minh-tg/specht/internal/parser"
	"github.com/minh-tg/specht/internal/port"
	"github.com/minh-tg/specht/internal/scanner"
	"github.com/minh-tg/specht/internal/usecase"
)

// evidenceHarness ingests real scanner documents through the full use case,
// one project per scenario so the scenarios share a database.
type evidenceHarness struct {
	t      *testing.T
	ctx    context.Context
	pool   *pgxpool.Pool
	stores *port.Stores
	uc     *usecase.Usecases
	n      int
}

func newEvidenceHarness(t *testing.T) (*evidenceHarness, func()) {
	t.Helper()
	pool, cleanup := setupIngestPool(t)
	stores := NewPortStores(pool)
	registry := scanner.NewRegistry()
	for _, sc := range parser.Builtins() {
		require.NoError(t, registry.Register(sc))
	}
	return &evidenceHarness{
		t: t, ctx: context.Background(), pool: pool, stores: stores,
		uc: usecase.New(usecase.Deps{Stores: stores, Registry: registry}),
	}, cleanup
}

// project creates a fresh project and returns its slug.
func (h *evidenceHarness) project() string {
	h.t.Helper()
	h.n++
	slug := fmt.Sprintf("evidence-%d", h.n)
	_, err := h.stores.Projects.Create(h.ctx, port.CreateProjectInput{Slug: slug, Name: slug, DeploymentThreshold: "high", Settings: []byte(`{}`)})
	require.NoError(h.t, err)
	return slug
}

func (h *evidenceHarness) ingest(slug, scannerName, commit string, raw []byte) *usecase.IngestReportOutput {
	h.t.Helper()
	out, err := h.uc.IngestReport(h.ctx, usecase.IngestReportInput{
		ProjectSlug: slug, Scanner: scannerName, Branch: "main", CommitSha: commit, RawData: raw,
	})
	require.NoError(h.t, err)
	return out
}

// states returns the state of every finding of the project, by fingerprint.
func (h *evidenceHarness) states(slug string) map[string]string {
	h.t.Helper()
	rows, err := h.pool.Query(h.ctx, `SELECT f.fingerprint, f.state FROM findings f JOIN projects p ON p.id = f.project_id WHERE p.slug = $1`, slug)
	require.NoError(h.t, err)
	defer rows.Close()
	out := map[string]string{}
	for rows.Next() {
		var fp, state string
		require.NoError(h.t, rows.Scan(&fp, &state))
		out[fp] = state
	}
	require.NoError(h.t, rows.Err())
	return out
}

func (h *evidenceHarness) onlyState(slug string) string {
	h.t.Helper()
	states := h.states(slug)
	require.Len(h.t, states, 1)
	for _, s := range states {
		return s
	}
	return ""
}

// sarifDoc builds a SARIF log with one run. rules are the rule ids the run
// lists, hits the (rule, file) results it reports, files the artifacts it
// lists, and extra extra keys merged into the run.
func sarifDoc(t *testing.T, driver string, rules []string, hits [][2]string, files []string, extra map[string]any) []byte {
	t.Helper()
	ruleDocs := []map[string]any{}
	for _, r := range rules {
		ruleDocs = append(ruleDocs, map[string]any{"id": r, "shortDescription": map[string]any{"text": r}})
	}
	results := []map[string]any{}
	for _, h := range hits {
		results = append(results, map[string]any{
			"ruleId": h[0], "level": "error", "message": map[string]any{"text": h[0] + " in " + h[1]},
			"locations": []map[string]any{{"physicalLocation": map[string]any{
				"artifactLocation": map[string]any{"uri": h[1]}, "region": map[string]any{"startLine": 3},
			}}},
		})
	}
	run := map[string]any{
		"tool":    map[string]any{"driver": map[string]any{"name": driver, "rules": ruleDocs}},
		"results": results,
	}
	if len(files) > 0 {
		artifacts := []map[string]any{}
		for _, f := range files {
			artifacts = append(artifacts, map[string]any{"location": map[string]any{"uri": f}})
		}
		run["artifacts"] = artifacts
	}
	for k, v := range extra {
		run[k] = v
	}
	raw, err := json.Marshal(map[string]any{"version": "2.1.0", "runs": []any{run}})
	require.NoError(t, err)
	return raw
}

func TestSARIFRuleListClosesAbsentFindings(t *testing.T) {
	h, cleanup := newEvidenceHarness(t)
	defer cleanup()
	hit := [][2]string{{"go/sql-injection", "pkg/db.go"}}
	cases := []struct {
		name    string
		scanner string
		driver  string
		clean   func() []byte
		want    string
	}{
		{
			"semgrep, rule listed", "semgrep", "Semgrep OSS",
			func() []byte {
				return sarifDoc(t, "Semgrep OSS", []string{"go/sql-injection", "go/xss"}, nil, nil, nil)
			}, "fixed",
		},
		{
			"semgrep, rule not listed", "semgrep", "Semgrep OSS",
			func() []byte { return sarifDoc(t, "Semgrep OSS", []string{"go/xss"}, nil, nil, nil) }, "open",
		},
		{
			"semgrep, run failed", "semgrep", "Semgrep OSS",
			func() []byte {
				return sarifDoc(t, "Semgrep OSS", []string{"go/sql-injection"}, nil, nil,
					map[string]any{"invocations": []map[string]any{{"executionSuccessful": false}}})
			}, "open",
		},
		{
			"sarif, rule listed, no file list", "sarif", "CodeQL",
			func() []byte { return sarifDoc(t, "CodeQL", []string{"go/sql-injection"}, nil, nil, nil) }, "fixed",
		},
		{
			"sarif, rule listed, file scanned", "sarif", "CodeQL",
			func() []byte {
				return sarifDoc(t, "CodeQL", []string{"go/sql-injection"}, nil, []string{"pkg/db.go", "pkg/other.go"}, nil)
			}, "fixed",
		},
		{
			"sarif, rule listed, file not scanned", "sarif", "CodeQL",
			func() []byte {
				return sarifDoc(t, "CodeQL", []string{"go/sql-injection"}, nil, []string{"pkg/other.go"}, nil)
			}, "open",
		},
		{
			"sarif, rule not listed", "sarif", "CodeQL",
			func() []byte { return sarifDoc(t, "CodeQL", []string{"go/xss"}, nil, []string{"pkg/db.go"}, nil) }, "open",
		},
		{
			"sarif, error notification", "sarif", "CodeQL",
			func() []byte {
				return sarifDoc(t, "CodeQL", []string{"go/sql-injection"}, nil, []string{"pkg/db.go"},
					map[string]any{"invocations": []map[string]any{{"executionSuccessful": true, "toolExecutionNotifications": []map[string]any{{"level": "error"}}}}})
			}, "open",
		},
		{
			"sarif, finding suppressed in the producer", "sarif", "CodeQL",
			func() []byte {
				raw := sarifDoc(t, "CodeQL", []string{"go/sql-injection"}, hit, nil, nil)
				var doc map[string]any
				require.NoError(t, json.Unmarshal(raw, &doc))
				run := doc["runs"].([]any)[0].(map[string]any)
				for _, r := range run["results"].([]any) {
					r.(map[string]any)["suppressions"] = []map[string]any{{"kind": "inSource", "status": "accepted"}}
				}
				out, err := json.Marshal(doc)
				require.NoError(t, err)
				return out
			}, "open",
		},
	}
	for i, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			slug := h.project()
			h.ingest(slug, tc.scanner, fmt.Sprintf("aaaa%04d", i), sarifDoc(t, tc.driver, []string{"go/sql-injection"}, hit, nil, nil))
			require.Equal(t, "open", h.onlyState(slug))
			h.ingest(slug, tc.scanner, fmt.Sprintf("bbbb%04d", i), tc.clean())
			require.Equal(t, tc.want, h.onlyState(slug))
		})
	}
}

func TestSARIFReportWithoutRuleListClosesNothing(t *testing.T) {
	h, cleanup := newEvidenceHarness(t)
	defer cleanup()
	slug := h.project()
	hit := [][2]string{{"go/sql-injection", "pkg/db.go"}}
	h.ingest(slug, "sarif", "aaaa0001", sarifDoc(t, "Gosec", []string{"go/sql-injection"}, hit, nil, nil))
	h.ingest(slug, "sarif", "bbbb0001", sarifDoc(t, "Gosec", nil, nil, nil, nil))
	require.Equal(t, "open", h.onlyState(slug))
}
