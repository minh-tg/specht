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

// grypeImage and grypeDirectory are the source blocks Grype writes for the two
// scans the tests repeat.
var (
	grypeImage     = map[string]any{"type": "image", "target": map[string]any{"userInput": "registry.example.com/app:1.4", "imageID": "sha256:aa"}}
	grypeDirectory = map[string]any{"type": "directory", "target": map[string]any{"userInput": "."}}
)

// grypeDoc builds a Grype report of the given source. A report with matches
// carries file locations, as a real scan does, so the scan scope may not
// depend on them: the same scope has to come out with and without matches.
func grypeDoc(t *testing.T, source map[string]any, vulnerable bool, configuration map[string]any) []byte {
	t.Helper()
	matches := []map[string]any{}
	if vulnerable {
		matches = append(matches, map[string]any{
			"vulnerability": map[string]any{"id": "CVE-2031-1000", "severity": "High", "namespace": "nvd"},
			"artifact": map[string]any{
				"name": "lodash", "version": "4.17.20", "type": "npm", "purl": "pkg:npm/lodash@4.17.20",
				"locations": []map[string]any{{"path": "/app/package-lock.json"}},
			},
			"matchDetails": []map[string]any{{"type": "exact-direct-match"}},
		})
	}
	descriptor := map[string]any{"name": "grype", "version": "0.120.1"}
	if configuration != nil {
		descriptor["configuration"] = configuration
	}
	doc := map[string]any{"matches": matches, "descriptor": descriptor}
	if source != nil {
		doc["source"] = source
	}
	raw, err := json.Marshal(doc)
	require.NoError(t, err)
	return raw
}

func TestGrypeClosesOnlyWhenNoFilterHidMatches(t *testing.T) {
	h, cleanup := newEvidenceHarness(t)
	defer cleanup()
	open := map[string]any{"only-fixed": false, "only-notfixed": false, "ignore": []any{}, "exclude": []any{}}
	cases := []struct {
		name  string
		clean map[string]any
		want  string
	}{
		{"unfiltered", open, "fixed"},
		{"only-fixed set", map[string]any{"only-fixed": true, "only-notfixed": false}, "open"},
		{"user ignore rule", map[string]any{"only-fixed": false, "only-notfixed": false, "ignore": []any{map[string]any{"vulnerability": "CVE-1"}}}, "open"},
		{"no configuration recorded", nil, "open"},
	}
	for i, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			slug := h.project()
			h.ingest(slug, "grype", fmt.Sprintf("aaaa%04d", i), grypeDoc(t, grypeImage, true, open))
			require.Equal(t, "open", h.onlyState(slug))
			h.ingest(slug, "grype", fmt.Sprintf("bbbb%04d", i), grypeDoc(t, grypeImage, false, tc.clean))
			require.Equal(t, tc.want, h.onlyState(slug))
		})
	}
}

// TestGrypeCleanScanClosesOnlyTheSameSource checks the scan scope that ties a
// clean report to the earlier one. The source is the only target a clean
// report has, so it decides whether the rescan counts as the same scan.
func TestGrypeCleanScanClosesOnlyTheSameSource(t *testing.T) {
	h, cleanup := newEvidenceHarness(t)
	defer cleanup()
	open := map[string]any{"only-fixed": false, "only-notfixed": false, "ignore": []any{}, "exclude": []any{}}
	image := func(ref string) map[string]any {
		return map[string]any{"type": "image", "target": map[string]any{"userInput": ref, "imageID": "sha256:bb"}}
	}
	cases := []struct {
		name         string
		first, clean map[string]any
		want         string
	}{
		{"same image", grypeImage, grypeImage, "fixed"},
		{"same image under a new tag", grypeImage, image("registry.example.com/app:1.5"), "fixed"},
		{"same image through a transport prefix", grypeImage, image("docker:registry.example.com/app:1.5"), "fixed"},
		{"another image", grypeImage, image("registry.example.com/other:1.4"), "open"},
		{"same directory", grypeDirectory, grypeDirectory, "fixed"},
		{"image then directory", grypeImage, grypeDirectory, "open"},
		{"directory then image", grypeDirectory, grypeImage, "open"},
	}
	for i, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			slug := h.project()
			h.ingest(slug, "grype", fmt.Sprintf("aaaa%04d", i), grypeDoc(t, tc.first, true, open))
			require.Equal(t, "open", h.onlyState(slug))
			h.ingest(slug, "grype", fmt.Sprintf("bbbb%04d", i), grypeDoc(t, tc.clean, false, open))
			require.Equal(t, tc.want, h.onlyState(slug))
		})
	}
}

// checkovDoc builds a Checkov report. failed and passed are (check id,
// resource, file) triples; quiet leaves passed_checks out the way --quiet does.
func checkovDoc(t *testing.T, failed, passed [][3]string, quiet bool) []byte {
	t.Helper()
	check := func(c [3]string, result string) map[string]any {
		return map[string]any{
			"check_id": c[0], "check_name": c[0] + " name", "resource": c[1], "file_path": c[2],
			"file_line_range": []int{1, 5}, "check_result": map[string]any{"result": result},
		}
	}
	failedChecks, passedChecks := []map[string]any{}, []map[string]any{}
	for _, c := range failed {
		failedChecks = append(failedChecks, check(c, "FAILED"))
	}
	for _, c := range passed {
		passedChecks = append(passedChecks, check(c, "PASSED"))
	}
	results := map[string]any{"failed_checks": failedChecks}
	if !quiet {
		results["passed_checks"] = passedChecks
		results["skipped_checks"] = []any{}
	}
	raw, err := json.Marshal(map[string]any{
		"check_type": "terraform", "results": results,
		"summary": map[string]any{"passed": len(passed), "failed": len(failed), "checkov_version": "3.3.26"},
	})
	require.NoError(t, err)
	return raw
}

func TestCheckovClosesOnlyOnAPassedCheck(t *testing.T) {
	h, cleanup := newEvidenceHarness(t)
	defer cleanup()
	bad := [][3]string{{"CKV_AWS_18", "aws_s3_bucket.a", "/main.tf"}}
	cases := []struct {
		name   string
		passed [][3]string
		quiet  bool
		want   string
	}{
		{"same check, resource and file passed", [][3]string{{"CKV_AWS_18", "aws_s3_bucket.a", "/main.tf"}}, false, "fixed"},
		{"report without passed checks", nil, true, "open"},
		{"passed_checks present but empty", nil, false, "open"},
		{"another resource passed", [][3]string{{"CKV_AWS_18", "aws_s3_bucket.b", "/main.tf"}}, false, "open"},
		{"another check passed", [][3]string{{"CKV_AWS_19", "aws_s3_bucket.a", "/main.tf"}}, false, "open"},
		{"same check and resource in another file", [][3]string{{"CKV_AWS_18", "aws_s3_bucket.a", "/other.tf"}}, false, "open"},
	}
	for i, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			slug := h.project()
			h.ingest(slug, "checkov", fmt.Sprintf("aaaa%04d", i), checkovDoc(t, bad, nil, false))
			require.Equal(t, "open", h.onlyState(slug))
			h.ingest(slug, "checkov", fmt.Sprintf("bbbb%04d", i), checkovDoc(t, nil, tc.passed, tc.quiet))
			require.Equal(t, tc.want, h.onlyState(slug))
		})
	}
}
