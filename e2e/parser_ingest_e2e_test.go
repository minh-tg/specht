//go:build e2e

package e2e

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"testing"

	"github.com/minh-tg/specht/internal/domain"
	"github.com/minh-tg/specht/internal/parser"
	"github.com/minh-tg/specht/internal/scanner"
	"github.com/stretchr/testify/require"
)

// Shapes for report history, finding state, audit events, the context
// tables, auto-fix, and the parser adapters.

type reportRow struct {
	ID            string  `json:"id"`
	ProjectID     string  `json:"project_id"`
	ToolName      string  `json:"tool_name"`
	ScanType      string  `json:"scan_type"`
	ScanTarget    *string `json:"scan_target"`
	Status        string  `json:"status"`
	TotalFindings *int32  `json:"total_findings"`
	Branch        *string `json:"branch"`
	CommitSha     *string `json:"commit_sha"`
	ScanMode      string  `json:"scan_mode"`
	CreatedAt     string  `json:"created_at"`
}

type scanFinding struct {
	ID              string `json:"id"`
	FindingKind     string `json:"finding_kind"`
	CurrentTitle    string `json:"current_title"`
	CurrentSeverity string `json:"current_severity"`
	State           string `json:"state"`
	AnalysisState   string `json:"analysis_state"`
	GateEffect      string `json:"gate_effect"`
}

type auditEvent struct {
	ID        string  `json:"id"`
	EventType string  `json:"event_type"`
	OldValue  *string `json:"old_value,omitempty"`
	NewValue  *string `json:"new_value,omitempty"`
	Changes   string  `json:"changes,omitempty"` // base64-encoded JSON
}

type environmentRow struct {
	ID   string `json:"id"`
	Name string `json:"name"`
	Tier string `json:"tier"`
}

type targetRow struct {
	ID      string `json:"id"`
	Name    string `json:"name"`
	Kind    string `json:"kind"`
	Locator string `json:"locator,omitempty"`
}

type artifactRow struct {
	ID           string `json:"id"`
	TargetID     string `json:"target_id,omitempty"`
	ArtifactType string `json:"artifact_type"`
	Name         string `json:"name"`
	Version      string `json:"version,omitempty"`
}

// listScanFindings returns findings with their technical state — the field
// the auto-fix writer moves to fixed.
func listScanFindings(t *testing.T, slug string) []scanFinding {
	t.Helper()
	return request[[]scanFinding](t, http.MethodGet,
		"/api/v1/projects/"+slug+"/findings?limit=50", adminToken, nil, http.StatusOK)
}

// ingestRaw posts an arbitrary scanner payload (fixtures outside the sarif
// harness helpers).
func ingestRaw(t *testing.T, slug, scanner, fixture string, extra map[string]any) ingestResponse {
	t.Helper()
	return request[ingestResponse](t, http.MethodPost, "/api/v1/reports", adminToken,
		ingestBodyWith(t, slug, fixture, mergeBody(scanner, extra)), http.StatusCreated)
}

// mergeBody overrides the sarif default of ingestBody with the requested
// scanner plus caller-supplied fields.
func mergeBody(scanner string, extra map[string]any) map[string]any {
	body := map[string]any{"scanner": scanner}
	for k, v := range extra {
		body[k] = v
	}
	return body
}

// jsonArrayFixture converts a JSONL fixture into the JSON array the wire
// contract carries (raw_data is one JSON value; the nuclei parser accepts
// "JSON array or JSONL").
func jsonArrayFixture(t *testing.T, fixture string) []json.RawMessage {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("testdata", fixture))
	require.NoError(t, err)
	lines := bytes.Split(bytes.TrimSpace(raw), []byte("\n"))
	events := make([]json.RawMessage, 0, len(lines))
	for _, line := range lines {
		if len(bytes.TrimSpace(line)) == 0 {
			continue
		}
		var probe map[string]any
		require.NoErrorf(t, json.Unmarshal(line, &probe), "fixture line must be JSON: %s", fixture)
		events = append(events, json.RawMessage(line))
	}
	require.NotEmpty(t, events)
	return events
}

type malformedDescriptorScanner struct{}

func (malformedDescriptorScanner) Descriptor() scanner.Descriptor { return scanner.Descriptor{} }
func (malformedDescriptorScanner) DetectFormat([]byte) bool       { return false }
func (malformedDescriptorScanner) Parse(context.Context, []byte) (*domain.NormalizedReport, error) {
	return nil, nil
}

// TestE2E_ParserRegistryDetection pins the parser onboarding matrix: unknown
// data has no match, overlapping adapters are reported as ambiguous, names
// cannot be registered twice, and malformed descriptors are rejected.
func TestE2E_ParserRegistryDetection(t *testing.T) {
	registry := scanner.NewRegistry()
	for _, adapter := range parser.Builtins() {
		require.NoError(t, registry.Register(adapter))
	}

	t.Run("scanner no-match", func(t *testing.T) {
		_, err := registry.Detect([]byte(`{"not":"a scanner report"}`))
		require.ErrorIs(t, err, scanner.ErrNoMatch)
	})
	t.Run("ambiguous-match", func(t *testing.T) {
		_, err := registry.Detect([]byte(`{"version":"2.1.0","runs":[{"tool":{"driver":{"name":"semgrep","version":"1.0.0"}},"results":[]}]}`))
		require.ErrorIs(t, err, scanner.ErrAmbiguousMatch)
	})
	t.Run("duplicate-name rejection", func(t *testing.T) {
		require.ErrorIs(t, registry.Register(parser.Builtins()[0]), scanner.ErrDuplicateName)
	})
	t.Run("malformed descriptor", func(t *testing.T) {
		require.ErrorIs(t, registry.Register(malformedDescriptorScanner{}), scanner.ErrInvalidDescriptor)
	})
}

// TestE2E_BuiltinParserIngest feeds every built-in parser through the real
// ingest API and pins each fixture's finding count and kind as the
// contract of its adapter.
func TestE2E_BuiltinParserIngest(t *testing.T) {
	// want counts distinct persisted findings (fingerprint identity,
	// finding identity); wantReport counts the report's total_findings, which
	// deliberately reflects every normalized entry the scanner emitted —
	// duplicated events stay visible there (pinned by
	// TestNucleiIngest_EndToEnd) while collapsing in the findings list.
	cases := []struct {
		scanner    string
		fixture    string
		want       int
		wantReport int
		wantKind   string
		jsonl      bool // fixture arrives line-delimited; wrap as an array
	}{
		{"trivy", "trivy-alpine-scan.json", 2, 2, "sca", false},
		{"osv-scanner", "osv-go-scan.json", 1, 1, "sca", false},
		{"semgrep", "semgrep-sarif.json", 2, 2, "sast", false},
		{"checkov", "checkov-terraform.json", 3, 3, "iac", false},
		{"dependency-check", "dependency-check.json", 2, 2, "sca", false},
		{"grype", "grype-report.json", 2, 2, "sca", false},
		{"sbom", "sbom-cyclonedx.json", 0, 0, "sca", false},
		{"gitleaks", "gitleaks.json", 3, 3, "secret", false},
		{"tfsec", "tfsec.json", 2, 2, "iac", false},
		// The fixture repeats one event: 3 reported entries, 2 identities.
		{"nuclei", "nuclei.jsonl", 2, 3, "dast", true},
	}
	for _, tc := range cases {
		t.Run(tc.scanner, func(t *testing.T) {
			slug := newProject(t, "parse-"+tc.scanner)
			var extra map[string]any
			if tc.jsonl {
				extra = map[string]any{"raw_data": jsonArrayFixture(t, tc.fixture)}
			}
			resp := ingestRaw(t, slug, tc.scanner, tc.fixture, extra)
			require.Equal(t, "full", resp.ScanMode)
			require.Equal(t, tc.wantReport, resp.TotalFindings,
				"total_findings reflects every reported entry")

			findings := listScanFindings(t, slug)
			require.Equal(t, tc.want, len(findings), "distinct persisted findings")
			for _, f := range findings {
				require.NotEmpty(t, f.CurrentTitle, "every finding carries a title")
				require.NotEmpty(t, f.CurrentSeverity, "every finding carries a severity")
				require.Equal(t, "open", f.State, "fresh findings start open")
				if tc.want > 0 {
					require.Equal(t, tc.wantKind, f.FindingKind, "scanner kind contract")
				}
			}
		})
	}
}

func TestE2E_CapturedReportIngest(t *testing.T) {
	cases := []struct {
		file    string
		scanner string
		kinds   map[string]int
	}{
		{"trivy.json", "trivy", map[string]int{"sca": 3, "iac": 9}},
		{"osv-scanner.json", "osv-scanner", map[string]int{"sca": 2}},
		{"grype.json", "grype", map[string]int{"sca": 2}},
		{"dependency-check.json", "dependency-check", map[string]int{"sca": 4}},
		{"checkov.json", "checkov", map[string]int{"iac": 3}},
		{"tfsec.json", "tfsec", map[string]int{"iac": 3}},
		{"nuclei.json", "nuclei", map[string]int{"dast": 1}},
		{"gitleaks.json", "gitleaks", map[string]int{"secret": 1}},
		{"semgrep.json", "semgrep", map[string]int{"sast": 2}},
		{"codeql.json", "sarif", map[string]int{"sast": 2}},
		{"cyclonedx.json", "sbom", map[string]int{}},
		{"spdx.json", "sbom", map[string]int{}},
	}
	for _, tc := range cases {
		t.Run(tc.file, func(t *testing.T) {
			slug := newProject(t, "captured-"+tc.scanner)
			raw, err := os.ReadFile(filepath.Join("..", "internal", "parser", "testdata", "captured", tc.file))
			require.NoError(t, err)
			body := map[string]any{"project": slug, "scanner": tc.scanner, "raw_data": json.RawMessage(raw)}
			first := request[ingestResponse](t, http.MethodPost, "/api/v1/reports", adminToken, body, http.StatusCreated)
			want := 0
			for _, count := range tc.kinds {
				want += count
			}
			require.Equal(t, want, first.TotalFindings)
			before := listScanFindings(t, slug)
			require.Len(t, before, want)
			kinds := map[string]int{}
			ids := map[string]bool{}
			for _, f := range before {
				kinds[f.FindingKind]++
				ids[f.ID] = true
			}
			require.Equal(t, tc.kinds, kinds)

			// Identical reports are rejected without adding findings.
			request[map[string]any](t, http.MethodPost, "/api/v1/reports", adminToken, body, http.StatusConflict)

			// Change ignored metadata, not scanner observations: a new report
			// must reuse the existing finding identities.
			var document any
			require.NoError(t, json.Unmarshal(raw, &document))
			switch d := document.(type) {
			case map[string]any:
				d["_repeat_capture"] = true
			case []any:
				require.NotEmpty(t, d)
				entry, ok := d[0].(map[string]any)
				require.True(t, ok)
				entry["_repeat_capture"] = true
			default:
				t.Fatal("captured report must be a JSON object or array")
			}
			body["raw_data"] = document
			second := request[ingestResponse](t, http.MethodPost, "/api/v1/reports", adminToken, body, http.StatusCreated)
			require.NotEqual(t, first.ReportID, second.ReportID)
			require.Equal(t, want, second.TotalFindings)
			after := listScanFindings(t, slug)
			require.Len(t, after, want)
			for _, f := range after {
				require.True(t, ids[f.ID], "repeated observations must not create new findings")
				require.Equal(t, "open", f.State)
			}
		})
	}
}

// TestE2E_AutoFixOnEquivalentRescan covers auto-fix on scan equivalence:
// a complete rescan of the same scope that no longer observes a finding
// closes it with a
// state_changed event naming the source report, while a scan whose
// completeness is unknown never closes anything.
func TestE2E_AutoFixOnEquivalentRescan(t *testing.T) {
	t.Run("complete equivalent rescan closes absent findings", func(t *testing.T) {
		slug := newProject(t, "autofix")
		scope := map[string]any{"branch": "main", "commit_sha": baseSHA}

		first := ingestRaw(t, slug, "trivy", "trivy-alpine-scan.json", scope)
		require.Positive(t, first.TotalFindings, "the fixture carries CVEs")
		before := listScanFindings(t, slug)
		require.Len(t, before, int(first.TotalFindings))
		for _, f := range before {
			require.Equal(t, "open", f.State)
		}

		second := ingestRaw(t, slug, "trivy", "trivy-empty-scan.json", scope)
		require.Zero(t, second.TotalFindings, "the follow-up scan observes nothing")

		after := listScanFindings(t, slug)
		require.Len(t, after, len(before), "absence never deletes findings")
		for _, f := range after {
			require.Equal(t, "fixed", f.State,
				"an equivalent complete rescan that omits a finding verifies the fix")
		}

		events := request[[]auditEvent](t, http.MethodGet,
			"/api/v1/findings/"+before[0].ID+"/events", adminToken, nil, http.StatusOK)
		var stateEvents []auditEvent
		for _, e := range events {
			if e.EventType == "state_changed" {
				stateEvents = append(stateEvents, e)
			}
		}
		require.NotEmpty(t, stateEvents, "the closure lands in the audit trail")
		ev := stateEvents[len(stateEvents)-1]
		require.NotNil(t, ev.NewValue)
		require.Equal(t, "fixed", *ev.NewValue)
		decoded, err := base64.StdEncoding.DecodeString(ev.Changes)
		require.NoErrorf(t, err, "changes travels base64-encoded: %s", ev.Changes)
		var changes map[string]any
		require.NoError(t, json.Unmarshal(decoded, &changes))
		require.Equal(t, second.ReportID, changes["report_id"],
			"the event names the verifying report")
	})

	t.Run("unknown-completeness scans never close findings", func(t *testing.T) {
		slug := newProject(t, "autofix-partial")
		first := ingestRaw(t, slug, "sarif", "high.sarif.json", nil)
		require.Positive(t, first.TotalFindings)
		before := listScanFindings(t, slug)

		// Same empty scope fields, different bytes: sarif normalizes to
		// unknown completeness, so the absent finding must stay open.
		ingestRaw(t, slug, "sarif", "medium.sarif.json", nil)

		after := listScanFindings(t, slug)
		byID := map[string]scanFinding{}
		for _, f := range after {
			byID[f.ID] = f
			require.NotEqual(t, "fixed", f.State,
				"a scan that cannot vouch for completeness proves nothing by absence")
		}
		for _, f := range before {
			got, ok := byID[f.ID]
			require.True(t, ok, "absence never deletes findings")
			require.Equal(t, "open", got.State)
		}
	})
}

// TestE2E_ReportHistoryReads covers project-scoped report history
// with pagination, single-report reads, and existence hiding for foreign
// keys.
func TestE2E_ReportHistoryReads(t *testing.T) {
	slug := newProject(t, "report-history")
	trivyReport := ingestRaw(t, slug, "trivy", "trivy-alpine-scan.json", nil)
	sarifReport := ingestFixture(t, slug, adminToken, "high.sarif.json")

	reports := request[[]reportRow](t, http.MethodGet,
		"/api/v1/projects/"+slug+"/reports", adminToken, nil, http.StatusOK)
	require.GreaterOrEqual(t, len(reports), 2)
	byID := map[string]reportRow{}
	for _, r := range reports {
		byID[r.ID] = r
		require.Equal(t, "completed", r.Status)
		require.NotNil(t, r.TotalFindings)
		require.NotEmpty(t, r.ScanMode)
	}
	require.Contains(t, byID, trivyReport.ReportID)
	require.Contains(t, byID, sarifReport.ReportID)
	require.Equal(t, "trivy", byID[trivyReport.ReportID].ToolName)
	require.Equal(t, "sarif", byID[sarifReport.ReportID].ToolName)

	one := request[[]reportRow](t, http.MethodGet,
		"/api/v1/projects/"+slug+"/reports?limit=1", adminToken, nil, http.StatusOK)
	require.Len(t, one, 1, "offset pagination honors the limit")

	detail := request[reportRow](t, http.MethodGet,
		"/api/v1/reports/"+trivyReport.ReportID, adminToken, nil, http.StatusOK)
	require.Equal(t, trivyReport.ReportID, detail.ID)
	require.Equal(t, "trivy", detail.ToolName)
	require.Equal(t, "completed", detail.Status)
	require.EqualValues(t, trivyReport.TotalFindings, *detail.TotalFindings)

	status, raw := doJSON(t, http.MethodGet, "/api/v1/reports/"+randomHex(16), adminToken, nil)
	require.Equal(t, http.StatusNotFound, status, string(raw))

	// A project key reads its own history but cannot learn whether another
	// project's report exists.
	key := mintKey(t, slug)
	status, raw = doJSON(t, http.MethodGet, "/api/v1/reports/"+trivyReport.ReportID, key, nil)
	require.Equal(t, http.StatusOK, status, string(raw))

	other := newProject(t, "report-foreign")
	foreign := ingestRaw(t, other, "trivy", "trivy-empty-scan.json", nil)
	status, raw = doJSON(t, http.MethodGet, "/api/v1/reports/"+foreign.ReportID, key, nil)
	require.Equal(t, http.StatusNotFound, status, string(raw),
		"a foreign report id must be indistinguishable from a missing one")
}

// TestE2E_ContextTablesReads covers the context tables:
// ingest-supplied deployment
// context materializes the environment, target, and artifact tables and
// the read routes expose them.
func TestE2E_ContextTablesReads(t *testing.T) {
	slug := newProject(t, "context-tables")
	ingestRaw(t, slug, "trivy", "trivy-alpine-scan.json", map[string]any{
		"branch":           "main",
		"commit_sha":       baseSHA,
		"environment":      "production",
		"artifact_name":    "alpine:3.20",
		"artifact_version": "3.20.3",
		"artifact_type":    "container_image",
		"owner":            "github://minh/specht",
	})

	environments := request[[]environmentRow](t, http.MethodGet,
		"/api/v1/projects/"+slug+"/environments", adminToken, nil, http.StatusOK)
	var envNames []string
	for _, e := range environments {
		envNames = append(envNames, e.Name)
	}
	require.Contains(t, envNames, "production", "environment resolves at ingest")

	artifacts := request[[]artifactRow](t, http.MethodGet,
		"/api/v1/projects/"+slug+"/artifacts", adminToken, nil, http.StatusOK)
	require.Len(t, artifacts, 1, "one scanned artifact row")
	require.Equal(t, "alpine:3.20", artifacts[0].Name)
	require.Equal(t, "3.20.3", artifacts[0].Version)
	require.Equal(t, "container_image", artifacts[0].ArtifactType)

	targets := request[[]targetRow](t, http.MethodGet,
		"/api/v1/projects/"+slug+"/targets", adminToken, nil, http.StatusOK)
	require.NotEmpty(t, targets, "the scan target materializes")
	require.NotEmpty(t, targets[0].Name)
	require.NotEmpty(t, targets[0].Kind)
	require.Equal(t, artifacts[0].TargetID, targets[0].ID,
		"the artifact hangs off the scanned target")
}
