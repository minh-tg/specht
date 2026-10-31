//go:build integration

package repo

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/minh-tg/specht/internal/db"
	"github.com/minh-tg/specht/internal/domain"
	"github.com/minh-tg/specht/internal/parser"
	"github.com/minh-tg/specht/internal/port"
	"github.com/minh-tg/specht/internal/scanner"
	"github.com/minh-tg/specht/internal/usecase"
)

// filterScenario is one scan scope that saw two open findings in an earlier
// full scan. Tests then ingest a complete report that omits both and see which
// of them it closes.
type filterScenario struct {
	ctx       context.Context
	pool      *pgxpool.Pool
	stores    *port.Stores
	projectID string
	ids       map[string]string
}

type seeded struct {
	fingerprint string
	severity    string
	rank        int16
	fixedIn     string
}

func newFilterScenario(t *testing.T, findings ...seeded) (*filterScenario, func()) {
	t.Helper()
	pool, cleanup := setupIngestPool(t)
	ctx := context.Background()
	stores := NewPortStores(pool)
	project, err := stores.Projects.Create(ctx, port.CreateProjectInput{
		Slug: "scan-filter", Name: "Scan Filter", DeploymentThreshold: "high", Settings: []byte("{}"),
	})
	require.NoError(t, err)
	s := &filterScenario{ctx: ctx, pool: pool, stores: stores, projectID: project.ID, ids: map[string]string{}}

	observed := time.Now().Add(-time.Hour)
	first, err := stores.Reports.Create(ctx, port.CreateReportInput{
		ProjectID: project.ID, ToolName: "trivy", ScanType: "image", ScanScopeHash: "main",
		ScanScope: []byte(`{}`), RawReportHash: "first", ScanMode: "full",
		ScanCompleteness: "complete", CoveredFindingKinds: []string{"sca"},
	})
	require.NoError(t, err)
	_, err = stores.Reports.UpdateStatus(ctx, first.ID, project.ID, "completed", int32(len(findings)), nil)
	require.NoError(t, err)
	for _, f := range findings {
		row, err := stores.Findings.Upsert(ctx, port.UpsertFindingInput{
			ProjectID: project.ID, FindingKind: "sca", Fingerprint: f.fingerprint, Title: f.fingerprint,
			Severity: f.severity, SeverityRank: f.rank, Score: 5, FirstSeen: observed, LastSeen: observed,
			Scope: &port.FindingScopeSeverityInput{
				ScopeHash: "main", Severity: f.severity, SeverityRank: f.rank,
				ReportID: first.ID, ObservedAt: observed,
			},
		})
		require.NoError(t, err)
		s.ids[f.fingerprint] = row.ID
		id := first.ID
		_, err = stores.Findings.CreateOccurrence(ctx, port.OccurrenceInput{
			FindingID: row.ID, ReportID: &id, Title: f.fingerprint, Severity: f.severity,
			SeverityRank: f.rank, ToolName: "trivy", ObservedAt: observed,
			Display: []byte(`{}`), Metadata: []byte(`{}`),
		})
		require.NoError(t, err)
		if f.fixedIn != "" {
			_, err = pool.Exec(ctx, `INSERT INTO finding_dimensions (finding_id, dim_key, dim_value) VALUES ($1, 'fixed_version', $2)`, row.ID, f.fixedIn)
			require.NoError(t, err)
		}
	}
	return s, cleanup
}

// scan stores a completed full Trivy-like report of the scope that lists no
// finding, with the given filter.
func (s *filterScenario) scan(t *testing.T, hash string, severities []string, fixableOnly bool) string {
	t.Helper()
	r, err := s.stores.Reports.Create(s.ctx, port.CreateReportInput{
		ProjectID: s.projectID, ToolName: "trivy", ScanType: "image", ScanScopeHash: "main",
		ScanScope: []byte(`{}`), RawReportHash: hash, ScanMode: "full",
		ScanCompleteness: "complete", CoveredFindingKinds: []string{"sca"},
		FilterSeverities: severities, FilterFixableOnly: fixableOnly,
	})
	require.NoError(t, err)
	_, err = s.stores.Reports.UpdateStatus(s.ctx, r.ID, s.projectID, "completed", 0, nil)
	require.NoError(t, err)
	return r.ID
}

func (s *filterScenario) state(t *testing.T, fingerprint string) string {
	t.Helper()
	f, err := s.stores.Findings.GetByID(s.ctx, s.ids[fingerprint])
	require.NoError(t, err)
	return f.State
}

func (s *filterScenario) scopeRows(t *testing.T, fingerprint string) int {
	t.Helper()
	rows, err := s.stores.Findings.ListScopeSeverities(s.ctx, []string{s.ids[fingerprint]})
	require.NoError(t, err)
	return len(rows)
}

func TestScanFilterSeverityClosesOnlyFindingsInTheFilter(t *testing.T) {
	s, cleanup := newFilterScenario(t,
		seeded{fingerprint: "low-1", severity: "low", rank: 1},
		seeded{fingerprint: "high-1", severity: "high", rank: 3},
	)
	defer cleanup()
	filtered := s.scan(t, "filtered", []string{"high", "critical"}, false)

	fixed, err := s.stores.Findings.MarkAbsentFindingsFixed(s.ctx, s.projectID, "main", filtered)
	require.NoError(t, err)

	require.Len(t, fixed, 1)
	assert.Equal(t, s.ids["high-1"], fixed[0].ID)
	assert.Equal(t, "fixed", s.state(t, "high-1"))
	assert.Equal(t, "open", s.state(t, "low-1"), "a HIGH,CRITICAL scan says nothing about a low finding")
	assert.Equal(t, 1, s.scopeRows(t, "low-1"), "the low finding keeps its scope evidence")
	assert.Zero(t, s.scopeRows(t, "high-1"))
}

func TestScanFilterFixableOnlyClosesOnlyFindingsWithAFix(t *testing.T) {
	s, cleanup := newFilterScenario(t,
		seeded{fingerprint: "fixable", severity: "medium", rank: 2, fixedIn: "1.2.3"},
		seeded{fingerprint: "unfixed", severity: "medium", rank: 2},
		seeded{fingerprint: "blank-fix", severity: "medium", rank: 2, fixedIn: ""},
	)
	defer cleanup()
	filtered := s.scan(t, "filtered", nil, true)

	fixed, err := s.stores.Findings.MarkAbsentFindingsFixed(s.ctx, s.projectID, "main", filtered)
	require.NoError(t, err)

	require.Len(t, fixed, 1)
	assert.Equal(t, "fixed", s.state(t, "fixable"))
	assert.Equal(t, "open", s.state(t, "unfixed"), "--ignore-unfixed hides it, so absence proves nothing")
	assert.Equal(t, "open", s.state(t, "blank-fix"))
}

func TestScanFilterSeverityAndFixableOnlyBothApply(t *testing.T) {
	s, cleanup := newFilterScenario(t,
		seeded{fingerprint: "high-fixable", severity: "high", rank: 3, fixedIn: "2.0"},
		seeded{fingerprint: "high-unfixed", severity: "high", rank: 3},
		seeded{fingerprint: "low-fixable", severity: "low", rank: 1, fixedIn: "2.0"},
	)
	defer cleanup()
	filtered := s.scan(t, "filtered", []string{"high"}, true)

	fixed, err := s.stores.Findings.MarkAbsentFindingsFixed(s.ctx, s.projectID, "main", filtered)
	require.NoError(t, err)

	require.Len(t, fixed, 1)
	assert.Equal(t, "fixed", s.state(t, "high-fixable"))
	assert.Equal(t, "open", s.state(t, "high-unfixed"))
	assert.Equal(t, "open", s.state(t, "low-fixable"))
}

func TestScanFilterUnfilteredReportStillClosesEverything(t *testing.T) {
	s, cleanup := newFilterScenario(t,
		seeded{fingerprint: "low-1", severity: "low", rank: 1},
		seeded{fingerprint: "high-1", severity: "high", rank: 3},
	)
	defer cleanup()
	unfiltered := s.scan(t, "unfiltered", nil, false)

	fixed, err := s.stores.Findings.MarkAbsentFindingsFixed(s.ctx, s.projectID, "main", unfiltered)
	require.NoError(t, err)

	assert.Len(t, fixed, 2)
	assert.Equal(t, "fixed", s.state(t, "low-1"))
	assert.Equal(t, "fixed", s.state(t, "high-1"))
}

func TestScanFilterVerifyRefusesAFindingOutsideTheFilter(t *testing.T) {
	s, cleanup := newFilterScenario(t,
		seeded{fingerprint: "low-1", severity: "low", rank: 1},
		seeded{fingerprint: "high-1", severity: "high", rank: 3},
	)
	defer cleanup()
	basis := s.scan(t, "filtered", []string{"high", "critical"}, false)

	_, err := s.stores.Findings.MarkFixedWithEvent(s.ctx, s.ids["low-1"], basis, port.FindingEventInput{FindingID: s.ids["low-1"], EventType: "verified_fixed"})
	require.ErrorIs(t, err, port.ErrFindingStillObserved, "complete is not enough for a filtered report")
	assert.Equal(t, "open", s.state(t, "low-1"))
	assert.Equal(t, 1, s.scopeRows(t, "low-1"))

	_, err = s.stores.Findings.MarkFixedWithEvent(s.ctx, s.ids["high-1"], basis, port.FindingEventInput{FindingID: s.ids["high-1"], EventType: "verified_fixed"})
	require.NoError(t, err)
	assert.Equal(t, "fixed", s.state(t, "high-1"))
}

func TestScanFilterVerifyFixAnswersInconclusiveOutsideTheFilter(t *testing.T) {
	s, cleanup := newFilterScenario(t,
		seeded{fingerprint: "low-1", severity: "low", rank: 1},
		seeded{fingerprint: "high-1", severity: "high", rank: 3},
	)
	defer cleanup()
	s.scan(t, "filtered", []string{"high", "critical"}, false)
	user, err := s.stores.Users.Create(s.ctx, "verifier@example.test", nil, nil)
	require.NoError(t, err)
	u := usecase.New(usecase.Deps{Stores: s.stores})

	low, err := u.VerifyFix(globalAdminCtx(user.ID), s.ids["low-1"])
	require.NoError(t, err)
	assert.Equal(t, usecase.VerifyInconclusive, low.Outcome)
	assert.Equal(t, "open", s.state(t, "low-1"))

	high, err := u.VerifyFix(globalAdminCtx(user.ID), s.ids["high-1"])
	require.NoError(t, err)
	assert.Equal(t, usecase.VerifyFixed, high.Outcome)
	assert.Equal(t, "fixed", s.state(t, "high-1"))
}

// The severity a filter is tested against is the one the report's own scope
// holds, and the finding's current severity when that scope has no row.
func TestReportExaminedFindingScanFilter(t *testing.T) {
	s, cleanup := newFilterScenario(t,
		seeded{fingerprint: "high-1", severity: "high", rank: 3, fixedIn: "1.0"},
	)
	defer cleanup()
	id := s.ids["high-1"]
	ask := func(scope string, severities []string, fixableOnly bool) bool {
		t.Helper()
		var sev any
		if severities != nil {
			sev = severities
		}
		var got bool
		require.NoError(t, s.pool.QueryRow(s.ctx,
			`SELECT report_examined_finding('complete', ARRAY['sca'], NULL::text[], $1::text[], $2::boolean, $3::text, $4::uuid, 'sca', 'high-1')`,
			sev, fixableOnly, scope, id).Scan(&got))
		return got
	}

	assert.True(t, ask("main", nil, false), "no filter")
	assert.True(t, ask("main", []string{"high"}, false))
	assert.False(t, ask("main", []string{"low", "medium", "critical"}, false))
	assert.True(t, ask("main", []string{"high"}, true))

	// Another scope has no row for the finding: its current severity decides.
	assert.True(t, ask("other", []string{"high"}, false))
	assert.False(t, ask("other", []string{"low"}, false))

	// The scope row wins over a stale current severity.
	_, err := s.pool.Exec(s.ctx, `UPDATE finding_scope_severities SET severity = 'medium', severity_rank = 2 WHERE finding_id = $1`, id)
	require.NoError(t, err)
	assert.False(t, ask("main", []string{"high"}, false), "the scope says medium")
	assert.True(t, ask("main", []string{"medium"}, false))

	_, err = s.pool.Exec(s.ctx, `DELETE FROM finding_dimensions WHERE finding_id = $1`, id)
	require.NoError(t, err)
	assert.False(t, ask("main", []string{"medium"}, true), "no fixed_version dimension")
	assert.True(t, ask("main", []string{"medium"}, false))
}

func TestReportsFilterSeveritiesCheckRejectsUnknownValues(t *testing.T) {
	s, cleanup := newFilterScenario(t)
	defer cleanup()
	insert := func(severities []string) error {
		_, err := s.pool.Exec(s.ctx,
			`INSERT INTO reports (project_id, tool_name, scan_type, status, filter_severities) VALUES ($1, 'trivy', 'image', 'processing', $2::text[])`,
			s.projectID, severities)
		return err
	}
	require.NoError(t, insert([]string{"high", "critical"}))
	for _, bad := range [][]string{{"severe"}, {"HIGH"}, {}} {
		require.Error(t, insert(bad), "%v", bad)
	}
}

// The 000067 down migration puts the six-argument examined test back and drops the
// filter columns; applying it again restores the nine-argument one.
func TestScanFilterMigrationRollbackRestoresTheOldFunction(t *testing.T) {
	repos, cleanup := setupTestDB(t)
	defer cleanup()
	ctx := context.Background()
	dsn := repos.pool.Config().ConnString()
	has := func(signature string) bool {
		var ok bool
		require.NoError(t, repos.pool.QueryRow(ctx, `SELECT to_regprocedure($1) IS NOT NULL`, signature).Scan(&ok))
		return ok
	}
	const oldSig = "report_examined_finding(text,text[],text[],uuid,text,text)"
	const newSig = "report_examined_finding(text,text[],text[],text[],boolean,text,uuid,text,text)"
	require.True(t, has(newSig))
	require.False(t, has(oldSig))

	// Roll back to just below 000067, however many migrations came after it.
	for {
		var version int
		require.NoError(t, repos.pool.QueryRow(ctx, `SELECT version FROM schema_migrations`).Scan(&version))
		if version < 67 {
			break
		}
		require.NoError(t, db.RollbackMigrations(dsn, "../../migrations"))
	}
	assert.True(t, has(oldSig))
	assert.False(t, has(newSig))
	var columns int
	require.NoError(t, repos.pool.QueryRow(ctx,
		`SELECT count(*) FROM information_schema.columns WHERE table_name = 'reports' AND column_name IN ('filter_severities', 'filter_fixable_only')`).Scan(&columns))
	assert.Zero(t, columns)

	require.NoError(t, db.RunMigrations(dsn, "../../migrations"))
	assert.True(t, has(newSig))
}

// End to end: a Trivy report written with --severity HIGH,CRITICAL looks like a
// full scan, so only the declared filter keeps it from closing a medium finding.
func TestScanFilterIngestClosesOnlyInsideTheDeclaredFilter(t *testing.T) {
	pool, cleanup := setupIngestPool(t)
	defer cleanup()
	ctx := context.Background()
	stores := NewPortStores(pool)
	reg := scanner.NewRegistry()
	for _, sc := range parser.Builtins() {
		require.NoError(t, reg.Register(sc))
	}
	uc := usecase.New(usecase.Deps{Stores: stores, Registry: reg})
	creator, err := stores.Users.Create(ctx, "tester@example.com", nil, nil)
	require.NoError(t, err)
	_, err = uc.CreateProject(globalAdminCtx(creator.ID), "My App", "my-app", "validation", creator.ID)
	require.NoError(t, err)
	project, err := stores.Projects.GetBySlug(ctx, "my-app")
	require.NoError(t, err)

	raw, err := os.ReadFile("../parser/trivy/testdata/multi-type-scan.json")
	require.NoError(t, err)
	// The same scan with every finding gone, as a filtered scan that kept none.
	empty, err := rewriteTrivyReport(raw, func(results []map[string]any) {
		for _, r := range results {
			for _, key := range []string{"Vulnerabilities", "Misconfigurations", "Secrets"} {
				if _, ok := r[key]; ok {
					r[key] = []any{}
				}
			}
		}
	})
	require.NoError(t, err)
	state := func(substr string) string {
		t.Helper()
		findings, err := stores.Findings.ListByProject(ctx, project.ID, port.ListFindingsParams{Limit: 100})
		require.NoError(t, err)
		id := findingIDFor(findings, substr)
		require.NotEmpty(t, id, substr)
		f, err := stores.Findings.GetByID(ctx, id)
		require.NoError(t, err)
		return f.State
	}
	ingest := func(data []byte, commit string, filter domain.ScanFilter) *usecase.IngestReportOutput {
		t.Helper()
		out, err := uc.IngestReport(ctx, usecase.IngestReportInput{
			ProjectSlug: "my-app", Scanner: "trivy", RawData: data, Branch: "main", CommitSha: commit, ScanFilter: filter,
		})
		require.NoError(t, err)
		return out
	}

	ingest(raw, "aaa111", domain.ScanFilter{})
	require.Equal(t, "open", state("curl"), "critical")
	require.Equal(t, "open", state("lodash"), "medium")

	filter := domain.ScanFilter{Severities: []string{"CRITICAL", "high"}}
	filtered := ingest(empty, "bbb222", filter)
	report, err := stores.Reports.GetByID(ctx, filtered.ReportID)
	require.NoError(t, err)
	assert.Equal(t, []string{"high", "critical"}, report.FilterSeverities)
	assert.False(t, report.FilterFixableOnly)
	assert.Equal(t, "fixed", state("curl"), "the filter kept critical findings, and this one is gone")
	assert.Equal(t, "open", state("lodash"), "the filter hid medium findings, so absence says nothing")

	// The same bytes under the same filter and commit replay.
	again := ingest(empty, "bbb222", filter)
	assert.True(t, again.Replayed)
	assert.Equal(t, filtered.ReportID, again.ReportID)

	// The same bytes with no filter are a different claim: a full scan with
	// nothing in it, which closes the medium finding too.
	full := ingest(empty, "bbb222", domain.ScanFilter{})
	assert.False(t, full.Replayed)
	assert.NotEqual(t, filtered.ReportID, full.ReportID)
	assert.Equal(t, "fixed", state("lodash"))
}
