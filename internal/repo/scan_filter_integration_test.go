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
	return s.scanCovering(t, hash, []string{"sca"}, severities, fixableOnly)
}

// scanCovering is scan with the finding kinds the report says it examined.
func (s *filterScenario) scanCovering(t *testing.T, hash string, kinds, severities []string, fixableOnly bool) string {
	t.Helper()
	r, err := s.stores.Reports.Create(s.ctx, port.CreateReportInput{
		ProjectID: s.projectID, ToolName: "trivy", ScanType: "image", ScanScopeHash: "main",
		ScanScope: []byte(`{}`), RawReportHash: hash, ScanMode: "full",
		ScanCompleteness: "complete", CoveredFindingKinds: kinds,
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

// A severity filter hides whatever the scanner now rates outside it, and the
// stored rating may be stale, so a severity-filtered report closes nothing by
// absence, inside the filter or outside it.
func TestScanFilterSeverityClosesNothingByAbsence(t *testing.T) {
	s, cleanup := newFilterScenario(t,
		seeded{fingerprint: "low-1", severity: "low", rank: 1},
		seeded{fingerprint: "high-1", severity: "high", rank: 3},
	)
	defer cleanup()
	filtered := s.scan(t, "filtered", []string{"high", "critical"}, false)

	fixed, err := s.stores.Findings.MarkAbsentFindingsFixed(s.ctx, s.projectID, "main", filtered)
	require.NoError(t, err)

	assert.Empty(t, fixed)
	assert.Equal(t, "open", s.state(t, "high-1"), "the scanner may have re-rated it below the filter")
	assert.Equal(t, "open", s.state(t, "low-1"), "a HIGH,CRITICAL scan says nothing about a low finding")
	assert.Equal(t, 1, s.scopeRows(t, "low-1"), "the low finding keeps its scope evidence")
	assert.Equal(t, 1, s.scopeRows(t, "high-1"), "the high finding keeps its scope evidence")
}

// A finding rated critical when it was last seen and gone from a
// HIGH,CRITICAL report may have been re-rated to medium and hidden. It stays
// open.
func TestScanFilterSeverityKeepsAReRatedFindingOpen(t *testing.T) {
	s, cleanup := newFilterScenario(t,
		seeded{fingerprint: "critical-1", severity: "critical", rank: 4},
	)
	defer cleanup()
	filtered := s.scan(t, "filtered", []string{"high", "critical"}, false)

	fixed, err := s.stores.Findings.MarkAbsentFindingsFixed(s.ctx, s.projectID, "main", filtered)
	require.NoError(t, err)
	assert.Empty(t, fixed)
	assert.Equal(t, "open", s.state(t, "critical-1"))
}

// A filter that keeps every severity filters nothing and closes like a full
// scan.
func TestScanFilterOfEverySeverityClosesLikeAFullScan(t *testing.T) {
	s, cleanup := newFilterScenario(t,
		seeded{fingerprint: "low-1", severity: "low", rank: 1},
		seeded{fingerprint: "high-1", severity: "high", rank: 3},
	)
	defer cleanup()
	all := s.scan(t, "all", []string{"unknown", "low", "medium", "high", "critical"}, false)

	fixed, err := s.stores.Findings.MarkAbsentFindingsFixed(s.ctx, s.projectID, "main", all)
	require.NoError(t, err)
	assert.Len(t, fixed, 2)
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
	t.Run("a severity filter closes nothing even for a fixable finding", func(t *testing.T) {
		s, cleanup := newFilterScenario(t,
			seeded{fingerprint: "high-fixable", severity: "high", rank: 3, fixedIn: "2.0"},
			seeded{fingerprint: "high-unfixed", severity: "high", rank: 3},
		)
		defer cleanup()
		filtered := s.scan(t, "filtered", []string{"high"}, true)

		fixed, err := s.stores.Findings.MarkAbsentFindingsFixed(s.ctx, s.projectID, "main", filtered)
		require.NoError(t, err)
		assert.Empty(t, fixed)
	})
	t.Run("every severity kept, fixable only", func(t *testing.T) {
		s, cleanup := newFilterScenario(t,
			seeded{fingerprint: "high-fixable", severity: "high", rank: 3, fixedIn: "2.0"},
			seeded{fingerprint: "high-unfixed", severity: "high", rank: 3},
		)
		defer cleanup()
		filtered := s.scan(t, "filtered", []string{"unknown", "low", "medium", "high", "critical"}, true)

		fixed, err := s.stores.Findings.MarkAbsentFindingsFixed(s.ctx, s.projectID, "main", filtered)
		require.NoError(t, err)
		require.Len(t, fixed, 1)
		assert.Equal(t, "fixed", s.state(t, "high-fixable"))
		assert.Equal(t, "open", s.state(t, "high-unfixed"))
	})
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
	require.ErrorIs(t, err, port.ErrFindingStillObserved, "a severity filter vouches for no absence")
	assert.Equal(t, "open", s.state(t, "high-1"))
}

func TestVerifyRefusesACompleteReportThatCoveredNoKindOfTheFinding(t *testing.T) {
	cases := map[string][]string{
		"no kind at all": nil,
		"another kind":   {"iac"},
	}
	for name, kinds := range cases {
		t.Run(name, func(t *testing.T) {
			s, cleanup := newFilterScenario(t, seeded{fingerprint: "sca-1", severity: "high", rank: 3})
			defer cleanup()
			basis := s.scanCovering(t, "uncovered", kinds, nil, false)

			_, err := s.stores.Findings.MarkFixedWithEvent(s.ctx, s.ids["sca-1"], basis, port.FindingEventInput{FindingID: s.ids["sca-1"], EventType: "verified_fixed"})
			require.ErrorIs(t, err, port.ErrFindingStillObserved, "complete is not enough when the report never covered the kind")
			assert.Equal(t, "open", s.state(t, "sca-1"))
			assert.Equal(t, 1, s.scopeRows(t, "sca-1"))

			user, err := s.stores.Users.Create(s.ctx, "verifier@example.test", nil, nil)
			require.NoError(t, err)
			got, err := usecase.New(usecase.Deps{Stores: s.stores}).VerifyFix(globalAdminCtx(user.ID), s.ids["sca-1"])
			require.NoError(t, err)
			assert.Equal(t, usecase.VerifyInconclusive, got.Outcome)
			assert.Contains(t, got.Detail, "does not cover this kind of finding")
			assert.Equal(t, "open", s.state(t, "sca-1"))
		})
	}
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
	assert.Equal(t, usecase.VerifyInconclusive, high.Outcome, "the scanner may have re-rated it below the filter")
	assert.Equal(t, "open", s.state(t, "high-1"))
}

// A severity filter that leaves out any severity never vouches for an absent
// finding, whatever severity the finding had. The fixable filter needs a
// non-empty fixed_version dimension.
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
	every := []string{"unknown", "low", "medium", "high", "critical"}

	assert.True(t, ask("main", nil, false), "no filter")
	assert.True(t, ask("main", every, false), "a filter of every severity filters nothing")
	assert.False(t, ask("main", []string{"high"}, false), "the finding's high rating may be stale")
	assert.False(t, ask("main", []string{"high", "critical"}, false))
	assert.False(t, ask("main", []string{"low", "medium", "high", "critical"}, false))
	assert.False(t, ask("other", []string{"high"}, false))
	assert.True(t, ask("main", nil, true))
	assert.True(t, ask("main", every, true))
	assert.False(t, ask("main", []string{"high"}, true))

	_, err := s.pool.Exec(s.ctx, `DELETE FROM finding_dimensions WHERE finding_id = $1`, id)
	require.NoError(t, err)
	assert.False(t, ask("main", nil, true), "no fixed_version dimension")
	assert.True(t, ask("main", nil, false))
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

// The 000070 down migration puts back the 000067 severity test, which reads the
// severity the finding has in the report's scope, and drops the shared filter
// function; applying it again makes a severity filter vouch for no absence.
func TestSeverityFilterAbsenceMigrationRollback(t *testing.T) {
	s, cleanup := newFilterScenario(t,
		seeded{fingerprint: "high-1", severity: "high", rank: 3},
	)
	defer cleanup()
	dsn := s.pool.Config().ConnString()
	examined := func() bool {
		t.Helper()
		var got bool
		require.NoError(t, s.pool.QueryRow(s.ctx,
			`SELECT report_examined_finding('complete', ARRAY['sca'], NULL::text[], ARRAY['high']::text[], false, 'main', $1::uuid, 'sca', 'high-1')`,
			s.ids["high-1"]).Scan(&got))
		return got
	}
	hasHelper := func() bool {
		t.Helper()
		var ok bool
		require.NoError(t, s.pool.QueryRow(s.ctx,
			`SELECT to_regprocedure('report_filter_admits_absence(text[],boolean,uuid)') IS NOT NULL`).Scan(&ok))
		return ok
	}
	require.False(t, examined())
	require.True(t, hasHelper())

	for {
		var version int
		require.NoError(t, s.pool.QueryRow(s.ctx, `SELECT version FROM schema_migrations`).Scan(&version))
		if version < 70 {
			break
		}
		require.NoError(t, db.RollbackMigrations(dsn, "../../migrations"))
	}
	assert.True(t, examined(), "000067 trusts the stored high rating")
	assert.False(t, hasHelper())

	require.NoError(t, db.RunMigrations(dsn, "../../migrations"))
	assert.False(t, examined())
	assert.True(t, hasHelper())
}

// End to end: a Trivy report written with --severity HIGH,CRITICAL looks like a
// full scan, so only the declared filter keeps it from closing what it hid.
func TestScanFilterIngestClosesNothingUnderADeclaredSeverityFilter(t *testing.T) {
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
	assert.Equal(t, "open", state("curl"), "the scanner may now rate it below the filter, so absence says nothing")
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
