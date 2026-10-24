package usecase

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/minh-tg/specht/internal/domain"
	"github.com/minh-tg/specht/internal/port"
	"github.com/minh-tg/specht/internal/scanner"
)

// severityCapture records what one ingest wrote for the finding under test.
type severityCapture struct {
	upserts   []port.UpsertFindingInput
	scopeRows []port.FindingScopeSeverityInput
	events    []port.FindingEventInput
}

// severityEvents returns the severity_changed events among the captured ones.
func (c *severityCapture) severityEvents() []port.FindingEventInput {
	var out []port.FindingEventInput
	for _, e := range c.events {
		if e.EventType == "severity_changed" {
			out = append(out, e)
		}
	}
	return out
}

// severityScopeHash is the scope the ingest derives for a branch, computed the
// same way IngestReport does for the same target.
func severityScopeHash(branch string) string {
	return scanScopeHash(IngestReportInput{Scanner: "trivy", Branch: branch},
		&domain.NormalizedReport{Target: &domain.TargetInfo{Kind: "container", Identifier: "myapp:latest"}})
}

// severityKnownFinding is an open, unanalyzed finding the scan will match. A
// material-change event would only add noise to these tests, so the analysis
// stays unanalyzed.
func severityKnownFinding(severity string, rank int16) port.Finding {
	f := makeFinding(9)
	f.FindingKind = "sca"
	f.Fingerprint = "fp-sev"
	f.State = "open"
	f.AnalysisState = "unanalyzed"
	f.GateEffect = "block"
	f.CurrentSeverity = severity
	f.CurrentSeverityRank = rank
	return f
}

// runSeverityIngest ingests one scan on branch with the given severity. known
// is the finding already stored (nil for a new one), and rows are the scope
// severities already stored for it.
func runSeverityIngest(t *testing.T, branch string, severity domain.Severity, known *port.Finding, rows []port.FindingScopeSeverity) *severityCapture {
	t.Helper()
	return runSeverityIngestSeq(t, branch, []domain.Severity{severity}, known, rows)
}

// runSeverityIngestSeq ingests one scan whose report lists the same finding
// once per severity, in order. A report that names a finding twice exercises
// the coalescing of that finding's severity_changed event.
func runSeverityIngestSeq(t *testing.T, branch string, severities []domain.Severity, known *port.Finding, rows []port.FindingScopeSeverity) *severityCapture {
	t.Helper()
	pr, rr, fr := makeTestRepos()
	pr.getBySlugFn = func(ctx context.Context, slug string) (port.Project, error) {
		return makeProject(true), nil
	}
	rr.createFn = func(ctx context.Context, arg port.CreateReportInput) (port.Report, error) {
		return makeReport(), nil
	}
	rr.updateStatusFn = func(ctx context.Context, id, projectID, status string, totalFindings int32, errorMsg *string) (port.Report, error) {
		r := makeReport()
		r.Status = status
		return r, nil
	}

	captured := &severityCapture{}
	storedID := makeFinding(9).ID
	if known != nil {
		storedID = known.ID
		fr.listFindingsByFingerprintsFn = func(ctx context.Context, projectID, kind string, fps []string) ([]port.Finding, error) {
			return []port.Finding{*known}, nil
		}
	}
	fr.listScopeSeveritiesFn = func(ctx context.Context, ids []string) ([]port.FindingScopeSeverity, error) {
		return rows, nil
	}
	fr.upsertFn = func(ctx context.Context, in port.UpsertFindingInput) (port.Finding, error) {
		captured.upserts = append(captured.upserts, in)
		if known != nil {
			return *known, nil
		}
		return makeFinding(9), nil
	}
	fr.upsertScopeSeverityFn = func(ctx context.Context, in port.FindingScopeSeverityInput) error {
		captured.scopeRows = append(captured.scopeRows, in)
		return nil
	}
	fr.createOccurrenceFn = func(ctx context.Context, arg port.OccurrenceInput) (port.Occurrence, error) {
		return port.Occurrence{}, nil
	}
	fr.upsertDimensionFn = func(ctx context.Context, arg port.DimensionInput) error {
		return nil
	}
	fr.createEventFn = func(ctx context.Context, arg port.FindingEventInput) (port.FindingEvent, error) {
		captured.events = append(captured.events, arg)
		return port.FindingEvent{ID: storedID, EventType: arg.EventType}, nil
	}

	reg := scanner.NewRegistry()
	findings := make([]domain.NormalizedFinding, 0, len(severities))
	for _, sev := range severities {
		findings = append(findings, domain.NormalizedFinding{
			Fingerprint: "fp-sev",
			FindingKind: "sca",
			Title:       "CVE-2026-0042",
			Severity:    sev,
			Score:       5.0,
		})
	}
	require.NoError(t, reg.Register(&mockScanner{
		name: "trivy",
		parseFn: func(ctx context.Context, input []byte) (*domain.NormalizedReport, error) {
			return &domain.NormalizedReport{
				ContractVersion:     1,
				FingerprintVersion:  1,
				Completeness:        domain.CompletenessComplete,
				CoveredFindingKinds: []string{"sca", "sast", "iac", "secret", "dast"},
				ScanType:            domain.ScanTypeImage,
				Target:              &domain.TargetInfo{Kind: "container", Identifier: "myapp:latest"},
				Findings:            findings,
			}, nil
		},
	}))

	uc := New(Deps{
		Stores: &port.Stores{
			Projects:  pr,
			Reports:   rr,
			Findings:  fr,
			Targets:   stubTargetRepo(),
			Artifacts: stubArtifactRepo(),
		},
		Registry: reg,
	})
	_, err := uc.IngestReport(context.Background(), IngestReportInput{
		ProjectSlug: "my-app",
		Scanner:     "trivy",
		Branch:      branch,
		RawData:     json.RawMessage(`{"scan": "severity"}`),
	})
	require.NoError(t, err)
	return captured
}

// A low scan from another branch leaves the project-wide severity high. The
// scan writes its own scope row and one severity_changed event for that scope.
func TestIngestSeverityScope_LowerScopeKeepsProjectSeverity(t *testing.T) {
	known := severityKnownFinding("high", 3)
	rows := []port.FindingScopeSeverity{
		{FindingID: known.ID, ScopeHash: severityScopeHash("main"), Severity: "high", SeverityRank: 3},
	}

	c := runSeverityIngest(t, "feature/unrelated", domain.SeverityLow, &known, rows)

	require.NotEmpty(t, c.upserts)
	assert.Equal(t, int16(3), c.upserts[0].SeverityRank, "the finding row keeps the high severity from main")
	assert.Equal(t, "high", c.upserts[0].Severity)

	require.Len(t, c.scopeRows, 1)
	assert.Equal(t, severityScopeHash("feature/unrelated"), c.scopeRows[0].ScopeHash)
	assert.Equal(t, "low", c.scopeRows[0].Severity)
	assert.Equal(t, int16(1), c.scopeRows[0].SeverityRank)

	events := c.severityEvents()
	require.Len(t, events, 1, "the feature scope's first report differs from the project-wide high, so it is recorded")
	assert.Equal(t, "high", *events[0].OldValue)
	assert.Equal(t, "low", *events[0].NewValue)
	var changes map[string]any
	require.NoError(t, json.Unmarshal(events[0].Changes, &changes))
	assert.Equal(t, severityScopeHash("feature/unrelated"), changes["scope_hash"])
	assert.Equal(t, "high", changes["project_severity_before"])
	assert.Equal(t, "high", changes["project_severity_after"])
}

// A repeat from the same scope at the same severity writes no event and
// leaves the project-wide severity unchanged.
func TestIngestSeverityScope_SameScopeSameSeverityWritesNoEvent(t *testing.T) {
	known := severityKnownFinding("high", 3)
	rows := []port.FindingScopeSeverity{
		{FindingID: known.ID, ScopeHash: severityScopeHash("main"), Severity: "high", SeverityRank: 3},
	}

	c := runSeverityIngest(t, "main", domain.SeverityHigh, &known, rows)

	require.Len(t, c.scopeRows, 1)
	assert.Equal(t, int16(3), c.upserts[0].SeverityRank)
	assert.Empty(t, c.severityEvents(), "an unchanged severity in the same scope writes no event")
}

// When the scan's own scope moves from high to low and another scope still
// reports high, the project-wide value stays high. The scope's change is
// still recorded, once, with the scope's old and new values.
func TestIngestSeverityScope_OwnScopeDowngradeWritesOneEvent(t *testing.T) {
	known := severityKnownFinding("high", 3)
	rows := []port.FindingScopeSeverity{
		{FindingID: known.ID, ScopeHash: severityScopeHash("main"), Severity: "high", SeverityRank: 3},
		{FindingID: known.ID, ScopeHash: severityScopeHash("feature/x"), Severity: "high", SeverityRank: 3},
	}

	c := runSeverityIngest(t, "feature/x", domain.SeverityLow, &known, rows)

	assert.Equal(t, int16(3), c.upserts[0].SeverityRank)
	events := c.severityEvents()
	require.Len(t, events, 1)
	assert.Equal(t, "high", *events[0].OldValue)
	assert.Equal(t, "low", *events[0].NewValue)
}

// A scope that reports a higher severity than the stored one raises the
// project-wide value. That raise is recorded as one event, so the increase
// is visible in the finding's history too.
func TestIngestSeverityScope_HigherScopeRaisesProjectSeverity(t *testing.T) {
	known := severityKnownFinding("low", 1)
	rows := []port.FindingScopeSeverity{
		{FindingID: known.ID, ScopeHash: severityScopeHash("main"), Severity: "low", SeverityRank: 1},
	}

	c := runSeverityIngest(t, "feature/x", domain.SeverityHigh, &known, rows)

	assert.Equal(t, int16(3), c.upserts[0].SeverityRank)
	assert.Equal(t, "high", c.upserts[0].Severity)
	events := c.severityEvents()
	require.Len(t, events, 1)
	assert.Equal(t, "low", *events[0].OldValue, "a scope with no earlier report compares against the project-wide value")
	assert.Equal(t, "high", *events[0].NewValue)
	var changes map[string]any
	require.NoError(t, json.Unmarshal(events[0].Changes, &changes))
	assert.Equal(t, "low", changes["project_severity_before"])
	assert.Equal(t, "high", changes["project_severity_after"])
}

// A finding seen for the first time has nothing to change from, so it writes
// its scope row and no severity_changed event.
func TestIngestSeverityScope_NewFindingWritesNoEvent(t *testing.T) {
	c := runSeverityIngest(t, "main", domain.SeverityHigh, nil, nil)

	require.Len(t, c.scopeRows, 1)
	assert.Equal(t, severityScopeHash("main"), c.scopeRows[0].ScopeHash)
	assert.Equal(t, int16(3), c.upserts[0].SeverityRank)
	assert.Empty(t, c.severityEvents())
}

// A report that names the same finding twice writes one event for it. The old
// value is the severity before the report and the new value is the last one
// the report sets, so the intermediate value leaves no stale event behind.
func TestIngestSeverityScope_DuplicateFindingWritesOneEvent(t *testing.T) {
	known := severityKnownFinding("medium", 2)
	rows := []port.FindingScopeSeverity{
		{FindingID: known.ID, ScopeHash: severityScopeHash("main"), Severity: "medium", SeverityRank: 2},
	}

	c := runSeverityIngestSeq(t, "main", []domain.Severity{domain.SeverityLow, domain.SeverityHigh}, &known, rows)

	events := c.severityEvents()
	require.Len(t, events, 1, "one report writes one severity_changed event per finding")
	assert.Equal(t, "medium", *events[0].OldValue, "the old value is the severity before the report")
	assert.Equal(t, "high", *events[0].NewValue, "the new value is the last severity the report sets")
	var changes map[string]any
	require.NoError(t, json.Unmarshal(events[0].Changes, &changes))
	assert.Equal(t, "medium", changes["project_severity_before"])
	assert.Equal(t, "high", changes["project_severity_after"])
}

// A report that names the same finding twice but ends on the value it started
// with writes no event. The transient lower value is not recorded.
func TestIngestSeverityScope_DuplicateFindingRestoresStartWritesNoEvent(t *testing.T) {
	known := severityKnownFinding("medium", 2)
	rows := []port.FindingScopeSeverity{
		{FindingID: known.ID, ScopeHash: severityScopeHash("main"), Severity: "medium", SeverityRank: 2},
	}

	c := runSeverityIngestSeq(t, "main", []domain.Severity{domain.SeverityLow, domain.SeverityMedium}, &known, rows)

	assert.Empty(t, c.severityEvents(), "the report ends where it started, so it writes no event")
}
