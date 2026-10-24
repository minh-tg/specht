//go:build integration

package repo

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/minh-tg/specht/internal/port"
)

// Report deletion settles findings a report observed, including findings the
// advisory watcher created before any scan saw them.
type scopeSeverityScenario struct {
	ctx       context.Context
	stores    *port.Stores
	projectID string
	findingID string
}

func newScopeSeverityScenario(t *testing.T) (*scopeSeverityScenario, func()) {
	t.Helper()
	pool, cleanup := setupIngestPool(t)
	ctx := context.Background()
	stores := NewPortStores(pool)
	project, err := stores.Projects.Create(ctx, port.CreateProjectInput{
		Slug: "scope-del", Name: "Scope Del", DeploymentThreshold: "high", Settings: []byte("{}"),
	})
	require.NoError(t, err)
	now := time.Now()
	finding, err := stores.Findings.Upsert(ctx, port.UpsertFindingInput{
		ProjectID: project.ID, FindingKind: "sca", Fingerprint: "shared", Title: "shared",
		Severity: "critical", SeverityRank: 5, Score: 9, FirstSeen: now, LastSeen: now,
	})
	require.NoError(t, err)
	return &scopeSeverityScenario{
		ctx: ctx, stores: stores, projectID: project.ID, findingID: finding.ID,
	}, cleanup
}

// report records one completed scan in a scope: the finding upsert with its
// scope severity, an occurrence, and attribution on first evidence, the same
// order ingest writes them.
func (s *scopeSeverityScenario) report(t *testing.T, scope, severity string, rank int16, age time.Duration) string {
	t.Helper()
	observed := time.Now().Add(-age)
	r, err := s.stores.Reports.Create(s.ctx, port.CreateReportInput{
		ProjectID: s.projectID, ToolName: "trivy", ScanType: "image", ScanScopeHash: scope,
		ScanScope: []byte(`{}`), RawReportHash: scope + severity, ScanMode: "full",
	})
	require.NoError(t, err)
	_, err = s.stores.Reports.UpdateStatus(s.ctx, r.ID, s.projectID, "completed", 1, nil)
	require.NoError(t, err)
	_, err = s.stores.Findings.Upsert(s.ctx, port.UpsertFindingInput{
		ProjectID: s.projectID, FindingKind: "sca", Fingerprint: "shared", Title: "shared",
		Severity: severity, SeverityRank: rank, Score: 9, FirstSeen: observed, LastSeen: observed,
		Scope: &port.FindingScopeSeverityInput{
			ScopeHash: scope, Severity: severity, SeverityRank: rank,
			ReportID: r.ID, ObservedAt: observed,
		},
	})
	require.NoError(t, err)
	id := r.ID
	_, err = s.stores.Findings.CreateOccurrence(s.ctx, port.OccurrenceInput{
		FindingID: s.findingID, ReportID: &id, Title: "shared", Severity: severity,
		SeverityRank: rank, ToolName: "trivy", ObservedAt: observed,
		Display: []byte(`{}`), Metadata: []byte(`{}`),
	})
	require.NoError(t, err)
	current, err := s.stores.Findings.GetByID(s.ctx, s.findingID)
	require.NoError(t, err)
	if current.IntroducedByReportID == nil {
		_, err = s.stores.Findings.SetFindingIntroducedBy(s.ctx, s.findingID, r.ID, nil)
		require.NoError(t, err)
	}
	return r.ID
}

// A finding the advisory watcher created has no introducing report. When a
// later scan observes it, deleting that report must settle it rather than fail
// because the comparison was SQL NULL.
func (s *scopeSeverityScenario) deleteReport(t *testing.T, id string) {
	t.Helper()
	_, err := s.stores.Reports.DeleteReportAndSettle(s.ctx, id, s.projectID, nil)
	require.NoError(t, err)
}

func TestDeleteReportAndSettle_SettlesAFindingWithNoIntroducingReport(t *testing.T) {
	s, cleanup := newScopeSeverityScenario(t)
	defer cleanup()
	report := s.report(t, "main-scope", "critical", 5, 0)
	now := time.Now()
	unattributed, err := s.stores.Findings.Upsert(s.ctx, port.UpsertFindingInput{
		ProjectID: s.projectID, FindingKind: "sca", Fingerprint: "watcher", Title: "watcher",
		Severity: "medium", SeverityRank: 3, Score: 5, FirstSeen: now, LastSeen: now,
	})
	require.NoError(t, err)
	_, err = s.stores.Findings.CreateOccurrence(s.ctx, port.OccurrenceInput{
		FindingID: unattributed.ID, ReportID: &report, Title: "watcher", Severity: "medium",
		SeverityRank: 3, ToolName: "trivy", ObservedAt: now,
		Display: []byte(`{}`), Metadata: []byte(`{}`),
	})
	require.NoError(t, err)

	s.deleteReport(t, report)

	after, err := s.stores.Findings.GetByID(s.ctx, unattributed.ID)
	require.NoError(t, err)
	assert.Equal(t, "archived", after.State)
}
