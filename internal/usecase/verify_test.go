package usecase

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/minh-tg/specht/internal/port"
	"github.com/minh-tg/specht/internal/tracker"
)

func verifyHarness(now time.Time) (*Usecases, *mockFindingRepo, *mockReportRepo, port.Finding) {
	fr := &mockFindingRepo{}
	rr := &mockReportRepo{}
	f := makeFindingRow(1)
	f.LastSeenAt = now.Add(-time.Hour)
	fr.getByIDFn = func(ctx context.Context, id string) (port.Finding, error) {
		return f, nil
	}
	fr.getDisplayContextFn = func(ctx context.Context, findingID string) (port.FindingDisplayContext, error) {
		return port.FindingDisplayContext{ToolName: "trivy"}, nil
	}
	pr, _, _ := makeTestRepos()
	uc := New(Deps{Stores: &port.Stores{Projects: pr, Findings: fr, Reports: rr}})
	return uc, fr, rr, f
}

func TestVerifyFix_Verified(t *testing.T) {
	now := time.Now()
	uc, fr, rr, f := verifyHarness(now)
	reportID := "11111111-1111-1111-1111-111111111111"
	rr.findingScopeFn = func(ctx context.Context, projectID, findingID string) (port.CompletedReport, error) {
		assert.Equal(t, f.ID, findingID)
		return port.CompletedReport{
			ID: reportID, ToolName: "trivy",
			Completeness: "complete", ExaminedFinding: true, CreatedAt: now,
		}, nil
	}
	fr.hasOccurrenceFn = func(ctx context.Context, findingID, repID string) (bool, error) {
		assert.Equal(t, reportID, repID)
		return false, nil
	}
	var marked string
	fr.markFixedFn = func(ctx context.Context, findingID string) (port.Finding, error) {
		marked = findingID
		f.State = "fixed"
		return f, nil
	}
	var eventType string
	fr.createEventFn = func(ctx context.Context, arg port.FindingEventInput) (port.FindingEvent, error) {
		eventType = arg.EventType
		return port.FindingEvent{}, nil
	}

	resp, err := uc.VerifyFix(findingScopeCtx(findingFixtureProjectID), f.ID)
	require.NoError(t, err)
	assert.Equal(t, VerifyFixed, resp.Outcome)
	require.NotNil(t, resp.ReportID)
	assert.Equal(t, reportID, *resp.ReportID)
	assert.Equal(t, f.ID, marked)
	assert.Equal(t, "verified_fixed", eventType)
}

func TestVerifyFix_VerifiesAnIncompleteReportThatExaminedTheFinding(t *testing.T) {
	now := time.Now()
	uc, fr, rr, f := verifyHarness(now)
	rr.findingScopeFn = func(ctx context.Context, projectID, findingID string) (port.CompletedReport, error) {
		return port.CompletedReport{
			ID: "11111111-1111-1111-1111-111111111111", ToolName: "sarif",
			Completeness: "unknown", ExaminedFinding: true, CreatedAt: now,
		}, nil
	}
	fr.hasOccurrenceFn = func(context.Context, string, string) (bool, error) { return false, nil }
	fr.markFixedFn = func(context.Context, string) (port.Finding, error) { return f, nil }
	fr.createEventFn = func(context.Context, port.FindingEventInput) (port.FindingEvent, error) {
		return port.FindingEvent{}, nil
	}

	resp, err := uc.VerifyFix(findingScopeCtx(findingFixtureProjectID), f.ID)
	require.NoError(t, err)
	assert.Equal(t, VerifyFixed, resp.Outcome)
}

func TestVerifyFix_EventFailureDoesNotChangeState(t *testing.T) {
	now := time.Now()
	uc, fr, rr, f := verifyHarness(now)
	rr.findingScopeFn = func(ctx context.Context, projectID, findingID string) (port.CompletedReport, error) {
		return port.CompletedReport{ID: "11111111-1111-1111-1111-111111111111", ToolName: "trivy", Completeness: "complete", ExaminedFinding: true, CreatedAt: now}, nil
	}
	fr.hasOccurrenceFn = func(ctx context.Context, findingID, reportID string) (bool, error) { return false, nil }
	fr.markFixedWithEventFn = func(ctx context.Context, findingID string, event port.FindingEventInput) (port.Finding, error) {
		return port.Finding{}, fmt.Errorf("event insert failed")
	}
	_, err := uc.VerifyFix(findingScopeCtx(findingFixtureProjectID), f.ID)
	require.Error(t, err)
	assert.NotEqual(t, "fixed", f.State)
}

func TestVerifyFix_StillPresent(t *testing.T) {
	now := time.Now()
	uc, fr, rr, f := verifyHarness(now)
	rr.findingScopeFn = func(ctx context.Context, projectID, findingID string) (port.CompletedReport, error) {
		return port.CompletedReport{
			ID: "11111111-1111-1111-1111-111111111111", ToolName: "trivy",
			Completeness: "complete", CreatedAt: now,
		}, nil
	}
	fr.hasOccurrenceFn = func(ctx context.Context, findingID, repID string) (bool, error) {
		return true, nil
	}

	resp, err := uc.VerifyFix(findingScopeCtx(findingFixtureProjectID), f.ID)
	require.NoError(t, err)
	assert.Equal(t, VerifyPresent, resp.Outcome)
}

func TestVerifyFix_InconclusivePaths(t *testing.T) {
	now := time.Now()

	t.Run("no report in finding scope", func(t *testing.T) {
		uc, _, _, f := verifyHarness(now)
		resp, err := uc.VerifyFix(findingScopeCtx(findingFixtureProjectID), f.ID)
		require.NoError(t, err)
		assert.Equal(t, VerifyInconclusive, resp.Outcome)
		assert.Nil(t, resp.ReportID)
	})

	t.Run("partial scope", func(t *testing.T) {
		uc, fr, rr, f := verifyHarness(now)
		rr.findingScopeFn = func(ctx context.Context, projectID, findingID string) (port.CompletedReport, error) {
			return port.CompletedReport{
				ID: "11111111-1111-1111-1111-111111111111", ToolName: "trivy",
				Completeness: "unknown", CreatedAt: now,
			}, nil
		}
		fr.hasOccurrenceFn = func(_ context.Context, _, _ string) (bool, error) {
			return false, nil
		}
		resp, err := uc.VerifyFix(findingScopeCtx(findingFixtureProjectID), f.ID)
		require.NoError(t, err)
		assert.Equal(t, VerifyInconclusive, resp.Outcome)
		assert.Contains(t, resp.Detail, "does not show it examined this one")
	})
	t.Run("complete scope that never covered the kind", func(t *testing.T) {
		uc, fr, rr, f := verifyHarness(now)
		rr.findingScopeFn = func(ctx context.Context, projectID, findingID string) (port.CompletedReport, error) {
			return port.CompletedReport{
				ID: "11111111-1111-1111-1111-111111111111", ToolName: "trivy",
				Completeness: "complete", ExaminedFinding: false, CreatedAt: now,
			}, nil
		}
		fr.hasOccurrenceFn = func(_ context.Context, _, _ string) (bool, error) {
			return false, nil
		}
		fr.markFixedWithEventFn = func(context.Context, string, port.FindingEventInput) (port.Finding, error) {
			t.Error("a report that did not cover the kind must not mark the finding fixed")
			return f, nil
		}
		resp, err := uc.VerifyFix(findingScopeCtx(findingFixtureProjectID), f.ID)
		require.NoError(t, err)
		assert.Equal(t, VerifyInconclusive, resp.Outcome)
		assert.Contains(t, resp.Detail, "does not cover this kind of finding")
	})
	t.Run("stale basis", func(t *testing.T) {
		uc, fr, rr, f := verifyHarness(now)
		rr.findingScopeFn = func(ctx context.Context, projectID, findingID string) (port.CompletedReport, error) {
			return port.CompletedReport{
				ID: "11111111-1111-1111-1111-111111111111", ToolName: "trivy",
				Completeness: "complete", CreatedAt: now.Add(-2 * time.Hour),
			}, nil
		}
		fr.hasOccurrenceFn = func(_ context.Context, _, _ string) (bool, error) {
			return false, nil
		}
		resp, err := uc.VerifyFix(findingScopeCtx(findingFixtureProjectID), f.ID)
		require.NoError(t, err)
		assert.Equal(t, VerifyInconclusive, resp.Outcome)
	})
}

func TestVerifyFix_IgnoresNewerReportOfOtherScope(t *testing.T) {
	now := time.Now()
	uc, fr, rr, f := verifyHarness(now)
	inScopeID := "11111111-1111-1111-1111-111111111111"
	rr.findingScopeFn = func(ctx context.Context, projectID, findingID string) (port.CompletedReport, error) {
		return port.CompletedReport{
			ID: inScopeID, ToolName: "trivy",
			Completeness: "complete", ExaminedFinding: true, CreatedAt: now.Add(-30 * time.Minute),
		}, nil
	}
	// A newer complete full scan of another image or branch lacks the finding.
	// Verification must not consult the scanner-wide lookup at all.
	rr.latestReportFn = func(ctx context.Context, projectID, scanner string) (port.CompletedReport, error) {
		t.Error("scanner-wide lookup must not drive verification")
		return port.CompletedReport{
			ID: "22222222-2222-2222-2222-222222222222", ToolName: "trivy",
			Completeness: "complete", CreatedAt: now,
		}, nil
	}
	fr.hasOccurrenceFn = func(ctx context.Context, findingID, reportID string) (bool, error) {
		assert.Equal(t, inScopeID, reportID)
		return false, nil
	}
	marked := false
	fr.markFixedWithEventFn = func(ctx context.Context, findingID string, event port.FindingEventInput) (port.Finding, error) {
		marked = true
		return f, nil
	}

	resp, err := uc.VerifyFix(findingScopeCtx(findingFixtureProjectID), f.ID)
	require.NoError(t, err)
	assert.Equal(t, VerifyFixed, resp.Outcome)
	require.NotNil(t, resp.ReportID)
	assert.Equal(t, inScopeID, *resp.ReportID)
	assert.True(t, marked)
}

func TestVerifyFix_NoReportInFindingScopeIsInconclusive(t *testing.T) {
	now := time.Now()
	uc, fr, rr, f := verifyHarness(now)
	rr.latestReportFn = func(ctx context.Context, projectID, scanner string) (port.CompletedReport, error) {
		t.Error("scanner-wide lookup must not drive verification")
		return port.CompletedReport{}, nil
	}
	fr.markFixedWithEventFn = func(ctx context.Context, findingID string, event port.FindingEventInput) (port.Finding, error) {
		t.Error("finding must not be marked fixed without a report in its scope")
		return port.Finding{}, nil
	}

	resp, err := uc.VerifyFix(findingScopeCtx(findingFixtureProjectID), f.ID)
	require.NoError(t, err)
	assert.Equal(t, VerifyInconclusive, resp.Outcome)
	assert.Nil(t, resp.ReportID)
}

type recordingTracker struct{ events []tracker.Event }

func (r *recordingTracker) Dispatch(_ context.Context, e tracker.Event) {
	r.events = append(r.events, e)
}

func TestVerifyFix_TrackerEventNamesTheProject(t *testing.T) {
	now := time.Now()
	for name, lookupFails := range map[string]bool{"slug resolved": false, "lookup failed": true} {
		t.Run(name, func(t *testing.T) {
			uc, fr, rr, f := verifyHarness(now)
			rt := &recordingTracker{}
			uc.deps.Tracker = rt
			uc.deps.Stores.Projects.(*mockProjectRepo).getByIDFn = func(_ context.Context, id string) (port.Project, error) {
				assert.Equal(t, f.ProjectID, id)
				if lookupFails {
					return port.Project{}, fmt.Errorf("db down")
				}
				return port.Project{ID: id, Slug: "acme-web"}, nil
			}
			rr.findingScopeFn = func(context.Context, string, string) (port.CompletedReport, error) {
				return port.CompletedReport{ID: "11111111-1111-1111-1111-111111111111", ToolName: "trivy", Completeness: "complete", ExaminedFinding: true, CreatedAt: now}, nil
			}
			fr.hasOccurrenceFn = func(context.Context, string, string) (bool, error) { return false, nil }
			fr.markFixedFn = func(context.Context, string) (port.Finding, error) { return f, nil }
			fr.createEventFn = func(context.Context, port.FindingEventInput) (port.FindingEvent, error) {
				return port.FindingEvent{}, nil
			}

			resp, err := uc.VerifyFix(findingScopeCtx(findingFixtureProjectID), f.ID)

			require.NoError(t, err)
			assert.Equal(t, VerifyFixed, resp.Outcome)
			require.Len(t, rt.events, 1)
			assert.Equal(t, tracker.EventVerifiedFixed, rt.events[0].Type)
			if lookupFails {
				assert.Empty(t, rt.events[0].ProjectSlug)
			} else {
				assert.Equal(t, "acme-web", rt.events[0].ProjectSlug)
			}
		})
	}
}
