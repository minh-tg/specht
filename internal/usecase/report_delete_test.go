package usecase

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/minh-tg/specht/internal/auth"
	"github.com/minh-tg/specht/internal/port"
)

// settlingReports records the calls to DeleteReportAndSettle.
type settlingReports struct {
	port.ReportStore
	err       error
	archived  int
	affected  int
	gotID     string
	gotActor  *string
	gotProj   string
	callCount int
}

func (s *settlingReports) DeleteReportAndSettle(_ context.Context, id, projectID string, actor *string) (port.ReportDeletion, error) {
	s.callCount++
	s.gotID, s.gotProj, s.gotActor = id, projectID, actor
	if s.err != nil {
		return port.ReportDeletion{}, s.err
	}
	return port.ReportDeletion{ArchivedFindings: s.archived}, nil
}

const deleteReportID = "00000000-0000-4000-8000-000000000a01"

func reportDeleteUsecase(role string, reports *settlingReports) *Usecases {
	pr := &mockProjectRepo{
		getBySlugFn: func(_ context.Context, slug string) (port.Project, error) {
			if slug != "payments" {
				return port.Project{}, port.ErrNotFound
			}
			return port.Project{ID: "00000000-0000-0000-0000-000000000001", Slug: slug}, nil
		},
		effectiveRoleFn: func(context.Context, string, string) (string, error) { return role, nil },
	}
	return New(Deps{Stores: &port.Stores{Projects: pr, Reports: reports}})
}

func TestDeleteReport_NeedsProjectAdmin(t *testing.T) {
	for name, tc := range map[string]struct {
		role string
		ctx  context.Context
	}{
		"manager":   {auth.RoleManager, sessionCtx("u1", auth.RoleViewer)},
		"member":    {auth.RoleMember, sessionCtx("u1", auth.RoleViewer)},
		"API key":   {auth.RoleAdmin, apiKeyCtx("k1", "00000000-0000-0000-0000-000000000001")},
		"anonymous": {auth.RoleAdmin, context.Background()},
	} {
		t.Run(name, func(t *testing.T) {
			reports := &settlingReports{}
			_, err := reportDeleteUsecase(tc.role, reports).DeleteReport(tc.ctx, "payments", deleteReportID)
			assert.ErrorIs(t, err, ErrProjectAccessDenied)
			assert.Zero(t, reports.callCount, "nothing is deleted for a refused caller")
		})
	}
}

func TestDeleteReport_ProjectAdminAndGlobalAdminMayDelete(t *testing.T) {
	for name, ctx := range map[string]context.Context{
		"project admin": sessionCtx("u1", auth.RoleViewer),
		"global admin":  sessionCtx("g1", auth.RoleAdmin),
	} {
		t.Run(name, func(t *testing.T) {
			reports := &settlingReports{archived: 3}
			resp, err := reportDeleteUsecase(auth.RoleAdmin, reports).DeleteReport(ctx, "payments", deleteReportID)

			require.NoError(t, err)
			assert.Equal(t, 3, resp.ArchivedFindings)
			assert.Equal(t, deleteReportID, reports.gotID)
			assert.Equal(t, "00000000-0000-0000-0000-000000000001", reports.gotProj, "scoped to the project, so another project's report cannot be named")
			require.NotNil(t, reports.gotActor)
			assert.NotEmpty(t, *reports.gotActor, "the event names who deleted it")
		})
	}
}

func (s *settlingReports) ReportDeletionImpact(_ context.Context, id, projectID string) (port.ReportDeletionImpact, error) {
	s.callCount++
	s.gotID, s.gotProj = id, projectID
	if s.err != nil {
		return port.ReportDeletionImpact{}, s.err
	}
	return port.ReportDeletionImpact{AffectedFindings: s.affected, ArchivedFindings: s.archived}, nil
}

func TestPreviewDeleteReport_NeedsProjectAdmin(t *testing.T) {
	reports := &settlingReports{}
	_, err := reportDeleteUsecase(auth.RoleManager, reports).PreviewDeleteReport(
		sessionCtx("u1", auth.RoleViewer), "payments", deleteReportID)

	assert.ErrorIs(t, err, ErrProjectAccessDenied)
	assert.Zero(t, reports.callCount)
}

func TestPreviewDeleteReport_ReturnsTheImpactWithoutDeleting(t *testing.T) {
	reports := &settlingReports{affected: 5, archived: 2}
	preview, err := reportDeleteUsecase(auth.RoleAdmin, reports).PreviewDeleteReport(
		sessionCtx("g1", auth.RoleAdmin), "payments", deleteReportID)

	require.NoError(t, err)
	assert.Equal(t, 5, preview.AffectedFindings)
	assert.Equal(t, 2, preview.ArchivedFindings)
	assert.Equal(t, deleteReportID, reports.gotID)
	assert.Equal(t, "00000000-0000-0000-0000-000000000001", reports.gotProj)
}

func TestPreviewDeleteReport_ErrorMapping(t *testing.T) {
	admin := sessionCtx("g1", auth.RoleAdmin)

	_, err := reportDeleteUsecase(auth.RoleAdmin, &settlingReports{}).PreviewDeleteReport(admin, "payments", "not-a-uuid")
	assert.ErrorIs(t, err, ErrInvalidID)

	_, err = reportDeleteUsecase(auth.RoleAdmin, &settlingReports{}).PreviewDeleteReport(admin, "nope", deleteReportID)
	assert.ErrorIs(t, err, ErrProjectAccessDenied)

	_, err = reportDeleteUsecase(auth.RoleAdmin, &settlingReports{err: port.ErrNotFound}).PreviewDeleteReport(admin, "payments", deleteReportID)
	assert.ErrorIs(t, err, ErrReportNotFound)

	_, err = reportDeleteUsecase(auth.RoleAdmin, &settlingReports{err: errors.New("db down")}).PreviewDeleteReport(admin, "payments", deleteReportID)
	require.Error(t, err)
	assert.NotErrorIs(t, err, ErrReportNotFound)
}

func TestDeleteReport_ErrorMapping(t *testing.T) {
	admin := sessionCtx("g1", auth.RoleAdmin)

	_, err := reportDeleteUsecase(auth.RoleAdmin, &settlingReports{}).DeleteReport(admin, "payments", "not-a-uuid")
	assert.ErrorIs(t, err, ErrInvalidID)

	_, err = reportDeleteUsecase(auth.RoleAdmin, &settlingReports{}).DeleteReport(admin, "nope", deleteReportID)
	assert.ErrorIs(t, err, ErrProjectAccessDenied, "an unknown project looks like no access")

	_, err = reportDeleteUsecase(auth.RoleAdmin, &settlingReports{err: port.ErrNotFound}).DeleteReport(admin, "payments", deleteReportID)
	assert.ErrorIs(t, err, ErrReportNotFound)

	_, err = reportDeleteUsecase(auth.RoleAdmin, &settlingReports{err: port.ErrReportProcessing}).DeleteReport(admin, "payments", deleteReportID)
	assert.ErrorIs(t, err, ErrReportProcessing)

	_, err = reportDeleteUsecase(auth.RoleAdmin, &settlingReports{err: errors.New("db down")}).DeleteReport(admin, "payments", deleteReportID)
	require.Error(t, err)
	assert.NotErrorIs(t, err, ErrReportNotFound)
}
