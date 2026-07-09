package usecase

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/xMinhx/specht/internal/auth"
	"github.com/xMinhx/specht/internal/db/sqlc"
	"github.com/xMinhx/specht/internal/repo"
	"github.com/xMinhx/specht/internal/scanner"
)

type mockProjectRepo struct {
	repo.ProjectRepo
	createFn    func(ctx context.Context, arg sqlc.CreateProjectParams) (sqlc.Project, error)
	listFn      func(ctx context.Context) ([]sqlc.Project, error)
	getBySlugFn func(ctx context.Context, slug string) (sqlc.Project, error)
}

func (m *mockProjectRepo) Create(ctx context.Context, arg sqlc.CreateProjectParams) (sqlc.Project, error) {
	if m.createFn == nil {
		return sqlc.Project{}, fmt.Errorf("unexpected call to Create")
	}
	return m.createFn(ctx, arg)
}

func (m *mockProjectRepo) List(ctx context.Context) ([]sqlc.Project, error) {
	if m.listFn == nil {
		return nil, fmt.Errorf("unexpected call to List")
	}
	return m.listFn(ctx)
}

func (m *mockProjectRepo) GetBySlug(ctx context.Context, slug string) (sqlc.Project, error) {
	if m.getBySlugFn == nil {
		return sqlc.Project{}, fmt.Errorf("unexpected call to GetBySlug")
	}
	return m.getBySlugFn(ctx, slug)
}

type mockReportRepo struct {
	repo.ReportRepo
	createFn        func(ctx context.Context, arg repo.CreateReportParams) (sqlc.Report, error)
	getByIDFn       func(ctx context.Context, id pgtype.UUID) (sqlc.Report, error)
	listByProjectFn func(ctx context.Context, projectID pgtype.UUID, limit, offset int32) ([]sqlc.Report, error)
	updateStatusFn  func(ctx context.Context, id, projectID pgtype.UUID, status string, totalFindings int, errorMsg pgtype.Text) (sqlc.Report, error)
}

func (m *mockReportRepo) Create(ctx context.Context, arg repo.CreateReportParams) (sqlc.Report, error) {
	if m.createFn == nil {
		return sqlc.Report{}, fmt.Errorf("unexpected call to Create")
	}
	return m.createFn(ctx, arg)
}

func (m *mockReportRepo) UpdateStatus(ctx context.Context, id, projectID pgtype.UUID, status string, totalFindings int, errorMsg pgtype.Text) (sqlc.Report, error) {
	if m.updateStatusFn == nil {
		return sqlc.Report{}, fmt.Errorf("unexpected call to UpdateStatus")
	}
	return m.updateStatusFn(ctx, id, projectID, status, totalFindings, errorMsg)
}

func (m *mockReportRepo) GetByID(ctx context.Context, id pgtype.UUID) (sqlc.Report, error) {
	if m.getByIDFn == nil {
		return sqlc.Report{}, fmt.Errorf("unexpected call to GetByID")
	}
	return m.getByIDFn(ctx, id)
}

func (m *mockReportRepo) ListByProject(ctx context.Context, projectID pgtype.UUID, limit, offset int32) ([]sqlc.Report, error) {
	if m.listByProjectFn == nil {
		return nil, fmt.Errorf("unexpected call to ListByProject")
	}
	return m.listByProjectFn(ctx, projectID, limit, offset)
}

type mockFindingRepo struct {
	repo.FindingRepo
	upsertFn               func(ctx context.Context, arg repo.UpsertFindingParams) (sqlc.Finding, error)
	createOccurrenceFn     func(ctx context.Context, arg repo.CreateOccurrenceParams) (sqlc.FindingOccurrence, error)
	upsertDimensionFn      func(ctx context.Context, arg repo.UpsertDimensionParams) (sqlc.FindingDimension, error)
	listByProjectFn        func(ctx context.Context, projectID pgtype.UUID, severities, states []string, limit, offset int32) ([]sqlc.Finding, error)
	getByFingerprintFn     func(ctx context.Context, arg repo.GetByFingerprintParams) (sqlc.Finding, error)
	getByIDFn              func(ctx context.Context, id pgtype.UUID) (sqlc.Finding, error)
	listByIDsFn            func(ctx context.Context, ids []pgtype.UUID) ([]sqlc.Finding, error)
	hasDimensionFn         func(ctx context.Context, findingID pgtype.UUID, key string) (bool, error)
	updateAnalysisFn       func(ctx context.Context, arg repo.UpdateAnalysisParams) (sqlc.Finding, error)
	bulkUpdateAnalysisFn   func(ctx context.Context, arg repo.BulkUpdateAnalysisParams) ([]sqlc.Finding, error)
	createEventFn          func(ctx context.Context, arg repo.CreateEventParams) (sqlc.FindingEvent, error)
	listEventsFn           func(ctx context.Context, findingID pgtype.UUID, eventTypes []string, limit, offset int32) ([]sqlc.FindingEvent, error)
	gateEvalFn             func(ctx context.Context, arg repo.GateEvalParams) (bool, error)
	countBlockingFn        func(ctx context.Context, arg repo.GateEvalParams) (int64, error)
	listBlockingFindingsFn func(ctx context.Context, projectID pgtype.UUID, minSeverityRank int16) ([]sqlc.Finding, error)
	getFindingContextFn    func(ctx context.Context, findingID pgtype.UUID) (repo.FindingContext, error)
}

func (m *mockFindingRepo) Upsert(ctx context.Context, arg repo.UpsertFindingParams) (sqlc.Finding, error) {
	if m.upsertFn == nil {
		return sqlc.Finding{}, fmt.Errorf("unexpected call to Upsert")
	}
	return m.upsertFn(ctx, arg)
}

func (m *mockFindingRepo) CreateOccurrence(ctx context.Context, arg repo.CreateOccurrenceParams) (sqlc.FindingOccurrence, error) {
	if m.createOccurrenceFn == nil {
		return sqlc.FindingOccurrence{}, fmt.Errorf("unexpected call to CreateOccurrence")
	}
	return m.createOccurrenceFn(ctx, arg)
}

func (m *mockFindingRepo) UpsertDimension(ctx context.Context, arg repo.UpsertDimensionParams) (sqlc.FindingDimension, error) {
	if m.upsertDimensionFn == nil {
		return sqlc.FindingDimension{}, fmt.Errorf("unexpected call to UpsertDimension")
	}
	return m.upsertDimensionFn(ctx, arg)
}

func (m *mockFindingRepo) ListByProject(ctx context.Context, projectID pgtype.UUID, severities, states []string, limit, offset int32) ([]sqlc.Finding, error) {
	if m.listByProjectFn == nil {
		return []sqlc.Finding{}, nil
	}
	return m.listByProjectFn(ctx, projectID, severities, states, limit, offset)
}

func (m *mockFindingRepo) GetByID(ctx context.Context, id pgtype.UUID) (sqlc.Finding, error) {
	if m.getByIDFn == nil {
		return sqlc.Finding{}, fmt.Errorf("unexpected call to GetByID")
	}
	return m.getByIDFn(ctx, id)
}

func (m *mockFindingRepo) ListByIDs(ctx context.Context, ids []pgtype.UUID) ([]sqlc.Finding, error) {
	if m.listByIDsFn == nil {
		return nil, fmt.Errorf("unexpected call to ListByIDs")
	}
	return m.listByIDsFn(ctx, ids)
}

func (m *mockFindingRepo) BulkUpdateAnalysis(ctx context.Context, arg repo.BulkUpdateAnalysisParams) ([]sqlc.Finding, error) {
	if m.bulkUpdateAnalysisFn == nil {
		return nil, fmt.Errorf("unexpected call to BulkUpdateAnalysis")
	}
	return m.bulkUpdateAnalysisFn(ctx, arg)
}

func (m *mockFindingRepo) ListEvents(ctx context.Context, findingID pgtype.UUID, eventTypes []string, limit, offset int32) ([]sqlc.FindingEvent, error) {
	if m.listEventsFn == nil {
		return nil, fmt.Errorf("unexpected call to ListEvents")
	}
	return m.listEventsFn(ctx, findingID, eventTypes, limit, offset)
}

func (m *mockFindingRepo) GateEval(ctx context.Context, arg repo.GateEvalParams) (bool, error) {
	if m.gateEvalFn == nil {
		return false, fmt.Errorf("unexpected call to GateEval")
	}
	return m.gateEvalFn(ctx, arg)
}

func (m *mockFindingRepo) CountBlocking(ctx context.Context, arg repo.GateEvalParams) (int64, error) {
	if m.countBlockingFn == nil {
		return 0, fmt.Errorf("unexpected call to CountBlocking")
	}
	return m.countBlockingFn(ctx, arg)
}

func (m *mockFindingRepo) ListBlockingFindings(ctx context.Context, projectID pgtype.UUID, minSeverityRank int16) ([]sqlc.Finding, error) {
	if m.listBlockingFindingsFn == nil {
		return []sqlc.Finding{}, nil
	}
	return m.listBlockingFindingsFn(ctx, projectID, minSeverityRank)
}

func (m *mockFindingRepo) GetFindingContext(ctx context.Context, findingID pgtype.UUID) (repo.FindingContext, error) {
	if m.getFindingContextFn == nil {
		return repo.FindingContext{}, fmt.Errorf("unexpected call to GetFindingContext")
	}
	return m.getFindingContextFn(ctx, findingID)
}

func (m *mockFindingRepo) GetByFingerprint(ctx context.Context, arg repo.GetByFingerprintParams) (sqlc.Finding, error) {
	if m.getByFingerprintFn == nil {
		return sqlc.Finding{}, fmt.Errorf("unexpected call to GetByFingerprint")
	}
	return m.getByFingerprintFn(ctx, arg)
}

func (m *mockFindingRepo) HasDimension(ctx context.Context, findingID pgtype.UUID, key string) (bool, error) {
	if m.hasDimensionFn == nil {
		return false, nil
	}
	return m.hasDimensionFn(ctx, findingID, key)
}

func (m *mockFindingRepo) UpdateAnalysis(ctx context.Context, arg repo.UpdateAnalysisParams) (sqlc.Finding, error) {
	if m.updateAnalysisFn == nil {
		return sqlc.Finding{}, fmt.Errorf("unexpected call to UpdateAnalysis")
	}
	return m.updateAnalysisFn(ctx, arg)
}

func (m *mockFindingRepo) CreateEvent(ctx context.Context, arg repo.CreateEventParams) (sqlc.FindingEvent, error) {
	if m.createEventFn == nil {
		return sqlc.FindingEvent{}, nil
	}
	return m.createEventFn(ctx, arg)
}

type mockUserRepo struct {
	repo.UserRepo
	createFn     func(ctx context.Context, email string, displayName, passwordHash pgtype.Text) (sqlc.User, error)
	getByEmailFn func(ctx context.Context, email string) (sqlc.User, error)
	getByIDFn    func(ctx context.Context, id pgtype.UUID) (sqlc.User, error)
}

func (m *mockUserRepo) Create(ctx context.Context, email string, displayName, passwordHash pgtype.Text) (sqlc.User, error) {
	if m.createFn == nil {
		return sqlc.User{}, fmt.Errorf("unexpected call to Create")
	}
	return m.createFn(ctx, email, displayName, passwordHash)
}

func (m *mockUserRepo) GetByEmail(ctx context.Context, email string) (sqlc.User, error) {
	if m.getByEmailFn == nil {
		return sqlc.User{}, fmt.Errorf("unexpected call to GetByEmail")
	}
	return m.getByEmailFn(ctx, email)
}

func (m *mockUserRepo) GetByID(ctx context.Context, id pgtype.UUID) (sqlc.User, error) {
	if m.getByIDFn == nil {
		return sqlc.User{}, fmt.Errorf("unexpected call to GetByID")
	}
	return m.getByIDFn(ctx, id)
}

type mockRefreshTokenRepo struct {
	repo.RefreshTokenRepo
	createFn    func(ctx context.Context, userID pgtype.UUID, tokenHash string, expiresAt time.Time) (sqlc.RefreshToken, error)
	getByHashFn func(ctx context.Context, tokenHash string) (sqlc.RefreshToken, error)
	revokeFn    func(ctx context.Context, id pgtype.UUID) (sqlc.RefreshToken, error)
}

func (m *mockRefreshTokenRepo) Create(ctx context.Context, userID pgtype.UUID, tokenHash string, expiresAt time.Time) (sqlc.RefreshToken, error) {
	if m.createFn == nil {
		return sqlc.RefreshToken{}, fmt.Errorf("unexpected call to Create")
	}
	return m.createFn(ctx, userID, tokenHash, expiresAt)
}

func (m *mockRefreshTokenRepo) GetByHash(ctx context.Context, tokenHash string) (sqlc.RefreshToken, error) {
	if m.getByHashFn == nil {
		return sqlc.RefreshToken{}, fmt.Errorf("unexpected call to GetByHash")
	}
	return m.getByHashFn(ctx, tokenHash)
}

func (m *mockRefreshTokenRepo) Revoke(ctx context.Context, id pgtype.UUID) (sqlc.RefreshToken, error) {
	if m.revokeFn == nil {
		return sqlc.RefreshToken{}, fmt.Errorf("unexpected call to Revoke")
	}
	return m.revokeFn(ctx, id)
}

type mockAPIKeyRepo struct {
	repo.APIKeyRepo
	createFn        func(ctx context.Context, arg sqlc.CreateAPIKeyParams) (sqlc.ApiKey, error)
	listByProjectFn func(ctx context.Context, projectID pgtype.UUID) ([]sqlc.ListAPIKeysByProjectRow, error)
	revokeFn        func(ctx context.Context, id, projectID pgtype.UUID) (sqlc.ApiKey, error)
}

func (m *mockAPIKeyRepo) Create(ctx context.Context, arg sqlc.CreateAPIKeyParams) (sqlc.ApiKey, error) {
	if m.createFn == nil {
		return sqlc.ApiKey{}, fmt.Errorf("unexpected call to Create")
	}
	return m.createFn(ctx, arg)
}

type mockWaiverRepo struct {
	repo.WaiverRepo
	listActiveFn         func(ctx context.Context, projectID pgtype.UUID) ([]sqlc.Waiver, error)
	listConditionsFn     func(ctx context.Context, waiverID pgtype.UUID) ([]sqlc.WaiverCondition, error)
	listContextsFn       func(ctx context.Context, waiverID pgtype.UUID) ([]sqlc.WaiverContext, error)
	listFindingTargetsFn func(ctx context.Context, waiverID pgtype.UUID) ([]sqlc.WaiverFindingTarget, error)
}

func (m *mockWaiverRepo) ListActive(ctx context.Context, projectID pgtype.UUID) ([]sqlc.Waiver, error) {
	if m.listActiveFn == nil {
		return []sqlc.Waiver{}, nil
	}
	return m.listActiveFn(ctx, projectID)
}

func (m *mockWaiverRepo) ListConditions(ctx context.Context, waiverID pgtype.UUID) ([]sqlc.WaiverCondition, error) {
	if m.listConditionsFn == nil {
		return []sqlc.WaiverCondition{}, nil
	}
	return m.listConditionsFn(ctx, waiverID)
}

func (m *mockWaiverRepo) ListContexts(ctx context.Context, waiverID pgtype.UUID) ([]sqlc.WaiverContext, error) {
	if m.listContextsFn == nil {
		return []sqlc.WaiverContext{}, nil
	}
	return m.listContextsFn(ctx, waiverID)
}

func (m *mockWaiverRepo) ListFindingTargets(ctx context.Context, waiverID pgtype.UUID) ([]sqlc.WaiverFindingTarget, error) {
	if m.listFindingTargetsFn == nil {
		return []sqlc.WaiverFindingTarget{}, nil
	}
	return m.listFindingTargetsFn(ctx, waiverID)
}

func (m *mockAPIKeyRepo) ListByProject(ctx context.Context, projectID pgtype.UUID) ([]sqlc.ListAPIKeysByProjectRow, error) {
	if m.listByProjectFn == nil {
		return nil, fmt.Errorf("unexpected call to ListByProject")
	}
	return m.listByProjectFn(ctx, projectID)
}

func (m *mockAPIKeyRepo) Revoke(ctx context.Context, id, projectID pgtype.UUID) (sqlc.ApiKey, error) {
	if m.revokeFn == nil {
		return sqlc.ApiKey{}, fmt.Errorf("unexpected call to Revoke")
	}
	return m.revokeFn(ctx, id, projectID)
}

func (m *mockAPIKeyRepo) GetByHash(ctx context.Context, keyHash string) (sqlc.ApiKey, error) {
	return sqlc.ApiKey{}, fmt.Errorf("not implemented")
}

type mockParser struct {
	name      string
	scanTypes []scanner.ScanType
	parseFn   func(ctx context.Context, input []byte) (*scanner.NormalizedReport, error)
}

func (m *mockParser) Name() string                  { return m.name }
func (m *mockParser) ScanTypes() []scanner.ScanType { return m.scanTypes }
func (m *mockParser) Parse(ctx context.Context, r io.Reader) (*scanner.NormalizedReport, error) {
	if m.parseFn == nil {
		return nil, fmt.Errorf("unexpected call to Parse")
	}
	input, _ := io.ReadAll(r)
	return m.parseFn(ctx, input)
}

type mockTargetRepo struct {
	repo.TargetRepo
	upsertFn  func(ctx context.Context, arg sqlc.UpsertTargetParams) (sqlc.Target, error)
	listFn    func(ctx context.Context, projectID pgtype.UUID) ([]sqlc.Target, error)
	getByIDFn func(ctx context.Context, id, projectID pgtype.UUID) (sqlc.Target, error)
	deleteFn  func(ctx context.Context, id, projectID pgtype.UUID) (sqlc.Target, error)
}

func (m *mockTargetRepo) Upsert(ctx context.Context, arg sqlc.UpsertTargetParams) (sqlc.Target, error) {
	if m.upsertFn == nil {
		return sqlc.Target{}, fmt.Errorf("unexpected call to Upsert")
	}
	return m.upsertFn(ctx, arg)
}

func (m *mockTargetRepo) List(ctx context.Context, projectID pgtype.UUID) ([]sqlc.Target, error) {
	if m.listFn == nil {
		return nil, fmt.Errorf("unexpected call to List")
	}
	return m.listFn(ctx, projectID)
}

func (m *mockTargetRepo) GetByID(ctx context.Context, id, projectID pgtype.UUID) (sqlc.Target, error) {
	if m.getByIDFn == nil {
		return sqlc.Target{}, fmt.Errorf("unexpected call to GetByID")
	}
	return m.getByIDFn(ctx, id, projectID)
}

func (m *mockTargetRepo) Delete(ctx context.Context, id, projectID pgtype.UUID) (sqlc.Target, error) {
	if m.deleteFn == nil {
		return sqlc.Target{}, fmt.Errorf("unexpected call to Delete")
	}
	return m.deleteFn(ctx, id, projectID)
}

type mockEnvironmentRepo struct {
	repo.EnvironmentRepo
	upsertFn  func(ctx context.Context, arg sqlc.UpsertEnvironmentParams) (sqlc.Environment, error)
	listFn    func(ctx context.Context, projectID pgtype.UUID) ([]sqlc.Environment, error)
	getByIDFn func(ctx context.Context, id, projectID pgtype.UUID) (sqlc.Environment, error)
	deleteFn  func(ctx context.Context, id, projectID pgtype.UUID) (sqlc.Environment, error)
}

func (m *mockEnvironmentRepo) Upsert(ctx context.Context, arg sqlc.UpsertEnvironmentParams) (sqlc.Environment, error) {
	if m.upsertFn == nil {
		return sqlc.Environment{}, fmt.Errorf("unexpected call to Upsert")
	}
	return m.upsertFn(ctx, arg)
}

func (m *mockEnvironmentRepo) List(ctx context.Context, projectID pgtype.UUID) ([]sqlc.Environment, error) {
	if m.listFn == nil {
		return nil, fmt.Errorf("unexpected call to List")
	}
	return m.listFn(ctx, projectID)
}

func (m *mockEnvironmentRepo) GetByID(ctx context.Context, id, projectID pgtype.UUID) (sqlc.Environment, error) {
	if m.getByIDFn == nil {
		return sqlc.Environment{}, fmt.Errorf("unexpected call to GetByID")
	}
	return m.getByIDFn(ctx, id, projectID)
}

func (m *mockEnvironmentRepo) Delete(ctx context.Context, id, projectID pgtype.UUID) (sqlc.Environment, error) {
	if m.deleteFn == nil {
		return sqlc.Environment{}, fmt.Errorf("unexpected call to Delete")
	}
	return m.deleteFn(ctx, id, projectID)
}

type mockArtifactRepo struct {
	repo.ArtifactRepo
	upsertFn       func(ctx context.Context, arg sqlc.UpsertArtifactParams) (sqlc.Artifact, error)
	listFn         func(ctx context.Context, projectID pgtype.UUID) ([]sqlc.Artifact, error)
	listByTargetFn func(ctx context.Context, targetID pgtype.UUID) ([]sqlc.Artifact, error)
	getByIDFn      func(ctx context.Context, id, projectID pgtype.UUID) (sqlc.Artifact, error)
	deleteFn       func(ctx context.Context, id, projectID pgtype.UUID) (sqlc.Artifact, error)
}

func (m *mockArtifactRepo) Upsert(ctx context.Context, arg sqlc.UpsertArtifactParams) (sqlc.Artifact, error) {
	if m.upsertFn == nil {
		return sqlc.Artifact{}, fmt.Errorf("unexpected call to Upsert")
	}
	return m.upsertFn(ctx, arg)
}

func (m *mockArtifactRepo) List(ctx context.Context, projectID pgtype.UUID) ([]sqlc.Artifact, error) {
	if m.listFn == nil {
		return nil, fmt.Errorf("unexpected call to List")
	}
	return m.listFn(ctx, projectID)
}

func (m *mockArtifactRepo) ListByTarget(ctx context.Context, targetID pgtype.UUID) ([]sqlc.Artifact, error) {
	if m.listByTargetFn == nil {
		return nil, fmt.Errorf("unexpected call to ListByTarget")
	}
	return m.listByTargetFn(ctx, targetID)
}

func (m *mockArtifactRepo) GetByID(ctx context.Context, id, projectID pgtype.UUID) (sqlc.Artifact, error) {
	if m.getByIDFn == nil {
		return sqlc.Artifact{}, fmt.Errorf("unexpected call to GetByID")
	}
	return m.getByIDFn(ctx, id, projectID)
}

func (m *mockArtifactRepo) Delete(ctx context.Context, id, projectID pgtype.UUID) (sqlc.Artifact, error) {
	if m.deleteFn == nil {
		return sqlc.Artifact{}, fmt.Errorf("unexpected call to Delete")
	}
	return m.deleteFn(ctx, id, projectID)
}

func makeTestRepos() (*mockProjectRepo, *mockReportRepo, *mockFindingRepo) {
	pr := &mockProjectRepo{}
	rr := &mockReportRepo{}
	fr := &mockFindingRepo{}
	return pr, rr, fr
}

func stubTargetRepo() *mockTargetRepo {
	tr := &mockTargetRepo{}
	tr.upsertFn = func(ctx context.Context, arg sqlc.UpsertTargetParams) (sqlc.Target, error) {
		return sqlc.Target{ID: arg.ProjectID, ProjectID: arg.ProjectID, Name: arg.Name, Kind: arg.Kind}, nil
	}
	return tr
}

func stubArtifactRepo() *mockArtifactRepo {
	ar := &mockArtifactRepo{}
	ar.upsertFn = func(ctx context.Context, arg sqlc.UpsertArtifactParams) (sqlc.Artifact, error) {
		return sqlc.Artifact{ID: arg.ProjectID, ProjectID: arg.ProjectID, Name: arg.Name}, nil
	}
	return ar
}

func TestCreateProject_Success(t *testing.T) {
	pr, _, _ := makeTestRepos()

	pr.createFn = func(ctx context.Context, arg sqlc.CreateProjectParams) (sqlc.Project, error) {
		return makeProject(true), nil
	}

	uc := New(Deps{
		Repos: &repo.Repos{Projects: pr},
	})

	result, err := uc.CreateProject(context.Background(), "My App", "my-app", "test description")
	require.NoError(t, err)
	require.NotNil(t, result)
	assert.Equal(t, "my-app", result.Slug)
	assert.Equal(t, "My App", result.Name)
}

func makeProject(valid bool) sqlc.Project {
	if !valid {
		return sqlc.Project{}
	}
	var id pgtype.UUID
	id.Scan("00000000-0000-0000-0000-000000000001")
	return sqlc.Project{
		ID:   id,
		Slug: "my-app",
		Name: "My App",
	}
}

func makeUser(id string) sqlc.User {
	var uid pgtype.UUID
	uid.Scan(id)
	var now pgtype.Timestamptz
	now.Scan(time.Now())
	return sqlc.User{
		ID:        uid,
		Email:     "test@example.com",
		Role:      "user",
		CreatedAt: now,
	}
}

func makeRefreshToken(revoked bool) sqlc.RefreshToken {
	var id, uid pgtype.UUID
	id.Scan("00000000-0000-0000-0000-000000000030")
	uid.Scan("00000000-0000-0000-0000-000000000040")
	var expires pgtype.Timestamptz
	expires.Scan(time.Now().Add(7 * 24 * time.Hour))
	var revokedAt pgtype.Timestamptz
	if revoked {
		revokedAt.Scan(time.Now())
	}
	return sqlc.RefreshToken{
		ID:        id,
		UserID:    uid,
		TokenHash: "somehash",
		ExpiresAt: expires,
		RevokedAt: revokedAt,
	}
}

func makeReport() sqlc.Report {
	var id, pid pgtype.UUID
	id.Scan("00000000-0000-0000-0000-000000000010")
	pid.Scan("00000000-0000-0000-0000-000000000001")
	return sqlc.Report{
		ID:            id,
		ProjectID:     pid,
		ToolName:      "trivy",
		Status:        "completed",
		TotalFindings: pgtype.Int4{Int32: 2, Valid: true},
	}
}

func makeFinding(idIdx int) sqlc.Finding {
	var id, pid pgtype.UUID
	id.Scan(fmt.Sprintf("00000000-0000-0000-0000-00000000002%d", idIdx))
	pid.Scan("00000000-0000-0000-0000-000000000001")
	return sqlc.Finding{
		ID:          id,
		ProjectID:   pid,
		FindingKind: "sca",
		Fingerprint: "fp1",
	}
}

func TestIngestReport_Success(t *testing.T) {
	pr, rr, fr := makeTestRepos()

	pr.getBySlugFn = func(ctx context.Context, slug string) (sqlc.Project, error) {
		return makeProject(true), nil
	}

	rr.createFn = func(ctx context.Context, arg repo.CreateReportParams) (sqlc.Report, error) {
		return makeReport(), nil
	}

	rr.updateStatusFn = func(ctx context.Context, id, projectID pgtype.UUID, status string, totalFindings int, errorMsg pgtype.Text) (sqlc.Report, error) {
		r := makeReport()
		r.Status = status
		return r, nil
	}

	callCount := 0
	fr.getByFingerprintFn = func(ctx context.Context, arg repo.GetByFingerprintParams) (sqlc.Finding, error) {
		return sqlc.Finding{}, fmt.Errorf("not found")
	}
	fr.upsertFn = func(ctx context.Context, arg repo.UpsertFindingParams) (sqlc.Finding, error) {
		callCount++
		return makeFinding(callCount), nil
	}

	fr.createOccurrenceFn = func(ctx context.Context, arg repo.CreateOccurrenceParams) (sqlc.FindingOccurrence, error) {
		return sqlc.FindingOccurrence{}, nil
	}

	fr.upsertDimensionFn = func(ctx context.Context, arg repo.UpsertDimensionParams) (sqlc.FindingDimension, error) {
		return sqlc.FindingDimension{}, nil
	}

	reg := scanner.NewRegistry()
	reg.Register(&mockParser{
		name:      "trivy",
		scanTypes: []scanner.ScanType{scanner.ScanTypeImage},
		parseFn: func(ctx context.Context, input []byte) (*scanner.NormalizedReport, error) {
			return &scanner.NormalizedReport{
				ScannerName: "trivy",
				ScanType:    scanner.ScanTypeImage,
				Target:      &scanner.TargetInfo{Kind: "container", Identifier: "myapp:latest"},
				Findings: []scanner.NormalizedFinding{
					{
						Fingerprint: "fp1",
						FindingKind: "sca",
						Title:       "CVE-2026-1234",
						Severity:    scanner.SeverityHigh,
						Score:       7.5,
						Dimensions:  []scanner.Dimension{{Key: "vulnerability.id", Value: "CVE-2026-1234"}},
						Display:     map[string]any{"title": "CVE-2026-1234"},
						Metadata:    map[string]any{"cvss": "7.5"},
					},
					{
						Fingerprint: "fp2",
						FindingKind: "sca",
						Title:       "CVE-2026-5678",
						Severity:    scanner.SeverityMedium,
						Score:       5.0,
					},
				},
				ScanScope: map[string]any{"packages": 150},
			}, nil
		},
	})

	uc := New(Deps{
		Repos: &repo.Repos{
			Projects:     pr,
			Reports:      rr,
			Findings:     fr,
			Targets:      stubTargetRepo(),
			Artifacts:    stubArtifactRepo(),
			Environments: &mockEnvironmentRepo{},
		},
		Registry: reg,
	})

	result, err := uc.IngestReport(context.Background(), IngestReportInput{
		ProjectSlug: "my-app",
		Scanner:     "trivy",
		RawData:     json.RawMessage(`{"test": true}`),
	})
	require.NoError(t, err)
	require.NotNil(t, result)
	assert.Equal(t, 2, result.TotalFindings)
	assert.NotEmpty(t, result.ReportID)
	assert.False(t, result.ThresholdBreached)
}

func TestIngestReport_EmptySlug(t *testing.T) {
	uc := New(Deps{})
	_, err := uc.IngestReport(context.Background(), IngestReportInput{})
	assert.EqualError(t, err, "project slug is required")
}

func TestIngestReport_EmptyScanner(t *testing.T) {
	uc := New(Deps{})
	_, err := uc.IngestReport(context.Background(), IngestReportInput{ProjectSlug: "my-app"})
	assert.EqualError(t, err, "scanner name is required")
}

func TestIngestReport_EmptyData(t *testing.T) {
	uc := New(Deps{})
	_, err := uc.IngestReport(context.Background(), IngestReportInput{ProjectSlug: "my-app", Scanner: "trivy"})
	assert.EqualError(t, err, "raw scan data is required")
}

func TestIngestReport_UnknownProject(t *testing.T) {
	pr, _, _ := makeTestRepos()
	pr.getBySlugFn = func(ctx context.Context, slug string) (sqlc.Project, error) {
		return sqlc.Project{}, fmt.Errorf("not found")
	}

	uc := New(Deps{
		Repos: &repo.Repos{Projects: pr},
	})
	_, err := uc.IngestReport(context.Background(), IngestReportInput{
		ProjectSlug: "nonexistent",
		Scanner:     "trivy",
		RawData:     json.RawMessage(`{}`),
	})
	assert.ErrorContains(t, err, "lookup project")
}

func TestIngestReport_UnknownScanner(t *testing.T) {
	pr, _, _ := makeTestRepos()
	pr.getBySlugFn = func(ctx context.Context, slug string) (sqlc.Project, error) {
		return makeProject(true), nil
	}

	uc := New(Deps{
		Repos:    &repo.Repos{Projects: pr},
		Registry: scanner.NewRegistry(),
	})
	_, err := uc.IngestReport(context.Background(), IngestReportInput{
		ProjectSlug: "my-app",
		Scanner:     "unknown-tool",
		RawData:     json.RawMessage(`{}`),
	})
	assert.ErrorContains(t, err, "unknown scanner")
}

func TestIngestReport_ParseError(t *testing.T) {
	pr, _, _ := makeTestRepos()
	pr.getBySlugFn = func(ctx context.Context, slug string) (sqlc.Project, error) {
		return makeProject(true), nil
	}

	reg := scanner.NewRegistry()
	reg.Register(&mockParser{
		name:      "trivy",
		scanTypes: []scanner.ScanType{scanner.ScanTypeImage},
		parseFn: func(ctx context.Context, input []byte) (*scanner.NormalizedReport, error) {
			return nil, fmt.Errorf("invalid scan data")
		},
	})

	uc := New(Deps{
		Repos: &repo.Repos{
			Projects:     pr,
			Targets:      stubTargetRepo(),
			Artifacts:    stubArtifactRepo(),
			Environments: &mockEnvironmentRepo{},
		},
		Registry: reg,
	})
	_, err := uc.IngestReport(context.Background(), IngestReportInput{
		ProjectSlug: "my-app",
		Scanner:     "trivy",
		RawData:     json.RawMessage(`bad data`),
	})
	assert.ErrorContains(t, err, "scanner trivy: parse output")
}

func TestIngestReport_Duplicate(t *testing.T) {
	pr, rr, _ := makeTestRepos()

	pr.getBySlugFn = func(ctx context.Context, slug string) (sqlc.Project, error) {
		return makeProject(true), nil
	}

	rr.createFn = func(ctx context.Context, arg repo.CreateReportParams) (sqlc.Report, error) {
		return sqlc.Report{}, &pgconn.PgError{Code: "23505"}
	}

	reg := scanner.NewRegistry()
	reg.Register(&mockParser{
		name:      "trivy",
		scanTypes: []scanner.ScanType{scanner.ScanTypeImage},
		parseFn: func(ctx context.Context, input []byte) (*scanner.NormalizedReport, error) {
			return &scanner.NormalizedReport{
				ScannerName: "trivy",
				ScanType:    scanner.ScanTypeImage,
				Target:      &scanner.TargetInfo{Kind: "container", Identifier: "myapp:latest"},
				Findings:    []scanner.NormalizedFinding{},
				ScanScope:   map[string]any{},
			}, nil
		},
	})

	uc := New(Deps{
		Repos: &repo.Repos{
			Projects:     pr,
			Reports:      rr,
			Targets:      stubTargetRepo(),
			Artifacts:    stubArtifactRepo(),
			Environments: &mockEnvironmentRepo{},
		},
		Registry: reg,
	})

	_, err := uc.IngestReport(context.Background(), IngestReportInput{
		ProjectSlug: "my-app",
		Scanner:     "trivy",
		RawData:     json.RawMessage(`{"test": true}`),
	})
	assert.ErrorIs(t, err, ErrDuplicateReport)
}

func TestIngestReport_ThresholdBreached(t *testing.T) {
	pr, rr, fr := makeTestRepos()

	pr.getBySlugFn = func(ctx context.Context, slug string) (sqlc.Project, error) {
		return makeProject(true), nil
	}

	rr.createFn = func(ctx context.Context, arg repo.CreateReportParams) (sqlc.Report, error) {
		return makeReport(), nil
	}

	rr.updateStatusFn = func(ctx context.Context, id, projectID pgtype.UUID, status string, totalFindings int, errorMsg pgtype.Text) (sqlc.Report, error) {
		r := makeReport()
		r.Status = status
		return r, nil
	}

	fr.getByFingerprintFn = func(ctx context.Context, arg repo.GetByFingerprintParams) (sqlc.Finding, error) {
		return sqlc.Finding{}, fmt.Errorf("not found")
	}

	fr.upsertFn = func(ctx context.Context, arg repo.UpsertFindingParams) (sqlc.Finding, error) {
		return makeFinding(1), nil
	}

	fr.createOccurrenceFn = func(ctx context.Context, arg repo.CreateOccurrenceParams) (sqlc.FindingOccurrence, error) {
		return sqlc.FindingOccurrence{}, nil
	}

	fr.upsertDimensionFn = func(ctx context.Context, arg repo.UpsertDimensionParams) (sqlc.FindingDimension, error) {
		return sqlc.FindingDimension{}, nil
	}

	fr.listByProjectFn = func(ctx context.Context, projectID pgtype.UUID, severities, states []string, limit, offset int32) ([]sqlc.Finding, error) {
		return []sqlc.Finding{makeFinding(1)}, nil
	}

	reg := scanner.NewRegistry()
	reg.Register(&mockParser{
		name:      "trivy",
		scanTypes: []scanner.ScanType{scanner.ScanTypeImage},
		parseFn: func(ctx context.Context, input []byte) (*scanner.NormalizedReport, error) {
			return &scanner.NormalizedReport{
				ScannerName: "trivy",
				ScanType:    scanner.ScanTypeImage,
				Target:      &scanner.TargetInfo{Kind: "container", Identifier: "myapp:latest"},
				Findings: []scanner.NormalizedFinding{
					{Fingerprint: "fp1", FindingKind: "sca", Title: "CVE-2026-1234", Severity: scanner.SeverityCritical, Score: 9.5},
				},
				ScanScope: map[string]any{},
			}, nil
		},
	})

	uc := New(Deps{
		Repos: &repo.Repos{
			Projects:     pr,
			Reports:      rr,
			Findings:     fr,
			Targets:      stubTargetRepo(),
			Artifacts:    stubArtifactRepo(),
			Environments: &mockEnvironmentRepo{},
		},
		Registry: reg,
	})

	result, err := uc.IngestReport(context.Background(), IngestReportInput{
		ProjectSlug: "my-app",
		Scanner:     "trivy",
		RawData:     json.RawMessage(`{"test": true}`),
	})
	require.NoError(t, err)
	assert.True(t, result.ThresholdBreached)
}

func TestIngestReport_ErrorWrapping(t *testing.T) {
	pr, _, _ := makeTestRepos()
	pr.getBySlugFn = func(ctx context.Context, slug string) (sqlc.Project, error) {
		return makeProject(true), nil
	}

	reg := scanner.NewRegistry()
	reg.Register(&mockParser{
		name:      "trivy",
		scanTypes: []scanner.ScanType{scanner.ScanTypeImage},
		parseFn: func(ctx context.Context, input []byte) (*scanner.NormalizedReport, error) {
			return nil, fmt.Errorf("malformed data")
		},
	})

	uc := New(Deps{
		Repos: &repo.Repos{
			Projects:     pr,
			Targets:      stubTargetRepo(),
			Artifacts:    stubArtifactRepo(),
			Environments: &mockEnvironmentRepo{},
		},
		Registry: reg,
	})

	_, err := uc.IngestReport(context.Background(), IngestReportInput{
		ProjectSlug: "my-app",
		Scanner:     "trivy",
		RawData:     json.RawMessage(`bad`),
	})
	require.Error(t, err)
	assert.ErrorContains(t, err, "scanner trivy")
}

func TestIngestReport_PartialFailure(t *testing.T) {
	pr, rr, fr := makeTestRepos()

	pr.getBySlugFn = func(ctx context.Context, slug string) (sqlc.Project, error) {
		return makeProject(true), nil
	}

	rr.createFn = func(ctx context.Context, arg repo.CreateReportParams) (sqlc.Report, error) {
		return makeReport(), nil
	}

	rr.updateStatusFn = func(ctx context.Context, id, projectID pgtype.UUID, status string, totalFindings int, errorMsg pgtype.Text) (sqlc.Report, error) {
		r := makeReport()
		r.Status = status
		return r, nil
	}

	callCount := 0
	fr.getByFingerprintFn = func(ctx context.Context, arg repo.GetByFingerprintParams) (sqlc.Finding, error) {
		return sqlc.Finding{}, fmt.Errorf("not found")
	}
	fr.upsertFn = func(ctx context.Context, arg repo.UpsertFindingParams) (sqlc.Finding, error) {
		callCount++
		if callCount == 2 {
			return sqlc.Finding{}, fmt.Errorf("db unavailable")
		}
		return makeFinding(callCount), nil
	}

	fr.createOccurrenceFn = func(ctx context.Context, arg repo.CreateOccurrenceParams) (sqlc.FindingOccurrence, error) {
		return sqlc.FindingOccurrence{}, nil
	}

	fr.upsertDimensionFn = func(ctx context.Context, arg repo.UpsertDimensionParams) (sqlc.FindingDimension, error) {
		return sqlc.FindingDimension{}, nil
	}

	reg := scanner.NewRegistry()
	reg.Register(&mockParser{
		name:      "trivy",
		scanTypes: []scanner.ScanType{scanner.ScanTypeImage},
		parseFn: func(ctx context.Context, input []byte) (*scanner.NormalizedReport, error) {
			return &scanner.NormalizedReport{
				ScannerName: "trivy",
				ScanType:    scanner.ScanTypeImage,
				Target:      &scanner.TargetInfo{Kind: "container", Identifier: "myapp:latest"},
				Findings: []scanner.NormalizedFinding{
					{Fingerprint: "fp1", FindingKind: "sca", Title: "CVE-2026-0001", Severity: scanner.SeverityHigh, Score: 7.5},
					{Fingerprint: "fp2", FindingKind: "sca", Title: "CVE-2026-0002", Severity: scanner.SeverityMedium, Score: 5.0},
				},
				ScanScope: map[string]any{},
			}, nil
		},
	})

	uc := New(Deps{
		Repos: &repo.Repos{
			Projects:     pr,
			Reports:      rr,
			Findings:     fr,
			Targets:      stubTargetRepo(),
			Artifacts:    stubArtifactRepo(),
			Environments: &mockEnvironmentRepo{},
		},
		Registry: reg,
	})

	_, err := uc.IngestReport(context.Background(), IngestReportInput{
		ProjectSlug: "my-app",
		Scanner:     "trivy",
		RawData:     json.RawMessage(`{"test": true}`),
	})
	require.Error(t, err)
	assert.ErrorContains(t, err, "scanner trivy")
	assert.ErrorContains(t, err, "upsert finding")
	assert.NotContains(t, err.Error(), "lookup project")
}

func testJWT(t *testing.T) *auth.JWTAuthenticator {
	a, err := auth.NewJWTAuthenticator("test-secret-for-tests-1234567890")
	require.NoError(t, err)
	return a
}

func makeFindingRow(id int) sqlc.Finding {
	var fid pgtype.UUID
	fid.Scan(fmt.Sprintf("00000000-0000-0000-0000-00000000002%d", id))
	var pid pgtype.UUID
	pid.Scan("00000000-0000-0000-0000-000000000001")
	var now pgtype.Timestamptz
	now.Scan(time.Now())
	return sqlc.Finding{
		ID:                  fid,
		ProjectID:           pid,
		FindingKind:         "sca",
		Fingerprint:         fmt.Sprintf("fp%d", id),
		CurrentTitle:        fmt.Sprintf("CVE-%d", 2026000+id),
		CurrentSeverity:     "high",
		CurrentSeverityRank: 2,
		State:               "open",
		TriageStatus:        "untriaged",
		AnalysisState:       "unanalyzed",
		GateEffect:          "block",
		FirstSeenAt:         now,
		LastSeenAt:          now,
		CreatedAt:           now,
		UpdatedAt:           now,
	}
}

// ----- Auth Usecase Tests -----

func TestRegister_Success(t *testing.T) {
	ur := &mockUserRepo{}
	rr := &mockRefreshTokenRepo{}
	jwt := testJWT(t)

	ur.getByEmailFn = func(ctx context.Context, email string) (sqlc.User, error) {
		return sqlc.User{}, fmt.Errorf("not found")
	}
	ur.createFn = func(ctx context.Context, email string, displayName, passwordHash pgtype.Text) (sqlc.User, error) {
		u := makeUser("00000000-0000-0000-0000-000000000040")
		u.Email = email
		u.PasswordHash = passwordHash
		return u, nil
	}
	rr.createFn = func(ctx context.Context, userID pgtype.UUID, tokenHash string, expiresAt time.Time) (sqlc.RefreshToken, error) {
		return makeRefreshToken(false), nil
	}

	uc := New(Deps{
		Repos:   &repo.Repos{Users: ur, RefreshTokens: rr},
		JWTAuth: jwt,
	})

	resp, err := uc.Register(context.Background(), "new@example.com", "password123")
	require.NoError(t, err)
	require.NotNil(t, resp)
	assert.Equal(t, "new@example.com", resp.Email)
	assert.NotEmpty(t, resp.UserID)
	assert.NotEmpty(t, resp.Token)
	assert.NotEmpty(t, resp.RefreshToken)
}

func TestRegister_EmptyEmail(t *testing.T) {
	uc := New(Deps{})
	_, err := uc.Register(context.Background(), "", "password123")
	assert.EqualError(t, err, "email and password are required")
}

func TestRegister_EmptyPassword(t *testing.T) {
	uc := New(Deps{})
	_, err := uc.Register(context.Background(), "test@example.com", "")
	assert.EqualError(t, err, "email and password are required")
}

func TestRegister_ShortPassword(t *testing.T) {
	uc := New(Deps{})
	_, err := uc.Register(context.Background(), "test@example.com", "short")
	assert.EqualError(t, err, "password must be at least 8 characters")
}

func TestRegister_ExistingEmail(t *testing.T) {
	ur := &mockUserRepo{}
	ur.getByEmailFn = func(ctx context.Context, email string) (sqlc.User, error) {
		return makeUser("00000000-0000-0000-0000-000000000040"), nil
	}

	uc := New(Deps{
		Repos: &repo.Repos{Users: ur},
	})

	_, err := uc.Register(context.Background(), "test@example.com", "password123")
	assert.EqualError(t, err, "email already registered")
}

// ----- Login Tests -----

func TestLogin_Success(t *testing.T) {
	ur := &mockUserRepo{}
	rr := &mockRefreshTokenRepo{}
	jwt := testJWT(t)

	hash, err := auth.HashPassword("correct-password")
	require.NoError(t, err)

	ur.getByEmailFn = func(ctx context.Context, email string) (sqlc.User, error) {
		u := makeUser("00000000-0000-0000-0000-000000000040")
		u.PasswordHash = pgtype.Text{String: hash, Valid: true}
		return u, nil
	}
	rr.createFn = func(ctx context.Context, userID pgtype.UUID, tokenHash string, expiresAt time.Time) (sqlc.RefreshToken, error) {
		return makeRefreshToken(false), nil
	}

	uc := New(Deps{
		Repos:   &repo.Repos{Users: ur, RefreshTokens: rr},
		JWTAuth: jwt,
	})

	resp, err := uc.Login(context.Background(), "test@example.com", "correct-password")
	require.NoError(t, err)
	require.NotNil(t, resp)
	assert.Equal(t, "test@example.com", resp.Email)
	assert.NotEmpty(t, resp.Token)
	assert.NotEmpty(t, resp.RefreshToken)
}

func TestLogin_EmptyEmail(t *testing.T) {
	uc := New(Deps{})
	_, err := uc.Login(context.Background(), "", "password")
	assert.EqualError(t, err, "email and password are required")
}

func TestLogin_EmptyPassword(t *testing.T) {
	uc := New(Deps{})
	_, err := uc.Login(context.Background(), "test@example.com", "")
	assert.EqualError(t, err, "email and password are required")
}

func TestLogin_UserNotFound(t *testing.T) {
	ur := &mockUserRepo{}
	ur.getByEmailFn = func(ctx context.Context, email string) (sqlc.User, error) {
		return sqlc.User{}, fmt.Errorf("not found")
	}

	uc := New(Deps{
		Repos: &repo.Repos{Users: ur},
	})

	_, err := uc.Login(context.Background(), "unknown@example.com", "password123")
	assert.EqualError(t, err, "invalid email or password")
}

func TestLogin_NoPasswordHash(t *testing.T) {
	ur := &mockUserRepo{}
	ur.getByEmailFn = func(ctx context.Context, email string) (sqlc.User, error) {
		u := makeUser("00000000-0000-0000-0000-000000000040")
		u.PasswordHash = pgtype.Text{Valid: false}
		return u, nil
	}

	uc := New(Deps{
		Repos: &repo.Repos{Users: ur},
	})

	_, err := uc.Login(context.Background(), "test@example.com", "password123")
	assert.EqualError(t, err, "invalid email or password")
}

func TestLogin_WrongPassword(t *testing.T) {
	ur := &mockUserRepo{}
	jwt := testJWT(t)

	hash, err := auth.HashPassword("real-password")
	require.NoError(t, err)

	ur.getByEmailFn = func(ctx context.Context, email string) (sqlc.User, error) {
		u := makeUser("00000000-0000-0000-0000-000000000040")
		u.PasswordHash = pgtype.Text{String: hash, Valid: true}
		return u, nil
	}

	uc := New(Deps{
		Repos:   &repo.Repos{Users: ur},
		JWTAuth: jwt,
	})

	_, err = uc.Login(context.Background(), "test@example.com", "wrong-password")
	assert.EqualError(t, err, "invalid email or password")
}

// ----- Refresh Tests -----

func TestRefresh_Success(t *testing.T) {
	rr := &mockRefreshTokenRepo{}
	ur := &mockUserRepo{}
	jwt := testJWT(t)

	token := makeRefreshToken(false)

	rr.getByHashFn = func(ctx context.Context, tokenHash string) (sqlc.RefreshToken, error) {
		return token, nil
	}
	rr.revokeFn = func(ctx context.Context, id pgtype.UUID) (sqlc.RefreshToken, error) {
		return makeRefreshToken(true), nil
	}
	rr.createFn = func(ctx context.Context, userID pgtype.UUID, tokenHash string, expiresAt time.Time) (sqlc.RefreshToken, error) {
		return makeRefreshToken(false), nil
	}
	ur.getByIDFn = func(ctx context.Context, id pgtype.UUID) (sqlc.User, error) {
		return makeUser("00000000-0000-0000-0000-000000000040"), nil
	}

	uc := New(Deps{
		Repos:   &repo.Repos{RefreshTokens: rr, Users: ur},
		JWTAuth: jwt,
	})

	resp, err := uc.Refresh(context.Background(), "some-valid-refresh-token")
	require.NoError(t, err)
	require.NotNil(t, resp)
	assert.NotEmpty(t, resp.Token)
	assert.NotEmpty(t, resp.RefreshToken)
	assert.Equal(t, "test@example.com", resp.Email)
}

func TestRefresh_EmptyToken(t *testing.T) {
	uc := New(Deps{})
	_, err := uc.Refresh(context.Background(), "")
	assert.EqualError(t, err, "refresh_token is required")
}

func TestRefresh_InvalidToken(t *testing.T) {
	rr := &mockRefreshTokenRepo{}
	rr.getByHashFn = func(ctx context.Context, tokenHash string) (sqlc.RefreshToken, error) {
		return sqlc.RefreshToken{}, fmt.Errorf("not found")
	}

	uc := New(Deps{
		Repos: &repo.Repos{RefreshTokens: rr},
	})

	_, err := uc.Refresh(context.Background(), "invalid-token")
	assert.EqualError(t, err, "invalid refresh token")
}

func TestRefresh_RevokedToken(t *testing.T) {
	rr := &mockRefreshTokenRepo{}
	rr.getByHashFn = func(ctx context.Context, tokenHash string) (sqlc.RefreshToken, error) {
		return makeRefreshToken(true), nil
	}

	uc := New(Deps{
		Repos: &repo.Repos{RefreshTokens: rr},
	})

	_, err := uc.Refresh(context.Background(), "revoked-token")
	assert.EqualError(t, err, "refresh token has been revoked")
}

func TestRefresh_ExpiredToken(t *testing.T) {
	rr := &mockRefreshTokenRepo{}

	var expired pgtype.Timestamptz
	expired.Scan(time.Now().Add(-1 * time.Hour))

	rr.getByHashFn = func(ctx context.Context, tokenHash string) (sqlc.RefreshToken, error) {
		tok := makeRefreshToken(false)
		tok.ExpiresAt = expired
		return tok, nil
	}

	uc := New(Deps{
		Repos: &repo.Repos{RefreshTokens: rr},
	})

	_, err := uc.Refresh(context.Background(), "expired-token")
	assert.EqualError(t, err, "refresh token has expired")
}

// ----- Logout Tests -----

func TestLogout_Success(t *testing.T) {
	rr := &mockRefreshTokenRepo{}
	rr.getByHashFn = func(ctx context.Context, tokenHash string) (sqlc.RefreshToken, error) {
		return makeRefreshToken(false), nil
	}
	rr.revokeFn = func(ctx context.Context, id pgtype.UUID) (sqlc.RefreshToken, error) {
		return makeRefreshToken(true), nil
	}

	uc := New(Deps{
		Repos: &repo.Repos{RefreshTokens: rr},
	})

	err := uc.Logout(context.Background(), "valid-token")
	require.NoError(t, err)
}

func TestLogout_EmptyToken(t *testing.T) {
	uc := New(Deps{})
	err := uc.Logout(context.Background(), "")
	require.NoError(t, err)
}

func TestLogout_InvalidToken(t *testing.T) {
	rr := &mockRefreshTokenRepo{}
	rr.getByHashFn = func(ctx context.Context, tokenHash string) (sqlc.RefreshToken, error) {
		return sqlc.RefreshToken{}, fmt.Errorf("not found")
	}

	uc := New(Deps{
		Repos: &repo.Repos{RefreshTokens: rr},
	})

	err := uc.Logout(context.Background(), "invalid-token")
	require.NoError(t, err)
}

// ----- GetProfile Tests -----

func TestGetProfile_Success(t *testing.T) {
	ur := &mockUserRepo{}
	ur.getByIDFn = func(ctx context.Context, id pgtype.UUID) (sqlc.User, error) {
		return makeUser("00000000-0000-0000-0000-000000000040"), nil
	}

	uc := New(Deps{
		Repos: &repo.Repos{Users: ur},
	})

	profile, err := uc.GetProfile(context.Background(), "00000000-0000-0000-0000-000000000040")
	require.NoError(t, err)
	require.NotNil(t, profile)
	assert.Equal(t, "00000000-0000-0000-0000-000000000040", profile.ID)
	assert.Equal(t, "test@example.com", profile.Email)
	assert.Equal(t, "user", profile.Role)
}

func TestGetProfile_InvalidUUID(t *testing.T) {
	uc := New(Deps{})
	_, err := uc.GetProfile(context.Background(), "not-a-uuid")
	assert.ErrorContains(t, err, "invalid user id")
}

func TestGetProfile_UserNotFound(t *testing.T) {
	ur := &mockUserRepo{}
	ur.getByIDFn = func(ctx context.Context, id pgtype.UUID) (sqlc.User, error) {
		return sqlc.User{}, fmt.Errorf("not found")
	}

	uc := New(Deps{
		Repos: &repo.Repos{Users: ur},
	})

	_, err := uc.GetProfile(context.Background(), "00000000-0000-0000-0000-000000000001")
	assert.EqualError(t, err, "user not found")
}

// ----- GetFinding Tests -----

func TestGetFinding_Success(t *testing.T) {
	fr := &mockFindingRepo{}
	fr.getByFingerprintFn = func(ctx context.Context, arg repo.GetByFingerprintParams) (sqlc.Finding, error) {
		return sqlc.Finding{}, fmt.Errorf("not used")
	}

	fr.getByFingerprintFn = nil
	fr.getByIDFn = func(ctx context.Context, id pgtype.UUID) (sqlc.Finding, error) {
		return makeFindingRow(1), nil
	}

	uc := New(Deps{
		Repos: &repo.Repos{Findings: fr},
	})

	finding, err := uc.GetFinding(context.Background(), "00000000-0000-0000-0000-000000000021")
	require.NoError(t, err)
	require.NotNil(t, finding)
	assert.Equal(t, "00000000-0000-0000-0000-000000000021", finding.ID)
	assert.Equal(t, "sca", finding.FindingKind)
	assert.Equal(t, "CVE-2026001", finding.CurrentTitle)
}

func TestGetFinding_InvalidUUID(t *testing.T) {
	uc := New(Deps{})
	_, err := uc.GetFinding(context.Background(), "not-a-uuid")
	assert.ErrorContains(t, err, "invalid finding id")
}

func TestGetFinding_NotFound(t *testing.T) {
	fr := &mockFindingRepo{}
	fr.getByIDFn = func(ctx context.Context, id pgtype.UUID) (sqlc.Finding, error) {
		return sqlc.Finding{}, fmt.Errorf("not found")
	}

	uc := New(Deps{
		Repos: &repo.Repos{Findings: fr},
	})

	_, err := uc.GetFinding(context.Background(), "00000000-0000-0000-0000-000000000021")
	assert.ErrorContains(t, err, "get finding")
}

// ----- GetGateStatus Tests -----

func TestGetGateStatus_Success(t *testing.T) {
	pr := &mockProjectRepo{}
	fr := &mockFindingRepo{}
	wr := &mockWaiverRepo{}

	pr.getBySlugFn = func(ctx context.Context, slug string) (sqlc.Project, error) {
		return makeProject(true), nil
	}
	fr.listBlockingFindingsFn = func(ctx context.Context, projectID pgtype.UUID, minSeverityRank int16) ([]sqlc.Finding, error) {
		return []sqlc.Finding{makeFindingRow(1), makeFindingRow(2), makeFindingRow(3)}, nil
	}

	uc := New(Deps{
		Repos: &repo.Repos{Projects: pr, Findings: fr, Waivers: wr},
	})

	status, err := uc.GetGateStatus(context.Background(), "my-app", 2)
	require.NoError(t, err)
	require.NotNil(t, status)
	assert.True(t, status.ThresholdBreached)
	assert.Equal(t, int64(3), status.BlockingCount)
	assert.Equal(t, 0, status.WaivedCount)
	assert.Len(t, status.BlockedBy, 3)
}

func TestGetGateStatus_ProjectNotFound(t *testing.T) {
	pr := &mockProjectRepo{}
	pr.getBySlugFn = func(ctx context.Context, slug string) (sqlc.Project, error) {
		return sqlc.Project{}, fmt.Errorf("not found")
	}

	uc := New(Deps{
		Repos: &repo.Repos{Projects: pr},
	})

	_, err := uc.GetGateStatus(context.Background(), "nonexistent", 2)
	assert.ErrorContains(t, err, "lookup project")
}

// ----- ListFindings Tests -----

func TestListFindings_Success(t *testing.T) {
	pr := &mockProjectRepo{}
	fr := &mockFindingRepo{}

	pr.getBySlugFn = func(ctx context.Context, slug string) (sqlc.Project, error) {
		return makeProject(true), nil
	}
	fr.listByProjectFn = func(ctx context.Context, projectID pgtype.UUID, severities, states []string, limit, offset int32) ([]sqlc.Finding, error) {
		return []sqlc.Finding{makeFindingRow(1), makeFindingRow(2)}, nil
	}

	uc := New(Deps{
		Repos: &repo.Repos{Projects: pr, Findings: fr},
	})

	findings, err := uc.ListFindings(context.Background(), "my-app", nil, nil, 20, 0)
	require.NoError(t, err)
	assert.Len(t, findings, 2)
}

func TestListFindings_ProjectNotFound(t *testing.T) {
	pr := &mockProjectRepo{}
	pr.getBySlugFn = func(ctx context.Context, slug string) (sqlc.Project, error) {
		return sqlc.Project{}, fmt.Errorf("not found")
	}

	uc := New(Deps{
		Repos: &repo.Repos{Projects: pr},
	})

	_, err := uc.ListFindings(context.Background(), "nonexistent", nil, nil, 20, 0)
	assert.ErrorContains(t, err, "lookup project")
}

// ----- ListProjects Tests -----

func TestListProjects_Success(t *testing.T) {
	pr := &mockProjectRepo{}
	pr.listFn = func(ctx context.Context) ([]sqlc.Project, error) {
		return []sqlc.Project{makeProject(true)}, nil
	}

	uc := New(Deps{
		Repos: &repo.Repos{Projects: pr},
	})

	projects, err := uc.ListProjects(context.Background())
	require.NoError(t, err)
	assert.Len(t, projects, 1)
	assert.Equal(t, "my-app", projects[0].Slug)
}

// ----- GetProject Tests -----

func TestGetProject_Success(t *testing.T) {
	pr := &mockProjectRepo{}
	pr.getBySlugFn = func(ctx context.Context, slug string) (sqlc.Project, error) {
		return makeProject(true), nil
	}

	uc := New(Deps{
		Repos: &repo.Repos{Projects: pr},
	})

	proj, err := uc.GetProject(context.Background(), "my-app")
	require.NoError(t, err)
	require.NotNil(t, proj)
	assert.Equal(t, "my-app", proj.Slug)
}

func TestGetProject_NotFound(t *testing.T) {
	pr := &mockProjectRepo{}
	pr.getBySlugFn = func(ctx context.Context, slug string) (sqlc.Project, error) {
		return sqlc.Project{}, fmt.Errorf("not found")
	}

	uc := New(Deps{
		Repos: &repo.Repos{Projects: pr},
	})

	_, err := uc.GetProject(context.Background(), "nonexistent")
	assert.ErrorContains(t, err, "get project")
}

// ----- ListReports Tests -----

func TestListReports_Success(t *testing.T) {
	pr := &mockProjectRepo{}
	rr := &mockReportRepo{}

	pr.getBySlugFn = func(ctx context.Context, slug string) (sqlc.Project, error) {
		return makeProject(true), nil
	}
	rr.listByProjectFn = func(ctx context.Context, projectID pgtype.UUID, limit, offset int32) ([]sqlc.Report, error) {
		return []sqlc.Report{makeReport()}, nil
	}

	uc := New(Deps{
		Repos: &repo.Repos{Projects: pr, Reports: rr},
	})

	reports, err := uc.ListReports(context.Background(), "my-app", 20, 0)
	require.NoError(t, err)
	assert.Len(t, reports, 1)
	assert.Equal(t, "trivy", reports[0].ToolName)
}

func TestListReports_ProjectNotFound(t *testing.T) {
	pr := &mockProjectRepo{}
	pr.getBySlugFn = func(ctx context.Context, slug string) (sqlc.Project, error) {
		return sqlc.Project{}, fmt.Errorf("not found")
	}

	uc := New(Deps{
		Repos: &repo.Repos{Projects: pr},
	})

	_, err := uc.ListReports(context.Background(), "nonexistent", 20, 0)
	assert.ErrorContains(t, err, "lookup project")
}

// ----- GetReport Tests -----

func TestGetReport_Success(t *testing.T) {
	rr := &mockReportRepo{}
	rr.getByIDFn = func(ctx context.Context, id pgtype.UUID) (sqlc.Report, error) {
		return makeReport(), nil
	}

	uc := New(Deps{
		Repos: &repo.Repos{Reports: rr},
	})

	report, err := uc.GetReport(context.Background(), pgtype.UUID{Bytes: [16]byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}, Valid: true})
	require.NoError(t, err)
	require.NotNil(t, report)
	assert.Equal(t, "trivy", report.ToolName)
}

func TestGetReport_NotFound(t *testing.T) {
	rr := &mockReportRepo{}
	rr.getByIDFn = func(ctx context.Context, id pgtype.UUID) (sqlc.Report, error) {
		return sqlc.Report{}, fmt.Errorf("not found")
	}

	uc := New(Deps{
		Repos: &repo.Repos{Reports: rr},
	})

	_, err := uc.GetReport(context.Background(), pgtype.UUID{Valid: true})
	assert.ErrorContains(t, err, "get report")
}

// ----- CreateAPIKey Tests -----

func TestCreateAPIKey_Success(t *testing.T) {
	pr := &mockProjectRepo{}
	akr := &mockAPIKeyRepo{}

	pr.getBySlugFn = func(ctx context.Context, slug string) (sqlc.Project, error) {
		return makeProject(true), nil
	}
	akr.createFn = func(ctx context.Context, arg sqlc.CreateAPIKeyParams) (sqlc.ApiKey, error) {
		var id pgtype.UUID
		id.Scan("00000000-0000-0000-0000-000000000050")
		var now pgtype.Timestamptz
		now.Scan(time.Now())
		return sqlc.ApiKey{
			ID:        id,
			Name:      arg.Name,
			KeyPrefix: arg.KeyPrefix,
			LastFour:  pgtype.Text{String: arg.LastFour.String, Valid: true},
			CreatedAt: now,
		}, nil
	}

	uc := New(Deps{
		Repos: &repo.Repos{Projects: pr, APIKeys: akr},
	})

	resp, err := uc.CreateAPIKey(context.Background(), "my-app", "ci-key")
	require.NoError(t, err)
	require.NotNil(t, resp)
	assert.Equal(t, "ci-key", resp.Name)
	assert.NotEmpty(t, resp.RawKey)
	assert.True(t, len(resp.KeyPrefix) > 0)
}

func TestCreateAPIKey_ProjectNotFound(t *testing.T) {
	pr := &mockProjectRepo{}
	pr.getBySlugFn = func(ctx context.Context, slug string) (sqlc.Project, error) {
		return sqlc.Project{}, fmt.Errorf("not found")
	}

	uc := New(Deps{
		Repos: &repo.Repos{Projects: pr},
	})

	_, err := uc.CreateAPIKey(context.Background(), "nonexistent", "ci-key")
	assert.ErrorContains(t, err, "project not found")
}

// ----- ListAPIKeys Tests -----

func TestListAPIKeys_Success(t *testing.T) {
	pr := &mockProjectRepo{}
	akr := &mockAPIKeyRepo{}

	pr.getBySlugFn = func(ctx context.Context, slug string) (sqlc.Project, error) {
		return makeProject(true), nil
	}
	akr.listByProjectFn = func(ctx context.Context, projectID pgtype.UUID) ([]sqlc.ListAPIKeysByProjectRow, error) {
		var now pgtype.Timestamptz
		now.Scan(time.Now())
		return []sqlc.ListAPIKeysByProjectRow{
			{ID: pgtype.UUID{Bytes: [16]byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 5}, Valid: true}, Name: "ci-key", KeyPrefix: "vuln_abc", CreatedAt: now},
		}, nil
	}

	uc := New(Deps{
		Repos: &repo.Repos{Projects: pr, APIKeys: akr},
	})

	keys, err := uc.ListAPIKeys(context.Background(), "my-app")
	require.NoError(t, err)
	assert.Len(t, keys, 1)
	assert.Equal(t, "ci-key", keys[0].Name)
}

func TestListAPIKeys_ProjectNotFound(t *testing.T) {
	pr := &mockProjectRepo{}
	pr.getBySlugFn = func(ctx context.Context, slug string) (sqlc.Project, error) {
		return sqlc.Project{}, fmt.Errorf("not found")
	}

	uc := New(Deps{
		Repos: &repo.Repos{Projects: pr},
	})

	_, err := uc.ListAPIKeys(context.Background(), "nonexistent")
	assert.ErrorContains(t, err, "project not found")
}

// ----- RevokeAPIKey Tests -----

func TestRevokeAPIKey_Success(t *testing.T) {
	pr := &mockProjectRepo{}
	akr := &mockAPIKeyRepo{}

	pr.getBySlugFn = func(ctx context.Context, slug string) (sqlc.Project, error) {
		return makeProject(true), nil
	}
	akr.revokeFn = func(ctx context.Context, id, projectID pgtype.UUID) (sqlc.ApiKey, error) {
		return sqlc.ApiKey{}, nil
	}

	uc := New(Deps{
		Repos: &repo.Repos{Projects: pr, APIKeys: akr},
	})

	err := uc.RevokeAPIKey(context.Background(), "my-app", "00000000-0000-0000-0000-000000000050")
	require.NoError(t, err)
}

func TestRevokeAPIKey_ProjectNotFound(t *testing.T) {
	pr := &mockProjectRepo{}
	pr.getBySlugFn = func(ctx context.Context, slug string) (sqlc.Project, error) {
		return sqlc.Project{}, fmt.Errorf("not found")
	}

	uc := New(Deps{
		Repos: &repo.Repos{Projects: pr},
	})

	err := uc.RevokeAPIKey(context.Background(), "nonexistent", "some-id")
	assert.ErrorContains(t, err, "project not found")
}

func TestRevokeAPIKey_InvalidID(t *testing.T) {
	pr := &mockProjectRepo{}
	akr := &mockAPIKeyRepo{}

	pr.getBySlugFn = func(ctx context.Context, slug string) (sqlc.Project, error) {
		return makeProject(true), nil
	}
	akr.revokeFn = nil

	uc := New(Deps{
		Repos: &repo.Repos{Projects: pr, APIKeys: akr},
	})

	err := uc.RevokeAPIKey(context.Background(), "my-app", "not-a-uuid")
	assert.ErrorContains(t, err, "invalid key id")
}

// ----- TriageFinding Tests -----

func TestTriageFinding_Success(t *testing.T) {
	fID := "00000000-0000-0000-0000-000000000021"

	fr := &mockFindingRepo{}
	fr.getByIDFn = func(ctx context.Context, id pgtype.UUID) (sqlc.Finding, error) {
		f := makeFindingRow(1)
		f.AnalysisState = "unanalyzed"
		f.GateEffect = "block"
		return f, nil
	}
	fr.updateAnalysisFn = func(ctx context.Context, arg repo.UpdateAnalysisParams) (sqlc.Finding, error) {
		f := makeFindingRow(1)
		f.AnalysisState = "false_positive"
		f.GateEffect = "ignore"
		return f, nil
	}
	fr.createEventFn = func(ctx context.Context, arg repo.CreateEventParams) (sqlc.FindingEvent, error) {
		return sqlc.FindingEvent{}, nil
	}

	uc := New(Deps{
		Repos: &repo.Repos{Findings: fr},
	})

	result, err := uc.TriageFinding(context.Background(), TriageInput{
		FindingID:     fID,
		AnalysisState: "false_positive",
		Reason:        "test code",
		UserID:        "00000000-0000-0000-0000-000000000040",
	})
	require.NoError(t, err)
	require.NotNil(t, result)
	assert.Equal(t, "false_positive", result.AnalysisState)
	assert.Equal(t, "ignore", result.GateEffect)
}

func TestTriageFinding_NotFound(t *testing.T) {
	fr := &mockFindingRepo{}
	fr.getByIDFn = func(ctx context.Context, id pgtype.UUID) (sqlc.Finding, error) {
		return sqlc.Finding{}, fmt.Errorf("not found")
	}

	uc := New(Deps{
		Repos: &repo.Repos{Findings: fr},
	})

	_, err := uc.TriageFinding(context.Background(), TriageInput{
		FindingID:     "00000000-0000-0000-0000-000000000021",
		AnalysisState: "false_positive",
		Reason:        "test",
		UserID:        "00000000-0000-0000-0000-000000000040",
	})
	assert.ErrorIs(t, err, ErrFindingNotFound)
}

func TestTriageFinding_InvalidFindingID(t *testing.T) {
	uc := New(Deps{})
	_, err := uc.TriageFinding(context.Background(), TriageInput{
		FindingID: "not-a-uuid",
	})
	assert.ErrorContains(t, err, "invalid finding id")
}

func TestTriageFinding_MissingReason(t *testing.T) {
	fr := &mockFindingRepo{}
	fr.getByIDFn = func(ctx context.Context, id pgtype.UUID) (sqlc.Finding, error) {
		return makeFindingRow(1), nil
	}

	uc := New(Deps{
		Repos: &repo.Repos{Findings: fr},
	})

	_, err := uc.TriageFinding(context.Background(), TriageInput{
		FindingID:     "00000000-0000-0000-0000-000000000021",
		AnalysisState: "false_positive",
		UserID:        "00000000-0000-0000-0000-000000000040",
	})
	assert.ErrorIs(t, err, ErrReasonRequired)
}

func TestTriageFinding_MissingExpiry(t *testing.T) {
	fr := &mockFindingRepo{}
	fr.getByIDFn = func(ctx context.Context, id pgtype.UUID) (sqlc.Finding, error) {
		return makeFindingRow(1), nil
	}

	uc := New(Deps{
		Repos: &repo.Repos{Findings: fr},
	})

	_, err := uc.TriageFinding(context.Background(), TriageInput{
		FindingID:     "00000000-0000-0000-0000-000000000021",
		AnalysisState: "accepted_risk",
		Reason:        "it's fine",
		UserID:        "00000000-0000-0000-0000-000000000040",
	})
	assert.ErrorIs(t, err, ErrExpiryRequired)
}

// ----- BulkTriage Tests -----

func TestBulkTriage_Success(t *testing.T) {
	fr := &mockFindingRepo{}
	fr.listByIDsFn = func(ctx context.Context, ids []pgtype.UUID) ([]sqlc.Finding, error) {
		return []sqlc.Finding{makeFindingRow(1)}, nil
	}
	fr.bulkUpdateAnalysisFn = func(ctx context.Context, arg repo.BulkUpdateAnalysisParams) ([]sqlc.Finding, error) {
		f := makeFindingRow(1)
		f.AnalysisState = "false_positive"
		f.GateEffect = "ignore"
		return []sqlc.Finding{f}, nil
	}
	fr.createEventFn = func(ctx context.Context, arg repo.CreateEventParams) (sqlc.FindingEvent, error) {
		return sqlc.FindingEvent{}, nil
	}

	uc := New(Deps{
		Repos: &repo.Repos{Findings: fr},
	})

	results, err := uc.BulkTriage(context.Background(), BulkTriageInput{
		FindingIDs:    []string{"00000000-0000-0000-0000-000000000021"},
		AnalysisState: "false_positive",
		Reason:        "test code",
		UserID:        "00000000-0000-0000-0000-000000000040",
	})
	require.NoError(t, err)
	assert.Len(t, results, 1)
	assert.Equal(t, "false_positive", results[0].AnalysisState)
}

func TestBulkTriage_FindingsNotFound(t *testing.T) {
	fr := &mockFindingRepo{}
	fr.listByIDsFn = func(ctx context.Context, ids []pgtype.UUID) ([]sqlc.Finding, error) {
		return []sqlc.Finding{}, nil
	}

	uc := New(Deps{
		Repos: &repo.Repos{Findings: fr},
	})

	_, err := uc.BulkTriage(context.Background(), BulkTriageInput{
		FindingIDs:    []string{"00000000-0000-0000-0000-000000000021"},
		AnalysisState: "false_positive",
		Reason:        "test",
		UserID:        "00000000-0000-0000-0000-000000000040",
	})
	assert.ErrorIs(t, err, ErrFindingNotFound)
}

func TestBulkTriage_InvalidUserID(t *testing.T) {
	uc := New(Deps{})
	_, err := uc.BulkTriage(context.Background(), BulkTriageInput{
		FindingIDs:    []string{"abc-123"},
		AnalysisState: "false_positive",
		UserID:        "not-a-uuid",
	})
	assert.ErrorContains(t, err, "invalid user id")
}

// ----- GetFindingEvents Tests -----

func TestGetFindingEvents_Success(t *testing.T) {
	fr := &mockFindingRepo{}
	var fid pgtype.UUID
	fid.Scan("00000000-0000-0000-0000-000000000021")
	fr.listEventsFn = func(ctx context.Context, findingID pgtype.UUID, eventTypes []string, limit, offset int32) ([]sqlc.FindingEvent, error) {
		return []sqlc.FindingEvent{
			{EventType: "analysis_changed"},
		}, nil
	}

	uc := New(Deps{
		Repos: &repo.Repos{Findings: fr},
	})

	events, err := uc.GetFindingEvents(context.Background(), "00000000-0000-0000-0000-000000000021", nil, 10, 0)
	require.NoError(t, err)
	assert.Len(t, events, 1)
	assert.Equal(t, "analysis_changed", events[0].EventType)
}

func TestGetFindingEvents_InvalidID(t *testing.T) {
	uc := New(Deps{})
	_, err := uc.GetFindingEvents(context.Background(), "not-a-uuid", nil, 10, 0)
	assert.ErrorContains(t, err, "invalid finding id")
}
