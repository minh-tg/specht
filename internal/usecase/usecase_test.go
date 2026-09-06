package usecase

import (
	"context"
	"encoding/json"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/xMinhx/specht/internal/auth"
	"github.com/xMinhx/specht/internal/domain"
	"github.com/xMinhx/specht/internal/gate"
	"github.com/xMinhx/specht/internal/port"
	"github.com/xMinhx/specht/internal/scanner"
)

type mockProjectRepo struct {
	port.ProjectStore
	createFn    func(context.Context, port.CreateProjectInput) (port.Project, error)
	listFn      func(context.Context) ([]port.Project, error)
	getBySlugFn func(context.Context, string) (port.Project, error)
}

func (m *mockProjectRepo) Create(ctx context.Context, arg port.CreateProjectInput) (port.Project, error) {
	if m.createFn == nil {
		return port.Project{}, fmt.Errorf("unexpected call to Create")
	}
	return m.createFn(ctx, arg)
}

func (m *mockProjectRepo) List(ctx context.Context) ([]port.Project, error) {
	if m.listFn == nil {
		return nil, fmt.Errorf("unexpected call to List")
	}
	return m.listFn(ctx)
}

func (m *mockProjectRepo) GetBySlug(ctx context.Context, slug string) (port.Project, error) {
	if m.getBySlugFn == nil {
		return port.Project{}, fmt.Errorf("unexpected call to GetBySlug")
	}
	return m.getBySlugFn(ctx, slug)
}

type mockReportRepo struct {
	port.ReportStore
	createFn        func(context.Context, port.CreateReportInput) (port.Report, error)
	getByIDFn       func(context.Context, string) (port.Report, error)
	listByProjectFn func(context.Context, string, int32, int32) ([]port.Report, error)
	updateStatusFn  func(context.Context, string, string, string, int32, *string) (port.Report, error)
	latestReportFn  func(context.Context, string, string) (port.CompletedReport, error)
}

func (m *mockReportRepo) Create(ctx context.Context, arg port.CreateReportInput) (port.Report, error) {
	if m.createFn == nil {
		return port.Report{}, fmt.Errorf("unexpected call to Create")
	}
	return m.createFn(ctx, arg)
}

func (m *mockReportRepo) UpdateStatus(ctx context.Context, id, projectID, status string, totalFindings int32, errorMsg *string) (port.Report, error) {
	if m.updateStatusFn == nil {
		return port.Report{}, fmt.Errorf("unexpected call to UpdateStatus")
	}
	return m.updateStatusFn(ctx, id, projectID, status, totalFindings, errorMsg)
}

func (m *mockReportRepo) GetByID(ctx context.Context, id string) (port.Report, error) {
	if m.getByIDFn == nil {
		return port.Report{}, fmt.Errorf("unexpected call to GetByID")
	}
	return m.getByIDFn(ctx, id)
}

func (m *mockReportRepo) ListByProject(ctx context.Context, projectID string, limit, offset int32) ([]port.Report, error) {
	if m.listByProjectFn == nil {
		return nil, fmt.Errorf("unexpected call to ListByProject")
	}
	return m.listByProjectFn(ctx, projectID, limit, offset)
}

func (m *mockReportRepo) LatestCompletedByScanner(ctx context.Context, projectID, scanner string) (port.CompletedReport, error) {
	if m.latestReportFn == nil {
		return port.CompletedReport{}, port.ErrNotFound
	}
	return m.latestReportFn(ctx, projectID, scanner)
}

type mockFindingRepo struct {
	port.FindingStore
	hasOccurrenceFn        func(context.Context, string, string) (bool, error)
	markFixedFn            func(context.Context, string) (port.Finding, error)
	createOccurrenceFn     func(context.Context, port.OccurrenceInput) (port.Occurrence, error)
	upsertDimensionFn      func(context.Context, port.DimensionInput) error
	listByProjectFn        func(context.Context, string, []string, []string, []string, []string, []string, int32, int32) ([]port.Finding, error)
	getDisplayContextFn    func(context.Context, string) (port.FindingDisplayContext, error)
	listDimensionsFn       func(context.Context, string) ([]port.FindingDimension, error)
	upsertFn               func(context.Context, string, string, string, string, string, int16, float64, time.Time, time.Time) (port.Finding, error)
	getByFingerprintFn     func(context.Context, string, string, string) (port.Finding, error)
	getByIDFn              func(context.Context, string) (port.Finding, error)
	listByIDsFn            func(context.Context, []string) ([]port.Finding, error)
	hasDimensionFn         func(context.Context, string, string) (bool, error)
	updateAnalysisFn       func(context.Context, port.UpdateAnalysisInput) (port.Finding, error)
	bulkUpdateAnalysisFn   func(context.Context, port.UpdateAnalysisInput, []string) ([]port.Finding, error)
	createEventFn          func(context.Context, port.FindingEventInput) (port.FindingEvent, error)
	listEventsFn           func(context.Context, string, []string, int32, int32) ([]port.FindingEvent, error)
	listBlockingFindingsFn func(context.Context, string, int16) ([]port.Finding, error)
	listGateCandidatesFn   func(context.Context, string, int16) ([]port.GateCandidate, error)
	getFindingContextFn    func(context.Context, string) (port.FindingContext, error)
}

func (m *mockFindingRepo) Upsert(ctx context.Context, projectID, findingKind, fingerprint, title, severity string, severityRank int16, score float64, firstSeen, lastSeen time.Time) (port.Finding, error) {
	if m.upsertFn == nil {
		return port.Finding{}, fmt.Errorf("unexpected call to Upsert")
	}
	return m.upsertFn(ctx, projectID, findingKind, fingerprint, title, severity, severityRank, score, firstSeen, lastSeen)
}

func (m *mockFindingRepo) CreateOccurrence(ctx context.Context, arg port.OccurrenceInput) (port.Occurrence, error) {
	if m.createOccurrenceFn == nil {
		return port.Occurrence{}, fmt.Errorf("unexpected call to CreateOccurrence")
	}
	return m.createOccurrenceFn(ctx, arg)
}

func (m *mockFindingRepo) UpsertDimension(ctx context.Context, arg port.DimensionInput) error {
	if m.upsertDimensionFn == nil {
		return nil
	}
	return m.upsertDimensionFn(ctx, arg)
}

func (m *mockFindingRepo) ListByProject(ctx context.Context, projectID string, severities, states, kinds, environments, targets []string, limit, offset int32) ([]port.Finding, error) {
	if m.listByProjectFn == nil {
		return []port.Finding{}, nil
	}
	return m.listByProjectFn(ctx, projectID, severities, states, kinds, environments, targets, limit, offset)
}

func (m *mockFindingRepo) GetByID(ctx context.Context, id string) (port.Finding, error) {
	if m.getByIDFn == nil {
		return port.Finding{}, fmt.Errorf("unexpected call to GetByID")
	}
	return m.getByIDFn(ctx, id)
}

func (m *mockFindingRepo) ListByIDs(ctx context.Context, ids []string) ([]port.Finding, error) {
	if m.listByIDsFn == nil {
		return nil, fmt.Errorf("unexpected call to ListByIDs")
	}
	return m.listByIDsFn(ctx, ids)
}

func (m *mockFindingRepo) BulkUpdateAnalysis(ctx context.Context, arg port.UpdateAnalysisInput, ids []string) ([]port.Finding, error) {
	if m.bulkUpdateAnalysisFn == nil {
		return nil, fmt.Errorf("unexpected call to BulkUpdateAnalysis")
	}
	return m.bulkUpdateAnalysisFn(ctx, arg, ids)
}

func (m *mockFindingRepo) ListEvents(ctx context.Context, findingID string, eventTypes []string, limit, offset int32) ([]port.FindingEvent, error) {
	if m.listEventsFn == nil {
		return nil, fmt.Errorf("unexpected call to ListEvents")
	}
	return m.listEventsFn(ctx, findingID, eventTypes, limit, offset)
}

func (m *mockFindingRepo) ListBlockingFindings(ctx context.Context, projectID string, minSeverityRank int16) ([]port.Finding, error) {
	if m.listBlockingFindingsFn == nil {
		return []port.Finding{}, nil
	}
	return m.listBlockingFindingsFn(ctx, projectID, minSeverityRank)
}

func (m *mockFindingRepo) ListGateCandidates(ctx context.Context, projectID string, minSeverityRank int16) ([]port.GateCandidate, error) {
	if m.listGateCandidatesFn == nil {
		return []port.GateCandidate{}, nil
	}
	return m.listGateCandidatesFn(ctx, projectID, minSeverityRank)
}

func (m *mockFindingRepo) GetFindingContext(ctx context.Context, findingID string) (port.FindingContext, error) {
	if m.getFindingContextFn == nil {
		return port.FindingContext{}, fmt.Errorf("unexpected call to GetFindingContext")
	}
	return m.getFindingContextFn(ctx, findingID)
}

func (m *mockFindingRepo) GetFindingDisplayContext(ctx context.Context, findingID string) (port.FindingDisplayContext, error) {
	if m.getDisplayContextFn == nil {
		return port.FindingDisplayContext{}, nil
	}
	return m.getDisplayContextFn(ctx, findingID)
}

func (m *mockFindingRepo) ListDimensions(ctx context.Context, findingID string) ([]port.FindingDimension, error) {
	if m.listDimensionsFn == nil {
		return nil, nil
	}
	return m.listDimensionsFn(ctx, findingID)
}

func (m *mockFindingRepo) HasOccurrence(ctx context.Context, findingID, reportID string) (bool, error) {
	if m.hasOccurrenceFn == nil {
		return false, fmt.Errorf("unexpected call to HasOccurrence")
	}
	return m.hasOccurrenceFn(ctx, findingID, reportID)
}

func (m *mockFindingRepo) MarkFixed(ctx context.Context, findingID string) (port.Finding, error) {
	if m.markFixedFn == nil {
		return port.Finding{}, fmt.Errorf("unexpected call to MarkFixed")
	}
	return m.markFixedFn(ctx, findingID)
}

func (m *mockFindingRepo) GetByFingerprint(ctx context.Context, projectID, findingKind, fingerprint string) (port.Finding, error) {
	if m.getByFingerprintFn == nil {
		return port.Finding{}, fmt.Errorf("unexpected call to GetByFingerprint")
	}
	return m.getByFingerprintFn(ctx, projectID, findingKind, fingerprint)
}

func (m *mockFindingRepo) HasDimension(ctx context.Context, findingID, key string) (bool, error) {
	if m.hasDimensionFn == nil {
		return false, nil
	}
	return m.hasDimensionFn(ctx, findingID, key)
}

func (m *mockFindingRepo) UpdateAnalysis(ctx context.Context, arg port.UpdateAnalysisInput) (port.Finding, error) {
	if m.updateAnalysisFn == nil {
		return port.Finding{}, fmt.Errorf("unexpected call to UpdateAnalysis")
	}
	return m.updateAnalysisFn(ctx, arg)
}

func (m *mockFindingRepo) CreateEvent(ctx context.Context, arg port.FindingEventInput) (port.FindingEvent, error) {
	if m.createEventFn == nil {
		return port.FindingEvent{}, nil
	}
	return m.createEventFn(ctx, arg)
}

type mockUserRepo struct {
	port.UserStore
	createFn     func(context.Context, string, *string, *string) (port.User, error)
	getByEmailFn func(context.Context, string) (port.User, error)
	getByIDFn    func(context.Context, string) (port.User, error)
}

func (m *mockUserRepo) Create(ctx context.Context, email string, displayName, passwordHash *string) (port.User, error) {
	if m.createFn == nil {
		return port.User{}, fmt.Errorf("unexpected call to Create")
	}
	return m.createFn(ctx, email, displayName, passwordHash)
}

func (m *mockUserRepo) GetByEmail(ctx context.Context, email string) (port.User, error) {
	if m.getByEmailFn == nil {
		return port.User{}, fmt.Errorf("unexpected call to GetByEmail")
	}
	return m.getByEmailFn(ctx, email)
}

func (m *mockUserRepo) GetByID(ctx context.Context, id string) (port.User, error) {
	if m.getByIDFn == nil {
		return port.User{}, fmt.Errorf("unexpected call to GetByID")
	}
	return m.getByIDFn(ctx, id)
}

type mockRefreshTokenRepo struct {
	port.RefreshTokenStore
	createFn    func(context.Context, string, string, time.Time) (port.RefreshToken, error)
	getByHashFn func(context.Context, string) (port.RefreshToken, error)
	revokeFn    func(context.Context, string) (port.RefreshToken, error)
}

func (m *mockRefreshTokenRepo) Create(ctx context.Context, userID, tokenHash string, expiresAt time.Time) (port.RefreshToken, error) {
	if m.createFn == nil {
		return port.RefreshToken{}, fmt.Errorf("unexpected call to Create")
	}
	return m.createFn(ctx, userID, tokenHash, expiresAt)
}

func (m *mockRefreshTokenRepo) GetByHash(ctx context.Context, tokenHash string) (port.RefreshToken, error) {
	if m.getByHashFn == nil {
		return port.RefreshToken{}, fmt.Errorf("unexpected call to GetByHash")
	}
	return m.getByHashFn(ctx, tokenHash)
}

func (m *mockRefreshTokenRepo) Revoke(ctx context.Context, id string) (port.RefreshToken, error) {
	if m.revokeFn == nil {
		return port.RefreshToken{}, fmt.Errorf("unexpected call to Revoke")
	}
	return m.revokeFn(ctx, id)
}

type mockAPIKeyRepo struct {
	port.APIKeyStore
	createFn        func(context.Context, port.CreateAPIKeyInput) (port.APIKey, error)
	listByProjectFn func(context.Context, string) ([]port.APIKey, error)
	revokeFn        func(context.Context, string, string) (port.APIKey, error)
	getByHashFn     func(context.Context, string) (port.APIKey, error)
}

func (m *mockAPIKeyRepo) Create(ctx context.Context, arg port.CreateAPIKeyInput) (port.APIKey, error) {
	if m.createFn == nil {
		return port.APIKey{}, fmt.Errorf("unexpected call to Create")
	}
	return m.createFn(ctx, arg)
}

func (m *mockAPIKeyRepo) ListByProject(ctx context.Context, projectID string) ([]port.APIKey, error) {
	if m.listByProjectFn == nil {
		return nil, fmt.Errorf("unexpected call to ListByProject")
	}
	return m.listByProjectFn(ctx, projectID)
}

func (m *mockAPIKeyRepo) Revoke(ctx context.Context, id, projectID string) (port.APIKey, error) {
	if m.revokeFn == nil {
		return port.APIKey{}, fmt.Errorf("unexpected call to Revoke")
	}
	return m.revokeFn(ctx, id, projectID)
}

func (m *mockAPIKeyRepo) GetByHash(ctx context.Context, keyHash string) (port.APIKey, error) {
	if m.getByHashFn == nil {
		return port.APIKey{}, fmt.Errorf("unexpected call to GetByHash")
	}
	return m.getByHashFn(ctx, keyHash)
}

type mockWaiverRepo struct {
	port.WaiverStore
	listActiveFn         func(context.Context, string) ([]port.Waiver, error)
	listConditionsFn     func(context.Context, string) ([]port.WaiverCondition, error)
	listContextsFn       func(context.Context, string) ([]port.WaiverContext, error)
	listFindingTargetsFn func(context.Context, string) ([]port.WaiverFindingTarget, error)
}

func (m *mockWaiverRepo) ListActive(ctx context.Context, projectID string) ([]port.Waiver, error) {
	if m.listActiveFn == nil {
		return []port.Waiver{}, nil
	}
	return m.listActiveFn(ctx, projectID)
}

func (m *mockWaiverRepo) ListConditions(ctx context.Context, waiverID string) ([]port.WaiverCondition, error) {
	if m.listConditionsFn == nil {
		return []port.WaiverCondition{}, nil
	}
	return m.listConditionsFn(ctx, waiverID)
}

func (m *mockWaiverRepo) ListContexts(ctx context.Context, waiverID string) ([]port.WaiverContext, error) {
	if m.listContextsFn == nil {
		return []port.WaiverContext{}, nil
	}
	return m.listContextsFn(ctx, waiverID)
}

func (m *mockWaiverRepo) ListFindingTargets(ctx context.Context, waiverID string) ([]port.WaiverFindingTarget, error) {
	if m.listFindingTargetsFn == nil {
		return []port.WaiverFindingTarget{}, nil
	}
	return m.listFindingTargetsFn(ctx, waiverID)
}

type mockScanner struct {
	name    string
	parseFn func(context.Context, []byte) (*domain.NormalizedReport, error)
}

func (m *mockScanner) Descriptor() scanner.Descriptor {
	return scanner.Descriptor{
		Name: m.name, Version: "test", ContractVersion: 1, FingerprintVersion: 1,
		FindingKinds:     []scanner.FindingKind{"sca", "test"},
		ScanTypes:        []domain.ScanType{domain.ScanTypeImage, domain.ScanTypeFilesystem},
		ProvidesPackages: true,
	}
}
func (m *mockScanner) DetectFormat(data []byte) bool { return true }
func (m *mockScanner) Parse(ctx context.Context, data []byte) (*domain.NormalizedReport, error) {
	if m.parseFn == nil {
		return nil, fmt.Errorf("unexpected call to Parse")
	}
	return m.parseFn(ctx, data)
}

type mockReachabilityRepo struct {
	port.ReachabilityStore
	upsertFn           func(context.Context, string, string, string, string) (port.ReachabilityAssessment, error)
	listByFindingFn    func(context.Context, string) ([]port.ReachabilityAssessment, error)
	latestByFindingFn  func(context.Context, string) (port.ReachabilityAssessment, error)
	latestByFindingsFn func(context.Context, []string) ([]port.ReachabilityAssessment, error)
}

func (m *mockReachabilityRepo) Upsert(ctx context.Context, findingID, state, evidence, assessedBy string) (port.ReachabilityAssessment, error) {
	if m.upsertFn == nil {
		return port.ReachabilityAssessment{}, fmt.Errorf("unexpected call to Upsert")
	}
	return m.upsertFn(ctx, findingID, state, evidence, assessedBy)
}

func (m *mockReachabilityRepo) ListByFinding(ctx context.Context, findingID string) ([]port.ReachabilityAssessment, error) {
	if m.listByFindingFn == nil {
		return nil, fmt.Errorf("unexpected call to ListByFinding")
	}
	return m.listByFindingFn(ctx, findingID)
}

func (m *mockReachabilityRepo) LatestByFinding(ctx context.Context, findingID string) (port.ReachabilityAssessment, error) {
	if m.latestByFindingFn == nil {
		return port.ReachabilityAssessment{}, fmt.Errorf("unexpected call to LatestByFinding")
	}
	return m.latestByFindingFn(ctx, findingID)
}

func (m *mockReachabilityRepo) LatestByFindings(ctx context.Context, findingIDs []string) ([]port.ReachabilityAssessment, error) {
	if m.latestByFindingsFn == nil {
		return nil, fmt.Errorf("unexpected call to LatestByFindings")
	}
	return m.latestByFindingsFn(ctx, findingIDs)
}

type mockEvidenceRepo struct {
	port.EvidenceStore
	getByIDFn       func(context.Context, string) (port.Evidence, error)
	listByFindingFn func(context.Context, string) ([]port.Evidence, error)
}

func (m *mockEvidenceRepo) GetByID(ctx context.Context, id string) (port.Evidence, error) {
	if m.getByIDFn == nil {
		return port.Evidence{}, fmt.Errorf("unexpected call to GetByID")
	}
	return m.getByIDFn(ctx, id)
}

func (m *mockEvidenceRepo) ListByFinding(ctx context.Context, findingID string) ([]port.Evidence, error) {
	if m.listByFindingFn == nil {
		return nil, fmt.Errorf("unexpected call to ListByFinding")
	}
	return m.listByFindingFn(ctx, findingID)
}

type mockSignoffRepo struct {
	port.SignoffStore
	getByFindingFn func(context.Context, string) (port.Signoff, error)
}

func (m *mockSignoffRepo) GetByFinding(ctx context.Context, findingID string) (port.Signoff, error) {
	if m.getByFindingFn == nil {
		return port.Signoff{}, fmt.Errorf("unexpected call to GetByFinding")
	}
	return m.getByFindingFn(ctx, findingID)
}

type mockTargetRepo struct {
	port.TargetStore
	upsertFn  func(context.Context, string, string, string, string, string) (port.Target, error)
	listFn    func(context.Context, string) ([]port.Target, error)
	getByIDFn func(context.Context, string, string) (port.Target, error)
	deleteFn  func(context.Context, string, string) (port.Target, error)
}

func (m *mockTargetRepo) Upsert(ctx context.Context, projectID, name, kind, locator, owner string) (port.Target, error) {
	if m.upsertFn == nil {
		return port.Target{}, fmt.Errorf("unexpected call to Upsert")
	}
	return m.upsertFn(ctx, projectID, name, kind, locator, owner)
}

func (m *mockTargetRepo) List(ctx context.Context, projectID string) ([]port.Target, error) {
	if m.listFn == nil {
		return nil, fmt.Errorf("unexpected call to List")
	}
	return m.listFn(ctx, projectID)
}

func (m *mockTargetRepo) GetByID(ctx context.Context, id, projectID string) (port.Target, error) {
	if m.getByIDFn == nil {
		return port.Target{}, fmt.Errorf("unexpected call to GetByID")
	}
	return m.getByIDFn(ctx, id, projectID)
}

func (m *mockTargetRepo) Delete(ctx context.Context, id, projectID string) (port.Target, error) {
	if m.deleteFn == nil {
		return port.Target{}, fmt.Errorf("unexpected call to Delete")
	}
	return m.deleteFn(ctx, id, projectID)
}

type mockEnvironmentRepo struct {
	port.EnvironmentStore
	upsertFn  func(context.Context, string, string, string, bool, string) (port.Environment, error)
	listFn    func(context.Context, string) ([]port.Environment, error)
	getByIDFn func(context.Context, string, string) (port.Environment, error)
	deleteFn  func(context.Context, string, string) (port.Environment, error)
}

func (m *mockEnvironmentRepo) Upsert(ctx context.Context, projectID, name, tier string, internetFacing bool, dataSensitivity string) (port.Environment, error) {
	if m.upsertFn == nil {
		return port.Environment{}, fmt.Errorf("unexpected call to Upsert")
	}
	return m.upsertFn(ctx, projectID, name, tier, internetFacing, dataSensitivity)
}

func (m *mockEnvironmentRepo) List(ctx context.Context, projectID string) ([]port.Environment, error) {
	if m.listFn == nil {
		return nil, fmt.Errorf("unexpected call to List")
	}
	return m.listFn(ctx, projectID)
}

func (m *mockEnvironmentRepo) GetByID(ctx context.Context, id, projectID string) (port.Environment, error) {
	if m.getByIDFn == nil {
		return port.Environment{}, fmt.Errorf("unexpected call to GetByID")
	}
	return m.getByIDFn(ctx, id, projectID)
}

func (m *mockEnvironmentRepo) Delete(ctx context.Context, id, projectID string) (port.Environment, error) {
	if m.deleteFn == nil {
		return port.Environment{}, fmt.Errorf("unexpected call to Delete")
	}
	return m.deleteFn(ctx, id, projectID)
}

type mockArtifactRepo struct {
	port.ArtifactStore
	upsertFn       func(context.Context, port.ArtifactInput) (port.Artifact, error)
	listFn         func(context.Context, string) ([]port.Artifact, error)
	listByTargetFn func(context.Context, string) ([]port.Artifact, error)
	getByIDFn      func(context.Context, string, string) (port.Artifact, error)
	deleteFn       func(context.Context, string, string) (port.Artifact, error)
}

func (m *mockArtifactRepo) Upsert(ctx context.Context, arg port.ArtifactInput) (port.Artifact, error) {
	if m.upsertFn == nil {
		return port.Artifact{}, fmt.Errorf("unexpected call to Upsert")
	}
	return m.upsertFn(ctx, arg)
}

func (m *mockArtifactRepo) List(ctx context.Context, projectID string) ([]port.Artifact, error) {
	if m.listFn == nil {
		return nil, fmt.Errorf("unexpected call to List")
	}
	return m.listFn(ctx, projectID)
}

func (m *mockArtifactRepo) ListByTarget(ctx context.Context, targetID string) ([]port.Artifact, error) {
	if m.listByTargetFn == nil {
		return nil, fmt.Errorf("unexpected call to ListByTarget")
	}
	return m.listByTargetFn(ctx, targetID)
}

func (m *mockArtifactRepo) GetByID(ctx context.Context, id, projectID string) (port.Artifact, error) {
	if m.getByIDFn == nil {
		return port.Artifact{}, fmt.Errorf("unexpected call to GetByID")
	}
	return m.getByIDFn(ctx, id, projectID)
}

func (m *mockArtifactRepo) Delete(ctx context.Context, id, projectID string) (port.Artifact, error) {
	if m.deleteFn == nil {
		return port.Artifact{}, fmt.Errorf("unexpected call to Delete")
	}
	return m.deleteFn(ctx, id, projectID)
}

type mockInventoryRepo struct {
	port.InventoryStore
	upsertReportPackagesFn func(context.Context, string, []port.PackageRef) error
	distinctInventoryFn    func(context.Context, string, time.Duration) ([]port.InventoryPackage, error)
	deleteReportPackagesFn func(context.Context, string) error
}

func (m *mockInventoryRepo) UpsertReportPackages(ctx context.Context, reportID string, packages []port.PackageRef) error {
	if m.upsertReportPackagesFn == nil {
		return fmt.Errorf("unexpected call to UpsertReportPackages")
	}
	return m.upsertReportPackagesFn(ctx, reportID, packages)
}

func (m *mockInventoryRepo) DistinctInventory(ctx context.Context, projectID string, since time.Duration) ([]port.InventoryPackage, error) {
	if m.distinctInventoryFn == nil {
		return nil, fmt.Errorf("unexpected call to DistinctInventory")
	}
	return m.distinctInventoryFn(ctx, projectID, since)
}

func (m *mockInventoryRepo) DeleteReportPackages(ctx context.Context, reportID string) error {
	if m.deleteReportPackagesFn == nil {
		return fmt.Errorf("unexpected call to DeleteReportPackages")
	}
	return m.deleteReportPackagesFn(ctx, reportID)
}

func makeTestRepos() (*mockProjectRepo, *mockReportRepo, *mockFindingRepo) {
	return &mockProjectRepo{}, &mockReportRepo{}, &mockFindingRepo{}
}

func stubTargetRepo() *mockTargetRepo {
	tr := &mockTargetRepo{}
	tr.upsertFn = func(ctx context.Context, projectID, name, kind, locator, owner string) (port.Target, error) {
		return port.Target{ID: projectID, ProjectID: projectID, Name: name, Kind: kind}, nil
	}
	return tr
}

func stubArtifactRepo() *mockArtifactRepo {
	ar := &mockArtifactRepo{}
	ar.upsertFn = func(ctx context.Context, arg port.ArtifactInput) (port.Artifact, error) {
		return port.Artifact{ID: arg.ProjectID, ProjectID: arg.ProjectID, Name: arg.Name}, nil
	}
	return ar
}

func makeProject(valid bool) port.Project {
	if !valid {
		return port.Project{}
	}
	return port.Project{ID: "00000000-0000-0000-0000-000000000001", Slug: "my-app", Name: "My App"}
}

func makeUser(id string) port.User {
	return port.User{ID: id, Email: "test@example.com", Role: "user", CreatedAt: time.Now()}
}

func makeRefreshToken(revoked bool) port.RefreshToken {
	var revokedAt *time.Time
	if revoked {
		t := time.Now()
		revokedAt = &t
	}
	return port.RefreshToken{
		ID:        "00000000-0000-0000-0000-000000000030",
		UserID:    "00000000-0000-0000-0000-000000000040",
		TokenHash: "somehash", ExpiresAt: time.Now().Add(7 * 24 * time.Hour), RevokedAt: revokedAt,
	}
}

func makeReport() port.Report {
	total := int32(2)
	return port.Report{
		ID:        "00000000-0000-0000-0000-000000000010",
		ProjectID: "00000000-0000-0000-0000-000000000001",
		ToolName:  "trivy", Status: "completed", TotalFindings: &total,
	}
}

func makeFinding(idIdx int) port.Finding {
	return port.Finding{
		ID:          fmt.Sprintf("00000000-0000-0000-0000-00000000002%d", idIdx),
		ProjectID:   "00000000-0000-0000-0000-000000000001",
		FindingKind: "sca", Fingerprint: "fp1",
	}
}

func TestCreateProject_Success(t *testing.T) {
	pr, _, _ := makeTestRepos()

	pr.createFn = func(ctx context.Context, arg port.CreateProjectInput) (port.Project, error) {
		return makeProject(true), nil
	}

	uc := New(Deps{
		Stores: &port.Stores{Projects: pr},
	})

	result, err := uc.CreateProject(context.Background(), "My App", "my-app", "test description")
	require.NoError(t, err)
	require.NotNil(t, result)
	assert.Equal(t, "my-app", result.Slug)
	assert.Equal(t, "My App", result.Name)
}

func TestIngestReport_Success(t *testing.T) {
	pr, rr, fr := makeTestRepos()

	pr.getBySlugFn = func(ctx context.Context, slug string) (port.Project, error) {
		return makeProject(true), nil
	}

	rr.createFn = func(ctx context.Context, arg port.CreateReportInput) (port.Report, error) {
		return makeReport(), nil
	}

	rr.updateStatusFn = func(ctx context.Context, id, projectID string, status string, totalFindings int32, errorMsg *string) (port.Report, error) {
		r := makeReport()
		r.Status = status
		return r, nil
	}

	callCount := 0
	fr.getByFingerprintFn = func(ctx context.Context, projectID, findingKind, fingerprint string) (port.Finding, error) {
		return port.Finding{}, port.ErrNotFound
	}
	fr.upsertFn = func(ctx context.Context, projectID, findingKind, fingerprint, title, severity string, severityRank int16, score float64, firstSeen, lastSeen time.Time) (port.Finding, error) {
		callCount++
		return makeFinding(callCount), nil
	}

	fr.createOccurrenceFn = func(ctx context.Context, arg port.OccurrenceInput) (port.Occurrence, error) {
		return port.Occurrence{}, nil
	}

	fr.upsertDimensionFn = func(ctx context.Context, arg port.DimensionInput) error {
		return nil
	}

	inv := &mockInventoryRepo{}
	var gotReportID string
	var gotPackages []port.PackageRef
	inv.upsertReportPackagesFn = func(ctx context.Context, reportID string, packages []port.PackageRef) error {
		gotReportID = reportID
		gotPackages = packages
		return nil
	}

	reg := scanner.NewRegistry()
	require.NoError(t, reg.Register(&mockScanner{
		name: "trivy",
		parseFn: func(ctx context.Context, input []byte) (*domain.NormalizedReport, error) {
			return &domain.NormalizedReport{
				ContractVersion:    1,
				FingerprintVersion: 1,
				ScanType:           domain.ScanTypeImage,
				Target:             &domain.TargetInfo{Kind: "container", Identifier: "myapp:latest"},
				Findings: []domain.NormalizedFinding{
					{
						Fingerprint: "fp1",
						FindingKind: "sca",
						Title:       "CVE-2026-1234",
						Severity:    domain.SeverityHigh,
						Score:       7.5,
						Dimensions:  []domain.Dimension{{Key: "vulnerability.id", Value: "CVE-2026-1234"}},
						Extensions:  map[string]any{"title": "CVE-2026-1234", "cvss": "7.5"},
					},
					{
						Fingerprint: "fp2",
						FindingKind: "sca",
						Title:       "CVE-2026-5678",
						Severity:    domain.SeverityMedium,
						Score:       5.0,
					},
				},
				// Vulnerable and clean packages both land in inventory; the
				// duplicate purl is forwarded as-is — the DB primary key is
				// what collapses it.
				Packages: []domain.PackageRef{
					{PURL: "pkg:npm/lodash@4.17.20", Ecosystem: "npm", Name: "lodash", Version: "4.17.20", ManifestPath: "package-lock.json"},
					{PURL: "pkg:golang/github.com/gin-gonic/gin@v1.9.1", Ecosystem: "Go", Name: "github.com/gin-gonic/gin", Version: "v1.9.1"},
					{PURL: "pkg:npm/lodash@4.17.20", Ecosystem: "npm", Name: "lodash", Version: "4.17.20", ManifestPath: "package-lock.json"},
				},
				ScanScope: &domain.ScanScope{Ext: map[string]string{"packages": "150"}},
			}, nil
		},
	}))

	uc := New(Deps{
		Stores: &port.Stores{
			Projects:     pr,
			Reports:      rr,
			Findings:     fr,
			Targets:      stubTargetRepo(),
			Artifacts:    stubArtifactRepo(),
			Environments: &mockEnvironmentRepo{},
			Inventory:    inv,
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

	assert.Equal(t, makeReport().ID, gotReportID, "inventory write must target the created report")
	require.Len(t, gotPackages, 3, "all package refs must be forwarded, duplicates included")
	assert.Equal(t, "pkg:npm/lodash@4.17.20", gotPackages[0].PURL)
	assert.Equal(t, "npm", *gotPackages[0].Ecosystem)
	assert.Equal(t, "lodash", *gotPackages[0].Name)
	assert.Equal(t, "4.17.20", *gotPackages[0].Version)
	assert.Equal(t, "package-lock.json", *gotPackages[0].ManifestPath)
	assert.Equal(t, "pkg:golang/github.com/gin-gonic/gin@v1.9.1", gotPackages[1].PURL)
	assert.Equal(t, "Go", *gotPackages[1].Ecosystem, "ecosystem is stored as-is from the parser")
	assert.Equal(t, "pkg:npm/lodash@4.17.20", gotPackages[2].PURL)
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
	pr.getBySlugFn = func(ctx context.Context, slug string) (port.Project, error) {
		return port.Project{}, port.ErrNotFound
	}

	uc := New(Deps{
		Stores: &port.Stores{Projects: pr},
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
	pr.getBySlugFn = func(ctx context.Context, slug string) (port.Project, error) {
		return makeProject(true), nil
	}

	uc := New(Deps{
		Stores:   &port.Stores{Projects: pr},
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
	pr.getBySlugFn = func(ctx context.Context, slug string) (port.Project, error) {
		return makeProject(true), nil
	}

	reg := scanner.NewRegistry()
	require.NoError(t, reg.Register(&mockScanner{
		name: "trivy",
		parseFn: func(ctx context.Context, input []byte) (*domain.NormalizedReport, error) {
			return nil, fmt.Errorf("invalid scan data")
		},
	}))

	uc := New(Deps{
		Stores: &port.Stores{
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

	pr.getBySlugFn = func(ctx context.Context, slug string) (port.Project, error) {
		return makeProject(true), nil
	}

	rr.createFn = func(ctx context.Context, arg port.CreateReportInput) (port.Report, error) {
		return port.Report{}, port.ErrDuplicateReport
	}

	reg := scanner.NewRegistry()
	require.NoError(t, reg.Register(&mockScanner{
		name: "trivy",
		parseFn: func(ctx context.Context, input []byte) (*domain.NormalizedReport, error) {
			return &domain.NormalizedReport{
				ScanType:  domain.ScanTypeImage,
				Target:    &domain.TargetInfo{Kind: "container", Identifier: "myapp:latest"},
				Findings:  []domain.NormalizedFinding{},
				ScanScope: &domain.ScanScope{},
			}, nil
		},
	}))

	uc := New(Deps{
		Stores: &port.Stores{
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

	pr.getBySlugFn = func(ctx context.Context, slug string) (port.Project, error) {
		return makeProject(true), nil
	}

	rr.createFn = func(ctx context.Context, arg port.CreateReportInput) (port.Report, error) {
		return makeReport(), nil
	}

	rr.updateStatusFn = func(ctx context.Context, id, projectID string, status string, totalFindings int32, errorMsg *string) (port.Report, error) {
		r := makeReport()
		r.Status = status
		return r, nil
	}

	fr.getByFingerprintFn = func(ctx context.Context, projectID, findingKind, fingerprint string) (port.Finding, error) {
		return port.Finding{}, port.ErrNotFound
	}

	fr.upsertFn = func(ctx context.Context, projectID, findingKind, fingerprint, title, severity string, severityRank int16, score float64, firstSeen, lastSeen time.Time) (port.Finding, error) {
		return makeFinding(1), nil
	}

	fr.createOccurrenceFn = func(ctx context.Context, arg port.OccurrenceInput) (port.Occurrence, error) {
		return port.Occurrence{}, nil
	}

	fr.upsertDimensionFn = func(ctx context.Context, arg port.DimensionInput) error {
		return nil
	}

	fr.listByProjectFn = func(ctx context.Context, projectID string, severities, states, kinds, environments, targets []string, limit, offset int32) ([]port.Finding, error) {
		return []port.Finding{makeFinding(1)}, nil
	}

	fr.listGateCandidatesFn = func(ctx context.Context, projectID string, minSeverityRank int16) ([]port.GateCandidate, error) {
		return []port.GateCandidate{{Finding: makeFinding(1)}}, nil
	}

	reg := scanner.NewRegistry()
	require.NoError(t, reg.Register(&mockScanner{
		name: "trivy",
		parseFn: func(ctx context.Context, input []byte) (*domain.NormalizedReport, error) {
			return &domain.NormalizedReport{
				ScanType: domain.ScanTypeImage,
				Target:   &domain.TargetInfo{Kind: "container", Identifier: "myapp:latest"},
				Findings: []domain.NormalizedFinding{
					{Fingerprint: "fp1", FindingKind: "sca", Title: "CVE-2026-1234", Severity: domain.SeverityCritical, Score: 9.5},
				},
				ScanScope: &domain.ScanScope{},
			}, nil
		},
	}))

	uc := New(Deps{
		Stores: &port.Stores{
			Projects:     pr,
			Reports:      rr,
			Findings:     fr,
			Waivers:      &mockWaiverRepo{},
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
	pr.getBySlugFn = func(ctx context.Context, slug string) (port.Project, error) {
		return makeProject(true), nil
	}

	reg := scanner.NewRegistry()
	require.NoError(t, reg.Register(&mockScanner{
		name: "trivy",
		parseFn: func(ctx context.Context, input []byte) (*domain.NormalizedReport, error) {
			return nil, fmt.Errorf("malformed data")
		},
	}))

	uc := New(Deps{
		Stores: &port.Stores{
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

	pr.getBySlugFn = func(ctx context.Context, slug string) (port.Project, error) {
		return makeProject(true), nil
	}

	rr.createFn = func(ctx context.Context, arg port.CreateReportInput) (port.Report, error) {
		return makeReport(), nil
	}

	rr.updateStatusFn = func(ctx context.Context, id, projectID string, status string, totalFindings int32, errorMsg *string) (port.Report, error) {
		r := makeReport()
		r.Status = status
		return r, nil
	}

	callCount := 0
	fr.getByFingerprintFn = func(ctx context.Context, projectID, findingKind, fingerprint string) (port.Finding, error) {
		return port.Finding{}, port.ErrNotFound
	}
	fr.upsertFn = func(ctx context.Context, projectID, findingKind, fingerprint, title, severity string, severityRank int16, score float64, firstSeen, lastSeen time.Time) (port.Finding, error) {
		callCount++
		if callCount == 2 {
			return port.Finding{}, fmt.Errorf("db unavailable")
		}
		return makeFinding(callCount), nil
	}

	fr.createOccurrenceFn = func(ctx context.Context, arg port.OccurrenceInput) (port.Occurrence, error) {
		return port.Occurrence{}, nil
	}

	fr.upsertDimensionFn = func(ctx context.Context, arg port.DimensionInput) error {
		return nil
	}

	reg := scanner.NewRegistry()
	require.NoError(t, reg.Register(&mockScanner{
		name: "trivy",
		parseFn: func(ctx context.Context, input []byte) (*domain.NormalizedReport, error) {
			return &domain.NormalizedReport{
				ScanType: domain.ScanTypeImage,
				Target:   &domain.TargetInfo{Kind: "container", Identifier: "myapp:latest"},
				Findings: []domain.NormalizedFinding{
					{Fingerprint: "fp1", FindingKind: "sca", Title: "CVE-2026-0001", Severity: domain.SeverityHigh, Score: 7.5},
					{Fingerprint: "fp2", FindingKind: "sca", Title: "CVE-2026-0002", Severity: domain.SeverityMedium, Score: 5.0},
				},
				ScanScope: &domain.ScanScope{},
			}, nil
		},
	}))

	uc := New(Deps{
		Stores: &port.Stores{
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

func TestIngestReport_InventoryWriteFailure(t *testing.T) {
	pr, rr, fr := makeTestRepos()

	pr.getBySlugFn = func(ctx context.Context, slug string) (port.Project, error) {
		return makeProject(true), nil
	}

	rr.createFn = func(ctx context.Context, arg port.CreateReportInput) (port.Report, error) {
		return makeReport(), nil
	}

	fr.getByFingerprintFn = func(ctx context.Context, projectID, findingKind, fingerprint string) (port.Finding, error) {
		return port.Finding{}, port.ErrNotFound
	}
	fr.upsertFn = func(ctx context.Context, projectID, findingKind, fingerprint, title, severity string, severityRank int16, score float64, firstSeen, lastSeen time.Time) (port.Finding, error) {
		return makeFinding(1), nil
	}
	fr.createOccurrenceFn = func(ctx context.Context, arg port.OccurrenceInput) (port.Occurrence, error) {
		return port.Occurrence{}, nil
	}
	fr.upsertDimensionFn = func(ctx context.Context, arg port.DimensionInput) error {
		return nil
	}

	updateStatusCalled := false
	rr.updateStatusFn = func(ctx context.Context, id, projectID string, status string, totalFindings int32, errorMsg *string) (port.Report, error) {
		updateStatusCalled = true
		r := makeReport()
		r.Status = status
		return r, nil
	}

	inv := &mockInventoryRepo{}
	inv.upsertReportPackagesFn = func(ctx context.Context, reportID string, packages []port.PackageRef) error {
		return fmt.Errorf("db unavailable")
	}

	reg := scanner.NewRegistry()
	require.NoError(t, reg.Register(&mockScanner{
		name: "trivy",
		parseFn: func(ctx context.Context, input []byte) (*domain.NormalizedReport, error) {
			return &domain.NormalizedReport{
				ScanType: domain.ScanTypeImage,
				Target:   &domain.TargetInfo{Kind: "container", Identifier: "myapp:latest"},
				Findings: []domain.NormalizedFinding{
					{Fingerprint: "fp1", FindingKind: "sca", Title: "CVE-2026-0001", Severity: domain.SeverityHigh, Score: 7.5},
				},
				Packages: []domain.PackageRef{
					{PURL: "pkg:npm/lodash@4.17.20", Ecosystem: "npm", Name: "lodash", Version: "4.17.20"},
				},
				ScanScope: &domain.ScanScope{},
			}, nil
		},
	}))

	uc := New(Deps{
		Stores: &port.Stores{
			Projects:     pr,
			Reports:      rr,
			Findings:     fr,
			Targets:      stubTargetRepo(),
			Artifacts:    stubArtifactRepo(),
			Environments: &mockEnvironmentRepo{},
			Inventory:    inv,
		},
		Registry: reg,
	})

	_, err := uc.IngestReport(context.Background(), IngestReportInput{
		ProjectSlug: "my-app",
		Scanner:     "trivy",
		RawData:     json.RawMessage(`{"test": true}`),
	})
	require.Error(t, err)
	assert.ErrorContains(t, err, "persist package inventory")
	assert.False(t, updateStatusCalled, "a failed inventory batch must fail the ingest before status update")
}

func testJWT(t *testing.T) *auth.JWTAuthenticator {
	a, err := auth.NewJWTAuthenticator("test-secret-for-tests-1234567890")
	require.NoError(t, err)
	return a
}

func makeFindingRow(id int) port.Finding {
	fid := fmt.Sprintf("00000000-0000-0000-0000-00000000002%d", id)
	pid := "00000000-0000-0000-0000-000000000001"
	now := time.Now()
	return port.Finding{
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

	ur.getByEmailFn = func(ctx context.Context, email string) (port.User, error) {
		return port.User{}, port.ErrNotFound
	}
	ur.createFn = func(ctx context.Context, email string, displayName, passwordHash *string) (port.User, error) {
		u := makeUser("00000000-0000-0000-0000-000000000040")
		u.Email = email
		if passwordHash != nil {
			u.PasswordHash = *passwordHash
		}
		return u, nil
	}
	rr.createFn = func(ctx context.Context, userID string, tokenHash string, expiresAt time.Time) (port.RefreshToken, error) {
		return makeRefreshToken(false), nil
	}

	uc := New(Deps{
		Stores:    &port.Stores{Users: ur, RefreshTokens: rr},
		Tokens:    jwt,
		Passwords: auth.NewPasswordHasher(),
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
	ur.getByEmailFn = func(ctx context.Context, email string) (port.User, error) {
		return makeUser("00000000-0000-0000-0000-000000000040"), nil
	}

	uc := New(Deps{
		Stores: &port.Stores{Users: ur},
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

	ur.getByEmailFn = func(ctx context.Context, email string) (port.User, error) {
		u := makeUser("00000000-0000-0000-0000-000000000040")
		u.PasswordHash = hash
		return u, nil
	}
	rr.createFn = func(ctx context.Context, userID string, tokenHash string, expiresAt time.Time) (port.RefreshToken, error) {
		return makeRefreshToken(false), nil
	}

	uc := New(Deps{
		Stores:    &port.Stores{Users: ur, RefreshTokens: rr},
		Tokens:    jwt,
		Passwords: auth.NewPasswordHasher(),
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
	ur.getByEmailFn = func(ctx context.Context, email string) (port.User, error) {
		return port.User{}, port.ErrNotFound
	}

	uc := New(Deps{
		Stores: &port.Stores{Users: ur},
	})

	_, err := uc.Login(context.Background(), "unknown@example.com", "password123")
	assert.EqualError(t, err, "invalid email or password")
}

func TestLogin_NoPasswordHash(t *testing.T) {
	ur := &mockUserRepo{}
	ur.getByEmailFn = func(ctx context.Context, email string) (port.User, error) {
		u := makeUser("00000000-0000-0000-0000-000000000040")
		u.PasswordHash = ""
		return u, nil
	}

	uc := New(Deps{
		Stores: &port.Stores{Users: ur},
	})

	_, err := uc.Login(context.Background(), "test@example.com", "password123")
	assert.EqualError(t, err, "invalid email or password")
}

func TestLogin_WrongPassword(t *testing.T) {
	ur := &mockUserRepo{}
	jwt := testJWT(t)

	hash, err := auth.HashPassword("real-password")
	require.NoError(t, err)

	ur.getByEmailFn = func(ctx context.Context, email string) (port.User, error) {
		u := makeUser("00000000-0000-0000-0000-000000000040")
		u.PasswordHash = hash
		return u, nil
	}

	uc := New(Deps{
		Stores:    &port.Stores{Users: ur},
		Tokens:    jwt,
		Passwords: auth.NewPasswordHasher(),
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

	rr.getByHashFn = func(ctx context.Context, tokenHash string) (port.RefreshToken, error) {
		return token, nil
	}
	rr.revokeFn = func(ctx context.Context, id string) (port.RefreshToken, error) {
		return makeRefreshToken(true), nil
	}
	rr.createFn = func(ctx context.Context, userID string, tokenHash string, expiresAt time.Time) (port.RefreshToken, error) {
		return makeRefreshToken(false), nil
	}
	ur.getByIDFn = func(ctx context.Context, id string) (port.User, error) {
		return makeUser("00000000-0000-0000-0000-000000000040"), nil
	}

	uc := New(Deps{
		Stores:    &port.Stores{RefreshTokens: rr, Users: ur},
		Tokens:    jwt,
		Passwords: auth.NewPasswordHasher(),
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
	rr.getByHashFn = func(ctx context.Context, tokenHash string) (port.RefreshToken, error) {
		return port.RefreshToken{}, port.ErrNotFound
	}

	uc := New(Deps{
		Stores: &port.Stores{RefreshTokens: rr},
	})

	_, err := uc.Refresh(context.Background(), "invalid-token")
	assert.EqualError(t, err, "invalid refresh token")
}

func TestRefresh_RevokedToken(t *testing.T) {
	rr := &mockRefreshTokenRepo{}
	rr.getByHashFn = func(ctx context.Context, tokenHash string) (port.RefreshToken, error) {
		return makeRefreshToken(true), nil
	}

	uc := New(Deps{
		Stores: &port.Stores{RefreshTokens: rr},
	})

	_, err := uc.Refresh(context.Background(), "revoked-token")
	assert.EqualError(t, err, "refresh token has been revoked")
}

func TestRefresh_ExpiredToken(t *testing.T) {
	rr := &mockRefreshTokenRepo{}

	expired := time.Now().Add(-1 * time.Hour)

	rr.getByHashFn = func(ctx context.Context, tokenHash string) (port.RefreshToken, error) {
		tok := makeRefreshToken(false)
		tok.ExpiresAt = expired
		return tok, nil
	}

	uc := New(Deps{
		Stores: &port.Stores{RefreshTokens: rr},
	})

	_, err := uc.Refresh(context.Background(), "expired-token")
	assert.EqualError(t, err, "refresh token has expired")
}

// ----- Logout Tests -----

func TestLogout_Success(t *testing.T) {
	rr := &mockRefreshTokenRepo{}
	rr.getByHashFn = func(ctx context.Context, tokenHash string) (port.RefreshToken, error) {
		return makeRefreshToken(false), nil
	}
	rr.revokeFn = func(ctx context.Context, id string) (port.RefreshToken, error) {
		return makeRefreshToken(true), nil
	}

	uc := New(Deps{
		Stores: &port.Stores{RefreshTokens: rr},
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
	rr.getByHashFn = func(ctx context.Context, tokenHash string) (port.RefreshToken, error) {
		return port.RefreshToken{}, port.ErrNotFound
	}

	uc := New(Deps{
		Stores: &port.Stores{RefreshTokens: rr},
	})

	err := uc.Logout(context.Background(), "invalid-token")
	require.NoError(t, err)
}

// ----- GetProfile Tests -----

func TestGetProfile_Success(t *testing.T) {
	ur := &mockUserRepo{}
	ur.getByIDFn = func(ctx context.Context, id string) (port.User, error) {
		return makeUser("00000000-0000-0000-0000-000000000040"), nil
	}

	uc := New(Deps{
		Stores: &port.Stores{Users: ur},
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
	ur.getByIDFn = func(ctx context.Context, id string) (port.User, error) {
		return port.User{}, port.ErrNotFound
	}

	uc := New(Deps{
		Stores: &port.Stores{Users: ur},
	})

	_, err := uc.GetProfile(context.Background(), "00000000-0000-0000-0000-000000000001")
	assert.EqualError(t, err, "user not found")
}

// ----- GetFinding Tests -----

func TestGetFinding_Success(t *testing.T) {
	fr := &mockFindingRepo{}
	fr.getByFingerprintFn = func(ctx context.Context, projectID, findingKind, fingerprint string) (port.Finding, error) {
		return port.Finding{}, fmt.Errorf("not used")
	}

	fr.getByFingerprintFn = nil
	fr.getByIDFn = func(ctx context.Context, id string) (port.Finding, error) {
		return makeFindingRow(1), nil
	}

	uc := New(Deps{
		Stores: &port.Stores{Findings: fr},
	})

	finding, err := uc.GetFinding(findingScopeCtx(findingFixtureProjectID), "00000000-0000-0000-0000-000000000021")
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
	fr.getByIDFn = func(ctx context.Context, id string) (port.Finding, error) {
		return port.Finding{}, port.ErrNotFound
	}

	uc := New(Deps{
		Stores: &port.Stores{Findings: fr},
	})

	_, err := uc.GetFinding(context.Background(), "00000000-0000-0000-0000-000000000021")
	assert.ErrorContains(t, err, "get finding")
}

// ----- GetGateStatus Tests -----

func TestGetGateStatus_Success(t *testing.T) {
	pr := &mockProjectRepo{}
	fr := &mockFindingRepo{}
	wr := &mockWaiverRepo{}

	pr.getBySlugFn = func(ctx context.Context, slug string) (port.Project, error) {
		return makeProject(true), nil
	}
	fr.listGateCandidatesFn = func(ctx context.Context, projectID string, minSeverityRank int16) ([]port.GateCandidate, error) {
		return []port.GateCandidate{
			{Finding: makeFindingRow(1)},
			{Finding: makeFindingRow(2)},
			{Finding: makeFindingRow(3)},
		}, nil
	}

	uc := New(Deps{
		Stores: &port.Stores{Projects: pr, Findings: fr, Waivers: wr},
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
	pr.getBySlugFn = func(ctx context.Context, slug string) (port.Project, error) {
		return port.Project{}, port.ErrNotFound
	}

	uc := New(Deps{
		Stores: &port.Stores{Projects: pr},
	})

	_, err := uc.GetGateStatus(context.Background(), "nonexistent", 2)
	assert.ErrorContains(t, err, "lookup project")
}

// ----- ListFindings Tests -----

func TestListFindings_Success(t *testing.T) {
	pr := &mockProjectRepo{}
	fr := &mockFindingRepo{}

	pr.getBySlugFn = func(ctx context.Context, slug string) (port.Project, error) {
		return makeProject(true), nil
	}
	fr.listByProjectFn = func(ctx context.Context, projectID string, severities, states, kinds, environments, targets []string, limit, offset int32) ([]port.Finding, error) {
		return []port.Finding{makeFindingRow(1), makeFindingRow(2)}, nil
	}

	uc := New(Deps{
		Stores: &port.Stores{Projects: pr, Findings: fr},
	})

	findings, err := uc.ListFindings(context.Background(), "my-app", FindingFilter{}, 20, 0)
	require.NoError(t, err)
	assert.Len(t, findings, 2)
}

func TestListFindings_ProjectNotFound(t *testing.T) {
	pr := &mockProjectRepo{}
	pr.getBySlugFn = func(ctx context.Context, slug string) (port.Project, error) {
		return port.Project{}, port.ErrNotFound
	}

	uc := New(Deps{
		Stores: &port.Stores{Projects: pr},
	})

	_, err := uc.ListFindings(context.Background(), "nonexistent", FindingFilter{}, 20, 0)
	assert.ErrorContains(t, err, "lookup project")
}

// ----- ListProjects Tests -----

func TestListProjects_Success(t *testing.T) {
	pr := &mockProjectRepo{}
	pr.listFn = func(ctx context.Context) ([]port.Project, error) {
		return []port.Project{makeProject(true)}, nil
	}

	uc := New(Deps{
		Stores: &port.Stores{Projects: pr},
	})

	projects, err := uc.ListProjects(context.Background())
	require.NoError(t, err)
	assert.Len(t, projects, 1)
	assert.Equal(t, "my-app", projects[0].Slug)
}

// ----- GetProject Tests -----

func TestGetProject_Success(t *testing.T) {
	pr := &mockProjectRepo{}
	pr.getBySlugFn = func(ctx context.Context, slug string) (port.Project, error) {
		return makeProject(true), nil
	}

	uc := New(Deps{
		Stores: &port.Stores{Projects: pr},
	})

	proj, err := uc.GetProject(context.Background(), "my-app")
	require.NoError(t, err)
	require.NotNil(t, proj)
	assert.Equal(t, "my-app", proj.Slug)
}

func TestGetProject_NotFound(t *testing.T) {
	pr := &mockProjectRepo{}
	pr.getBySlugFn = func(ctx context.Context, slug string) (port.Project, error) {
		return port.Project{}, port.ErrNotFound
	}

	uc := New(Deps{
		Stores: &port.Stores{Projects: pr},
	})

	_, err := uc.GetProject(context.Background(), "nonexistent")
	assert.ErrorContains(t, err, "get project")
}

// ----- ListReports Tests -----

func TestListReports_Success(t *testing.T) {
	pr := &mockProjectRepo{}
	rr := &mockReportRepo{}

	pr.getBySlugFn = func(ctx context.Context, slug string) (port.Project, error) {
		return makeProject(true), nil
	}
	rr.listByProjectFn = func(ctx context.Context, projectID string, limit, offset int32) ([]port.Report, error) {
		return []port.Report{makeReport()}, nil
	}

	uc := New(Deps{
		Stores: &port.Stores{Projects: pr, Reports: rr},
	})

	reports, err := uc.ListReports(context.Background(), "my-app", 20, 0)
	require.NoError(t, err)
	assert.Len(t, reports, 1)
	assert.Equal(t, "trivy", reports[0].ToolName)
}

func TestListReports_ProjectNotFound(t *testing.T) {
	pr := &mockProjectRepo{}
	pr.getBySlugFn = func(ctx context.Context, slug string) (port.Project, error) {
		return port.Project{}, port.ErrNotFound
	}

	uc := New(Deps{
		Stores: &port.Stores{Projects: pr},
	})

	_, err := uc.ListReports(context.Background(), "nonexistent", 20, 0)
	assert.ErrorContains(t, err, "lookup project")
}

// ----- GetReport Tests -----

func TestGetReport_Success(t *testing.T) {
	rr := &mockReportRepo{}
	rr.getByIDFn = func(ctx context.Context, id string) (port.Report, error) {
		return makeReport(), nil
	}

	uc := New(Deps{
		Stores: &port.Stores{Reports: rr},
	})

	report, err := uc.GetReport(context.Background(), "00000000-0000-0000-0000-000000000001")
	require.NoError(t, err)
	require.NotNil(t, report)
	assert.Equal(t, "trivy", report.ToolName)
}

func TestGetReport_NotFound(t *testing.T) {
	rr := &mockReportRepo{}
	rr.getByIDFn = func(ctx context.Context, id string) (port.Report, error) {
		return port.Report{}, port.ErrNotFound
	}

	uc := New(Deps{
		Stores: &port.Stores{Reports: rr},
	})

	_, err := uc.GetReport(context.Background(), "00000000-0000-0000-0000-000000000001")
	assert.ErrorContains(t, err, "get report")
}

// ----- CreateAPIKey Tests -----

func TestCreateAPIKey_Success(t *testing.T) {
	pr := &mockProjectRepo{}
	akr := &mockAPIKeyRepo{}

	pr.getBySlugFn = func(ctx context.Context, slug string) (port.Project, error) {
		return makeProject(true), nil
	}
	akr.createFn = func(ctx context.Context, arg port.CreateAPIKeyInput) (port.APIKey, error) {
		now := time.Now()
		return port.APIKey{
			ID:   "00000000-0000-0000-0000-000000000050",
			Name: arg.Name, KeyPrefix: arg.KeyPrefix, LastFour: new(arg.LastFour),
			ProjectID: arg.ProjectID, CreatedBy: new(arg.CreatedBy), CreatedAt: now,
		}, nil
	}

	uc := New(Deps{
		Stores: &port.Stores{Projects: pr, APIKeys: akr},
	})

	resp, err := uc.CreateAPIKey(context.Background(), "my-app", "ci-key", "00000000-0000-0000-0000-000000000001")
	require.NoError(t, err)
	require.NotNil(t, resp)
	assert.Equal(t, "ci-key", resp.Name)
	assert.NotEmpty(t, resp.RawKey)
	assert.True(t, len(resp.KeyPrefix) > 0)
}

func TestCreateAPIKey_ProjectNotFound(t *testing.T) {
	pr := &mockProjectRepo{}
	pr.getBySlugFn = func(ctx context.Context, slug string) (port.Project, error) {
		return port.Project{}, port.ErrNotFound
	}

	uc := New(Deps{
		Stores: &port.Stores{Projects: pr},
	})

	_, err := uc.CreateAPIKey(context.Background(), "nonexistent", "ci-key", "00000000-0000-0000-0000-000000000001")
	assert.ErrorContains(t, err, "project not found")
}

// ----- ListAPIKeys Tests -----

func TestListAPIKeys_Success(t *testing.T) {
	pr := &mockProjectRepo{}
	akr := &mockAPIKeyRepo{}

	pr.getBySlugFn = func(ctx context.Context, slug string) (port.Project, error) {
		return makeProject(true), nil
	}
	akr.listByProjectFn = func(ctx context.Context, projectID string) ([]port.APIKey, error) {
		return []port.APIKey{{
			ID:        "00000000-0000-0000-0000-000000000005",
			ProjectID: projectID, Name: "ci-key", KeyPrefix: "vuln_abc", CreatedAt: time.Now(),
		}}, nil
	}

	uc := New(Deps{
		Stores: &port.Stores{Projects: pr, APIKeys: akr},
	})

	keys, err := uc.ListAPIKeys(context.Background(), "my-app")
	require.NoError(t, err)
	assert.Len(t, keys, 1)
	assert.Equal(t, "ci-key", keys[0].Name)
}

func TestListAPIKeys_ProjectNotFound(t *testing.T) {
	pr := &mockProjectRepo{}
	pr.getBySlugFn = func(ctx context.Context, slug string) (port.Project, error) {
		return port.Project{}, port.ErrNotFound
	}

	uc := New(Deps{
		Stores: &port.Stores{Projects: pr},
	})

	_, err := uc.ListAPIKeys(context.Background(), "nonexistent")
	assert.ErrorContains(t, err, "project not found")
}

// ----- RevokeAPIKey Tests -----

func TestRevokeAPIKey_Success(t *testing.T) {
	pr := &mockProjectRepo{}
	akr := &mockAPIKeyRepo{}

	pr.getBySlugFn = func(ctx context.Context, slug string) (port.Project, error) {
		return makeProject(true), nil
	}
	akr.revokeFn = func(ctx context.Context, id, projectID string) (port.APIKey, error) {
		return port.APIKey{}, nil
	}

	uc := New(Deps{
		Stores: &port.Stores{Projects: pr, APIKeys: akr},
	})

	err := uc.RevokeAPIKey(context.Background(), "my-app", "00000000-0000-0000-0000-000000000050")
	require.NoError(t, err)
}

func TestRevokeAPIKey_ProjectNotFound(t *testing.T) {
	pr := &mockProjectRepo{}
	pr.getBySlugFn = func(ctx context.Context, slug string) (port.Project, error) {
		return port.Project{}, port.ErrNotFound
	}

	uc := New(Deps{
		Stores: &port.Stores{Projects: pr},
	})

	err := uc.RevokeAPIKey(context.Background(), "nonexistent", "some-id")
	assert.ErrorContains(t, err, "project not found")
}

func TestRevokeAPIKey_InvalidID(t *testing.T) {
	pr := &mockProjectRepo{}
	akr := &mockAPIKeyRepo{}

	pr.getBySlugFn = func(ctx context.Context, slug string) (port.Project, error) {
		return makeProject(true), nil
	}
	akr.revokeFn = nil

	uc := New(Deps{
		Stores: &port.Stores{Projects: pr, APIKeys: akr},
	})

	err := uc.RevokeAPIKey(context.Background(), "my-app", "not-a-uuid")
	assert.ErrorContains(t, err, "invalid key id")
}

// ----- TriageFinding Tests -----

func TestTriageFinding_Success(t *testing.T) {
	fID := "00000000-0000-0000-0000-000000000021"

	fr := &mockFindingRepo{}
	fr.getByIDFn = func(ctx context.Context, id string) (port.Finding, error) {
		f := makeFindingRow(1)
		f.AnalysisState = "unanalyzed"
		f.GateEffect = "block"
		return f, nil
	}
	fr.updateAnalysisFn = func(ctx context.Context, arg port.UpdateAnalysisInput) (port.Finding, error) {
		f := makeFindingRow(1)
		f.AnalysisState = "false_positive"
		f.GateEffect = "ignore"
		return f, nil
	}
	fr.createEventFn = func(ctx context.Context, arg port.FindingEventInput) (port.FindingEvent, error) {
		return port.FindingEvent{}, nil
	}

	uc := New(Deps{
		Stores: &port.Stores{Findings: fr},
	})

	result, err := uc.TriageFinding(findingScopeCtx(findingFixtureProjectID), TriageInput{
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
	fr.getByIDFn = func(ctx context.Context, id string) (port.Finding, error) {
		return port.Finding{}, port.ErrNotFound
	}

	uc := New(Deps{
		Stores: &port.Stores{Findings: fr},
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
	fr.getByIDFn = func(ctx context.Context, id string) (port.Finding, error) {
		return makeFindingRow(1), nil
	}

	uc := New(Deps{
		Stores: &port.Stores{Findings: fr},
	})

	_, err := uc.TriageFinding(findingScopeCtx(findingFixtureProjectID), TriageInput{
		FindingID:     "00000000-0000-0000-0000-000000000021",
		AnalysisState: "false_positive",
		UserID:        "00000000-0000-0000-0000-000000000040",
	})
	assert.ErrorIs(t, err, ErrReasonRequired)
}

func TestTriageFinding_MissingExpiry(t *testing.T) {
	fr := &mockFindingRepo{}
	fr.getByIDFn = func(ctx context.Context, id string) (port.Finding, error) {
		return makeFindingRow(1), nil
	}

	uc := New(Deps{
		Stores: &port.Stores{Findings: fr},
	})

	_, err := uc.TriageFinding(findingScopeCtx(findingFixtureProjectID), TriageInput{
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
	fr.listByIDsFn = func(ctx context.Context, ids []string) ([]port.Finding, error) {
		return []port.Finding{makeFindingRow(1)}, nil
	}
	fr.bulkUpdateAnalysisFn = func(ctx context.Context, arg port.UpdateAnalysisInput, ids []string) ([]port.Finding, error) {
		f := makeFindingRow(1)
		f.AnalysisState = "false_positive"
		f.GateEffect = "ignore"
		return []port.Finding{f}, nil
	}
	fr.createEventFn = func(ctx context.Context, arg port.FindingEventInput) (port.FindingEvent, error) {
		return port.FindingEvent{}, nil
	}

	uc := New(Deps{
		Stores: &port.Stores{Findings: fr},
	})

	results, err := uc.BulkTriage(findingScopeCtx(findingFixtureProjectID), BulkTriageInput{
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
	fr.listByIDsFn = func(ctx context.Context, ids []string) ([]port.Finding, error) {
		return []port.Finding{}, nil
	}

	uc := New(Deps{
		Stores: &port.Stores{Findings: fr},
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
	fr.getByIDFn = func(ctx context.Context, id string) (port.Finding, error) {
		return makeFindingRow(1), nil
	}
	fr.listEventsFn = func(ctx context.Context, findingID string, eventTypes []string, limit, offset int32) ([]port.FindingEvent, error) {
		return []port.FindingEvent{
			{EventType: "analysis_changed"},
		}, nil
	}

	uc := New(Deps{
		Stores: &port.Stores{Findings: fr},
	})

	events, err := uc.GetFindingEvents(findingScopeCtx(findingFixtureProjectID), "00000000-0000-0000-0000-000000000021", nil, 10, 0)
	require.NoError(t, err)
	assert.Len(t, events, 1)
	assert.Equal(t, "analysis_changed", events[0].EventType)
}

func TestGetFindingEvents_InvalidID(t *testing.T) {
	uc := New(Deps{})
	_, err := uc.GetFindingEvents(context.Background(), "not-a-uuid", nil, 10, 0)
	assert.ErrorContains(t, err, "invalid finding id")
}

func TestGetGateStatus_IncludesBlockedByReachability(t *testing.T) {
	pr := &mockProjectRepo{}
	fr := &mockFindingRepo{}
	wr := &mockWaiverRepo{}
	rch := &mockReachabilityRepo{}

	pr.getBySlugFn = func(ctx context.Context, slug string) (port.Project, error) {
		return makeProject(true), nil
	}
	row1 := makeFindingRow(1)
	row2 := makeFindingRow(2)
	fr.listGateCandidatesFn = func(ctx context.Context, projectID string, minSeverityRank int16) ([]port.GateCandidate, error) {
		return []port.GateCandidate{
			{Finding: row1, Reachability: "reachable"},
			{Finding: row2, Reachability: ""}, // no assessment => unknown
		}, nil
	}

	uc := New(Deps{
		Stores: &port.Stores{Projects: pr, Findings: fr, Waivers: wr, Reachability: rch},
	})

	status, err := uc.GetGateStatus(context.Background(), "my-app", 2)
	require.NoError(t, err)
	require.NotNil(t, status)
	assert.True(t, status.ThresholdBreached)
	assert.Equal(t, []string{
		"00000000-0000-0000-0000-000000000021",
		"00000000-0000-0000-0000-000000000022",
	}, status.BlockedBy)
	// Reachability arrives in the batch row (no separate per-finding or
	// N+1 reachability calls). The reachability store is never consulted.
	assert.Equal(t, map[string]string{
		"00000000-0000-0000-0000-000000000021": "reachable",
		"00000000-0000-0000-0000-000000000022": "unknown",
	}, status.BlockedByReachability)
}

func TestGetGateStatus_ReachabilityExemptionsPass(t *testing.T) {
	pr := &mockProjectRepo{}
	fr := &mockFindingRepo{}
	wr := &mockWaiverRepo{}
	rch := &mockReachabilityRepo{}

	pr.getBySlugFn = func(ctx context.Context, slug string) (port.Project, error) {
		return makeProject(true), nil
	}
	row1 := makeFindingRow(1)
	row2 := makeFindingRow(2)
	fr.listGateCandidatesFn = func(ctx context.Context, projectID string, minSeverityRank int16) ([]port.GateCandidate, error) {
		return []port.GateCandidate{
			{Finding: row1, Reachability: "not_reachable"},
			{Finding: row2, Reachability: "not_applicable"},
		}, nil
	}

	uc := New(Deps{
		Stores: &port.Stores{Projects: pr, Findings: fr, Waivers: wr, Reachability: rch},
	})

	status, err := uc.GetGateStatus(context.Background(), "my-app", 2)
	require.NoError(t, err)
	assert.False(t, status.ThresholdBreached)
	assert.Zero(t, status.BlockingCount)
	assert.Empty(t, status.BlockedBy)
	assert.Empty(t, status.BlockedByReachability)
}

func TestGetGateStatus_ReachabilityLookupError(t *testing.T) {
	pr := &mockProjectRepo{}
	fr := &mockFindingRepo{}
	wr := &mockWaiverRepo{}
	rch := &mockReachabilityRepo{}

	pr.getBySlugFn = func(ctx context.Context, slug string) (port.Project, error) {
		return makeProject(true), nil
	}
	fr.listGateCandidatesFn = func(ctx context.Context, projectID string, minSeverityRank int16) ([]port.GateCandidate, error) {
		return nil, fmt.Errorf("database unavailable")
	}

	uc := New(Deps{
		Stores: &port.Stores{Projects: pr, Findings: fr, Waivers: wr, Reachability: rch},
	})

	_, err := uc.GetGateStatus(context.Background(), "my-app", 2)
	assert.ErrorContains(t, err, "database unavailable")
}

func TestUpsertReachability_InvalidState(t *testing.T) {
	rch := &mockReachabilityRepo{}
	uc := New(Deps{Stores: &port.Stores{Reachability: rch}})

	_, err := uc.UpsertReachability(context.Background(), "00000000-0000-0000-0000-000000000001", "00000000-0000-0000-0000-000000000002", "definitely-reachable", "evidence")
	require.ErrorIs(t, err, ErrInvalidReachabilityState)
}

func TestUpsertReachability_UsesUpdatedAt(t *testing.T) {
	id := "00000000-0000-0000-0000-000000000030"
	findingID := "00000000-0000-0000-0000-000000000031"
	userID := "00000000-0000-0000-0000-000000000032"
	createdAt := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	updatedAt := time.Date(2026, 1, 2, 0, 0, 0, 0, time.UTC)
	rch := &mockReachabilityRepo{}
	rch.upsertFn = func(ctx context.Context, findingID, state, evidence, assessedBy string) (port.ReachabilityAssessment, error) {
		return port.ReachabilityAssessment{
			ID: id, FindingID: findingID, State: "reachable",
			AssessedBy: userID, CreatedAt: createdAt, UpdatedAt: updatedAt,
		}, nil
	}
	fr := &mockFindingRepo{}
	fr.getByIDFn = func(ctx context.Context, id string) (port.Finding, error) {
		return makeFindingRow(1), nil
	}
	uc := New(Deps{Stores: &port.Stores{Findings: fr, Reachability: rch}})

	result, err := uc.UpsertReachability(findingScopeCtx(findingFixtureProjectID), findingID, userID, "reachable", "evidence")
	require.NoError(t, err)
	assert.Equal(t, updatedAt.Format(time.RFC3339), result.UpdatedAt)
}

func TestReachability_InvalidFindingID(t *testing.T) {
	uc := New(Deps{})

	_, err := uc.ListReachability(context.Background(), "not-a-uuid")
	require.ErrorIs(t, err, ErrInvalidFindingID)

	_, err = uc.UpsertReachability(
		context.Background(),
		"not-a-uuid",
		"00000000-0000-0000-0000-000000000002",
		"unknown",
		"",
	)
	require.ErrorIs(t, err, ErrInvalidFindingID)
}

func TestReachability_ValidatesFindingForJWT(t *testing.T) {
	fr := &mockFindingRepo{}
	var findingLookups int
	fr.getByIDFn = func(ctx context.Context, id string) (port.Finding, error) {
		findingLookups++
		return port.Finding{}, fmt.Errorf("missing finding")
	}
	rch := &mockReachabilityRepo{
		listByFindingFn: func(ctx context.Context, findingID string) ([]port.ReachabilityAssessment, error) {
			return nil, nil
		},
		upsertFn: func(ctx context.Context, findingID, state, evidence, assessedBy string) (port.ReachabilityAssessment, error) {
			return port.ReachabilityAssessment{}, nil
		},
	}
	uc := New(Deps{Stores: &port.Stores{Findings: fr, Reachability: rch}})
	ctx := auth.ContextWithIdentity(context.Background(), &auth.Identity{
		UserID: "00000000-0000-0000-0000-000000000002",
	})
	findingID := "00000000-0000-0000-0000-000000000021"

	_, err := uc.ListReachability(ctx, findingID)
	require.ErrorIs(t, err, ErrFindingNotFound)

	_, err = uc.UpsertReachability(ctx, findingID, "00000000-0000-0000-0000-000000000002", "unknown", "")
	require.ErrorIs(t, err, ErrFindingNotFound)
	assert.Equal(t, 2, findingLookups)
}

func TestReachability_APIKeyCannotCrossProject(t *testing.T) {
	fr := &mockFindingRepo{}
	fr.getByIDFn = func(ctx context.Context, id string) (port.Finding, error) {
		return makeFindingRow(1), nil
	}
	rch := &mockReachabilityRepo{}
	rch.upsertFn = func(ctx context.Context, findingID, state, evidence, assessedBy string) (port.ReachabilityAssessment, error) {
		t.Fatal("cross-project reachability must be denied before the write")
		return port.ReachabilityAssessment{}, nil
	}
	uc := New(Deps{Stores: &port.Stores{Findings: fr, Reachability: rch}})
	ctx := auth.ContextWithIdentity(context.Background(), &auth.Identity{
		UserID:    "00000000-0000-0000-0000-000000000040",
		ProjectID: "00000000-0000-0000-0000-000000000002",
		IsAPIKey:  true,
	})

	_, err := uc.UpsertReachability(ctx,
		"00000000-0000-0000-0000-000000000021",
		"00000000-0000-0000-0000-000000000040",
		"reachable", "evidence")
	require.ErrorIs(t, err, ErrProjectAccessDenied)

	_, err = uc.ListReachability(ctx,
		"00000000-0000-0000-0000-000000000021")
	require.ErrorIs(t, err, ErrProjectAccessDenied)
}

func TestFindingWrites_APIKeyCannotCrossProject(t *testing.T) {
	fr := &mockFindingRepo{}
	fr.getByIDFn = func(ctx context.Context, id string) (port.Finding, error) {
		return makeFindingRow(1), nil
	}
	fr.listByIDsFn = func(ctx context.Context, ids []string) ([]port.Finding, error) {
		return []port.Finding{makeFindingRow(1)}, nil
	}
	er := &mockEvidenceRepo{}
	er.getByIDFn = func(ctx context.Context, id string) (port.Evidence, error) {
		return port.Evidence{FindingID: makeFindingRow(1).ID}, nil
	}
	uc := New(Deps{Stores: &port.Stores{Findings: fr, Evidence: er}})
	ctx := auth.ContextWithIdentity(context.Background(), &auth.Identity{
		UserID:    "00000000-0000-0000-0000-000000000040",
		ProjectID: "00000000-0000-0000-0000-000000000002",
		IsAPIKey:  true,
	})
	findingID := "00000000-0000-0000-0000-000000000021"
	userID := "00000000-0000-0000-0000-000000000040"

	_, err := uc.TriageFinding(ctx, TriageInput{
		FindingID:     findingID,
		AnalysisState: "exploitable",
		UserID:        userID,
	})
	require.ErrorIs(t, err, ErrProjectAccessDenied)

	_, err = uc.CreateEvidence(ctx, findingID, userID, "url", "https://example.test", "evidence")
	require.ErrorIs(t, err, ErrProjectAccessDenied)

	_, err = uc.UpsertSignoff(ctx, findingID, userID, "approved", "reviewed")
	require.ErrorIs(t, err, ErrProjectAccessDenied)

	err = uc.DeleteEvidence(ctx, "00000000-0000-0000-0000-000000000031")
	require.ErrorIs(t, err, ErrProjectAccessDenied)

	_, err = uc.BulkTriage(ctx, BulkTriageInput{
		FindingIDs:    []string{findingID},
		AnalysisState: "exploitable",
		UserID:        userID,
	})
	require.ErrorIs(t, err, ErrProjectAccessDenied)
}

func TestFindingReads_APIKeyCannotCrossProject(t *testing.T) {
	fr := &mockFindingRepo{}
	finding := makeFindingRow(1)
	fr.getByIDFn = func(ctx context.Context, id string) (port.Finding, error) {
		return finding, nil
	}
	fr.listEventsFn = func(ctx context.Context, findingID string, eventTypes []string, limit, offset int32) ([]port.FindingEvent, error) {
		return []port.FindingEvent{{FindingID: finding.ID}}, nil
	}
	er := &mockEvidenceRepo{
		listByFindingFn: func(ctx context.Context, findingID string) ([]port.Evidence, error) {
			return []port.Evidence{{FindingID: finding.ID}}, nil
		},
	}
	sr := &mockSignoffRepo{
		getByFindingFn: func(ctx context.Context, findingID string) (port.Signoff, error) {
			return port.Signoff{FindingID: finding.ID}, nil
		},
	}
	uc := New(Deps{Stores: &port.Stores{Findings: fr, Evidence: er, Signoffs: sr}})
	ctx := auth.ContextWithIdentity(context.Background(), &auth.Identity{
		UserID:    "00000000-0000-0000-0000-000000000040",
		ProjectID: "00000000-0000-0000-0000-000000000002",
		IsAPIKey:  true,
	})
	findingID := "00000000-0000-0000-0000-000000000021"

	_, err := uc.GetFinding(ctx, findingID)
	require.ErrorIs(t, err, ErrProjectAccessDenied)

	_, err = uc.GetFindingEvents(ctx, findingID, nil, 10, 0)
	require.ErrorIs(t, err, ErrProjectAccessDenied)

	_, err = uc.ListEvidence(ctx, findingID)
	require.ErrorIs(t, err, ErrProjectAccessDenied)

	_, err = uc.GetSignoff(ctx, findingID)
	require.ErrorIs(t, err, ErrProjectAccessDenied)
}

func TestCreateAPIKey_RecordsCreator(t *testing.T) {
	pr := &mockProjectRepo{}
	akr := &mockAPIKeyRepo{}
	var gotCreator string

	pr.getBySlugFn = func(ctx context.Context, slug string) (port.Project, error) {
		return makeProject(true), nil
	}
	akr.createFn = func(ctx context.Context, arg port.CreateAPIKeyInput) (port.APIKey, error) {
		gotCreator = arg.CreatedBy
		return port.APIKey{
			ID:   "00000000-0000-0000-0000-000000000050",
			Name: arg.Name, KeyPrefix: arg.KeyPrefix, CreatedAt: time.Now(),
		}, nil
	}

	uc := New(Deps{Stores: &port.Stores{Projects: pr, APIKeys: akr}})
	_, err := uc.CreateAPIKey(context.Background(), "my-app", "ci-key", "00000000-0000-0000-0000-000000000001")
	require.NoError(t, err)
	assert.Equal(t, "00000000-0000-0000-0000-000000000001", gotCreator)
}

// TestIngestGateParity_GetGateStatusAgrees asserts Phase 4's core contract:
// after a completed ingest, the ingest response's ThresholdBreached equals
// what a subsequent GET /api/v1/projects/{slug}/gate would report for the
// same project. Both paths now run through the same gate service, so a
// waiver covering every blocking finding flips both to false and an unwaived
// critical finding keeps both true.
func TestIngestGateParity_GetGateStatusAgrees(t *testing.T) {
	pr, rr, fr := makeTestRepos()
	wr := &mockWaiverRepo{}

	pr.getBySlugFn = func(ctx context.Context, slug string) (port.Project, error) {
		return makeProject(true), nil
	}
	rr.createFn = func(ctx context.Context, arg port.CreateReportInput) (port.Report, error) {
		return makeReport(), nil
	}
	rr.updateStatusFn = func(ctx context.Context, id, projectID string, status string, totalFindings int32, errorMsg *string) (port.Report, error) {
		r := makeReport()
		r.Status = status
		return r, nil
	}
	fr.getByFingerprintFn = func(ctx context.Context, projectID, findingKind, fingerprint string) (port.Finding, error) {
		return port.Finding{}, port.ErrNotFound
	}
	fr.upsertFn = func(ctx context.Context, projectID, findingKind, fingerprint, title, severity string, severityRank int16, score float64, firstSeen, lastSeen time.Time) (port.Finding, error) {
		return makeFinding(1), nil
	}
	fr.createOccurrenceFn = func(ctx context.Context, arg port.OccurrenceInput) (port.Occurrence, error) {
		return port.Occurrence{}, nil
	}
	fr.upsertDimensionFn = func(ctx context.Context, arg port.DimensionInput) error {
		return nil
	}
	// One unwaived blocking candidate (rank 4 => above the default high floor).
	blocking := makeFinding(1)
	blocking.CurrentSeverityRank = 4
	fr.listGateCandidatesFn = func(ctx context.Context, projectID string, minSeverityRank int16) ([]port.GateCandidate, error) {
		return []port.GateCandidate{{Finding: blocking}}, nil
	}
	wr.listActiveFn = func(ctx context.Context, projectID string) ([]port.Waiver, error) {
		return nil, nil // no waivers => still blocked
	}

	uc := New(Deps{
		Stores: &port.Stores{
			Projects: pr, Reports: rr, Findings: fr, Waivers: wr,
			Targets: stubTargetRepo(), Artifacts: stubArtifactRepo(),
			Environments: &mockEnvironmentRepo{},
		},
		Registry: newTestRegistryWithCriticalFinding(),
	})

	ingestOut, err := uc.IngestReport(context.Background(), IngestReportInput{
		ProjectSlug: "my-app",
		Scanner:     "trivy",
		RawData:     json.RawMessage(`{"test": true}`),
	})
	require.NoError(t, err)
	assert.True(t, ingestOut.ThresholdBreached, "unwaived critical finding breaches ingest gate")

	gateStatus, err := uc.GetGateStatus(context.Background(), "my-app", 3)
	require.NoError(t, err)
	assert.Equal(t, ingestOut.ThresholdBreached, gateStatus.ThresholdBreached,
		"ingest response and GET gate must agree for the same completed report")
	assert.True(t, gateStatus.ThresholdBreached)
}

// newTestRegistryWithCriticalFinding registers a trivy mock scanner whose
// report carries one critical SCA finding.
func newTestRegistryWithCriticalFinding() *scanner.Registry {
	reg := scanner.NewRegistry()
	_ = reg.Register(&mockScanner{
		name: "trivy",
		parseFn: func(ctx context.Context, input []byte) (*domain.NormalizedReport, error) {
			return &domain.NormalizedReport{
				ScanType: domain.ScanTypeImage,
				Target:   &domain.TargetInfo{Kind: "container", Identifier: "myapp:latest"},
				Findings: []domain.NormalizedFinding{
					{Fingerprint: "fp1", FindingKind: "sca", Title: "CVE-2026-1234", Severity: domain.SeverityCritical, Score: 9.5},
				},
				ScanScope: &domain.ScanScope{},
			}, nil
		},
	})
	return reg
}

// TestGatePoliciesForProject maps the stored project mode to gate source
// policies — the SQL literal policy is gone; the watcher source category is
// data, not a core constant.
func TestGatePoliciesForProject(t *testing.T) {
	tests := []struct {
		mode string
		want []gate.GatePolicy
	}{
		{"", nil},
		{"immediate", nil},
		{"off", []gate.GatePolicy{{Source: "cve_watcher", Mode: gate.PolicyOff}}},
		{"require_triage", []gate.GatePolicy{{Source: "cve_watcher", Mode: gate.PolicyRequireTriage}}},
	}
	for _, tt := range tests {
		got := gatePoliciesForProject(port.Project{CveWatcherGate: tt.mode})
		assert.Equal(t, tt.want, got, "mode %q", tt.mode)
	}
}

// TestGetGateStatus_WatcherRequireTriageDropsUntriaged asserts the watcher
// policy is honored through the gate service without any SQL literal: an
// untriaged cve_watcher finding is not a gate candidate under require_triage,
// while a triaged one is.
func TestGetGateStatus_WatcherRequireTriageDropsUntriaged(t *testing.T) {
	pr := &mockProjectRepo{}
	fr := &mockFindingRepo{}
	wr := &mockWaiverRepo{}
	rch := &mockReachabilityRepo{}

	pr.getBySlugFn = func(ctx context.Context, slug string) (port.Project, error) {
		return makeProject(true), nil
	}
	untriaged := port.Finding{ID: "w1", FindingKind: "cve_watcher", CurrentSeverityRank: 4, AnalysisState: ""}
	triaged := port.Finding{ID: "w2", FindingKind: "cve_watcher", CurrentSeverityRank: 4, AnalysisState: "exploitable"}
	fr.listGateCandidatesFn = func(ctx context.Context, projectID string, minSeverityRank int16) ([]port.GateCandidate, error) {
		return []port.GateCandidate{{Finding: untriaged}, {Finding: triaged}}, nil
	}
	// The candidate SQL no longer filters by project mode: the full candidate
	// set is returned and the core policy decides admission.
	_ = rch
	uc := New(Deps{
		Stores: &port.Stores{Projects: pr, Findings: fr, Waivers: wr},
	})

	// Default project (cve_watcher_gate = "" -> immediate): both block.
	status, err := uc.GetGateStatus(context.Background(), "my-app", 3)
	require.NoError(t, err)
	assert.True(t, status.ThresholdBreached)
	assert.Len(t, status.BlockedBy, 2)

	// require_triage project: only the triaged watcher finding blocks.
	pr.getBySlugFn = func(ctx context.Context, slug string) (port.Project, error) {
		p := makeProject(true)
		p.CveWatcherGate = "require_triage"
		return p, nil
	}
	status, err = uc.GetGateStatus(context.Background(), "my-app", 3)
	require.NoError(t, err)
	assert.True(t, status.ThresholdBreached)
	assert.Equal(t, []string{"w2"}, status.BlockedBy)
}

// TestGetGateStatus_WatcherOffDropsAll asserts 'off' admits no watcher
// findings: an untriaged and a triaged cve_watcher finding both pass.
func TestGetGateStatus_WatcherOffDropsAll(t *testing.T) {
	pr := &mockProjectRepo{}
	fr := &mockFindingRepo{}
	wr := &mockWaiverRepo{}

	pr.getBySlugFn = func(ctx context.Context, slug string) (port.Project, error) {
		p := makeProject(true)
		p.CveWatcherGate = "off"
		return p, nil
	}
	fr.listGateCandidatesFn = func(ctx context.Context, projectID string, minSeverityRank int16) ([]port.GateCandidate, error) {
		return []port.GateCandidate{
			{Finding: port.Finding{ID: "w1", FindingKind: "cve_watcher", CurrentSeverityRank: 4, AnalysisState: ""}},
			{Finding: port.Finding{ID: "w2", FindingKind: "cve_watcher", CurrentSeverityRank: 4, AnalysisState: "exploitable"}},
		}, nil
	}
	uc := New(Deps{
		Stores: &port.Stores{Projects: pr, Findings: fr, Waivers: wr},
	})

	status, err := uc.GetGateStatus(context.Background(), "my-app", 3)
	require.NoError(t, err)
	assert.False(t, status.ThresholdBreached)
	assert.Empty(t, status.BlockedBy)
}

// TestIngestUnknownScan_CannotCloseUnseenFinding is the no-auto-fix
// regression: an unknown-completeness scan of a new fingerprint must leave
// the finding open/unanalyzed — no fixed-state write and no silent expiry
// path may close an unseen finding. (The auto-fix writer does not exist;
// SQL has no state='fixed' update, and upsert reopens on reappearance.)
func TestIngestUnknownScan_CannotCloseUnseenFinding(t *testing.T) {
	pr, rr, fr := makeTestRepos()
	wr := &mockWaiverRepo{}

	pr.getBySlugFn = func(ctx context.Context, slug string) (port.Project, error) {
		return makeProject(true), nil
	}
	rr.createFn = func(ctx context.Context, arg port.CreateReportInput) (port.Report, error) {
		assert.Equal(t, "unknown", arg.ScanCompleteness, "report completeness must default to unknown")
		return makeReport(), nil
	}
	rr.updateStatusFn = func(ctx context.Context, id, projectID string, status string, totalFindings int32, errorMsg *string) (port.Report, error) {
		return makeReport(), nil
	}
	// No existing finding: the fingerprint is unseen.
	fr.getByFingerprintFn = func(ctx context.Context, projectID, findingKind, fingerprint string) (port.Finding, error) {
		return port.Finding{}, port.ErrNotFound
	}
	var upsertedSeverity string
	fr.upsertFn = func(ctx context.Context, projectID, findingKind, fingerprint, title, severity string, severityRank int16, score float64, firstSeen, lastSeen time.Time) (port.Finding, error) {
		upsertedSeverity = severity
		return port.Finding{
			ID: "find-1", ProjectID: projectID, FindingKind: findingKind,
			Fingerprint: fingerprint, CurrentTitle: title, CurrentSeverity: severity,
			CurrentSeverityRank: severityRank, State: "open", AnalysisState: "unanalyzed",
			GateEffect: "block", FirstSeenAt: firstSeen, LastSeenAt: lastSeen,
		}, nil
	}
	fr.createOccurrenceFn = func(ctx context.Context, arg port.OccurrenceInput) (port.Occurrence, error) {
		return port.Occurrence{ID: "occ-1", FindingID: arg.FindingID}, nil
	}
	fr.upsertDimensionFn = func(ctx context.Context, arg port.DimensionInput) error { return nil }
	fr.listGateCandidatesFn = func(ctx context.Context, projectID string, minSeverityRank int16) ([]port.GateCandidate, error) {
		return nil, nil
	}

	reg := scanner.NewRegistry()
	_ = reg.Register(&mockScanner{
		name: "trivy",
		parseFn: func(ctx context.Context, input []byte) (*domain.NormalizedReport, error) {
			return &domain.NormalizedReport{
				ScanType:     domain.ScanTypeImage,
				Completeness: domain.CompletenessUnknown,
				Target:       &domain.TargetInfo{Kind: "container", Identifier: "img:latest"},
				Findings:     []domain.NormalizedFinding{{Fingerprint: "fp-new", FindingKind: "sca", Title: "CVE-new", Severity: domain.SeverityHigh}},
				ScanScope:    &domain.ScanScope{},
			}, nil
		},
	})

	uc := New(Deps{
		Stores: &port.Stores{
			Projects: pr, Reports: rr, Findings: fr, Waivers: wr,
			Targets: stubTargetRepo(), Artifacts: stubArtifactRepo(),
			Environments: &mockEnvironmentRepo{},
		},
		Registry: reg,
	})

	out, err := uc.IngestReport(context.Background(), IngestReportInput{
		ProjectSlug: "my-app",
		Scanner:     "trivy",
		RawData:     json.RawMessage(`{"test": true}`),
	})
	require.NoError(t, err)
	assert.Equal(t, 1, out.TotalFindings)
	assert.Equal(t, "high", upsertedSeverity, "fresh unknown-scan finding upserts as open/high, never fixed")
	// No update-analysis call may have fired (no fixed write, no expiry).
}
