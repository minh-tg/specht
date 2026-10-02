package server

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/golang-jwt/jwt/v5"
	"github.com/minh-tg/specht/internal/auth"
	"github.com/minh-tg/specht/internal/notify"
	"github.com/minh-tg/specht/internal/patch"
	"github.com/minh-tg/specht/internal/port"
	"github.com/minh-tg/specht/internal/usecase"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type mockUsecases struct {
	createProjectFn      func(ctx context.Context, name, slug, description, creatorID string) (*usecase.ProjectResponse, error)
	listProjectMembersFn func(ctx context.Context, projectSlug string) ([]usecase.ProjectMemberResponse, error)
	addProjectMemberFn   func(ctx context.Context, projectSlug, userID, role string) (*usecase.ProjectMemberResponse, error)
	isProjectMemberFn    func(ctx context.Context, projectID, userID string) (bool, error)
	listProjectsFn       func(ctx context.Context) ([]usecase.ProjectResponse, error)
	getProjectFn         func(ctx context.Context, slug string) (*usecase.ProjectResponse, error)
	updateProjectFn      func(ctx context.Context, slug string, name, description *string) (*usecase.ProjectResponse, error)
	deleteProjectFn      func(ctx context.Context, slug string) (*usecase.ProjectResponse, error)
	listFindingsFn       func(ctx context.Context, projectSlug string, filter usecase.FindingFilter, limit, offset int32) ([]usecase.FindingResponse, int64, error)
	listReportsFn        func(ctx context.Context, projectSlug string, limit, offset int32) ([]usecase.ReportResponse, error)
	getReportFn          func(ctx context.Context, reportID string) (*usecase.ReportResponse, error)
	ingestReportFn       func(ctx context.Context, input usecase.IngestReportInput) (*usecase.IngestReportOutput, error)
	registerFn           func(ctx context.Context, email, password string) (*usecase.AuthResponse, error)
	loginFn              func(ctx context.Context, email, password string) (*usecase.AuthResponse, error)
	createAPIKeyFn       func(ctx context.Context, projectSlug, name string, expiresAt *time.Time) (*usecase.APIKeyResponse, error)
	listAPIKeysFn        func(ctx context.Context, projectSlug string) ([]usecase.APIKeyResponse, error)
	revokeAPIKeyFn       func(ctx context.Context, projectSlug, keyID string) error
	triageFindingFn      func(ctx context.Context, input usecase.TriageInput) (*usecase.TriageOutput, error)
	bulkTriageFn         func(ctx context.Context, input usecase.BulkTriageInput) ([]usecase.TriageOutput, error)
	getGateStatusFn      func(ctx context.Context, slug string, minRank int16) (*usecase.GateStatusOutput, error)
	getIntroducedGateFn  func(ctx context.Context, slug string, minRank int16, reportID string) (*usecase.GateStatusOutput, error)
	previewPRCheckFn     func(ctx context.Context, input usecase.PRCheckPreviewInput) (*usecase.PRCheckPreview, error)
	previewPatchFn       func(ctx context.Context, findingID string) (*patch.Outcome, error)
	previewNotifyFn      func(ctx context.Context, findingID, channel, target string, alreadyLinked bool) (*notify.Outcome, error)
	adminStatusFn        func(ctx context.Context) (*usecase.AdminStatus, error)
	previewRetentionFn   func(ctx context.Context, olderThanDays int) (*usecase.RetentionPreview, error)
	purgeRetentionFn     func(ctx context.Context, olderThanDays int) (*usecase.RetentionResult, error)
	createPolicyFn       func(ctx context.Context, name, description string, definition json.RawMessage) (*usecase.PolicyTemplateResponse, error)
	listPoliciesFn       func(ctx context.Context) ([]usecase.PolicyTemplateResponse, error)
	updatePolicyFn       func(ctx context.Context, id, name, description string, definition json.RawMessage) (*usecase.PolicyTemplateResponse, error)
	deletePolicyFn       func(ctx context.Context, id string) error
	setProjectPolicyFn   func(ctx context.Context, projectSlug, templateName string) (*usecase.PolicyEffectiveResponse, error)
	setPolicyOverridesFn func(ctx context.Context, projectSlug string, overrides map[string]string) (*usecase.PolicyEffectiveResponse, error)
	effectivePolicyFn    func(ctx context.Context, projectSlug string) (*usecase.PolicyEffectiveResponse, error)
	createTeamFn         func(ctx context.Context, name, description string) (*usecase.TeamResponse, error)
	listTeamsFn          func(ctx context.Context) ([]usecase.TeamResponse, error)
	deleteTeamFn         func(ctx context.Context, teamID string) error
	addTeamMemberFn      func(ctx context.Context, teamID, userID, role string) (*usecase.TeamMemberResponse, error)
	listTeamMembersFn    func(ctx context.Context, teamID string) ([]usecase.TeamMemberResponse, error)
	removeTeamMemberFn   func(ctx context.Context, teamID, userID string) error
	linkProjectTeamFn    func(ctx context.Context, projectSlug, teamID, role string) (*usecase.ProjectTeamResponse, error)
	unlinkProjectTeamFn  func(ctx context.Context, projectSlug, teamID string) error
	listProjectTeamsFn   func(ctx context.Context, projectSlug string) ([]usecase.ProjectTeamResponse, error)
	getFindingFn         func(ctx context.Context, findingID string) (*usecase.FindingResponse, error)
	getFindingEventsFn   func(ctx context.Context, findingID string, eventTypes []string, limit, offset int32) ([]usecase.FindingEvent, error)
	refreshFn            func(ctx context.Context, refreshToken string) (*usecase.AuthResponse, error)
	logoutFn             func(ctx context.Context, refreshToken string) error
	getProfileFn         func(ctx context.Context, userID string) (*usecase.UserProfile, error)
	updateProfileFn      func(ctx context.Context, userID string, displayName *string) (*usecase.UserProfile, error)
	listUsersFn          func(ctx context.Context, filter string, limit, offset int32) ([]usecase.UserProfile, error)
	listEnvironmentsFn   func(ctx context.Context, slug string) ([]usecase.EnvironmentResponse, error)
	listTargetsFn        func(ctx context.Context, slug string) ([]usecase.TargetResponse, error)
	listArtifactsFn      func(ctx context.Context, slug string) ([]usecase.ArtifactResponse, error)
	createWaiverFn       func(ctx context.Context, input usecase.CreateWaiverInput) (*usecase.WaiverResponse, error)
	listWaiversFn        func(ctx context.Context, projectSlug string) ([]usecase.WaiverResponse, error)
	getWaiverFn          func(ctx context.Context, projectSlug, waiverID string) (*usecase.WaiverDetailResponse, error)
	updateWaiverFn       func(ctx context.Context, input usecase.UpdateWaiverInput) (*usecase.WaiverResponse, error)
	deleteWaiverFn       func(ctx context.Context, projectSlug, waiverID string) error
	toggleWaiverFn       func(ctx context.Context, projectSlug, waiverID, actorID string) (*usecase.WaiverResponse, error)
	listWaiverEventsFn   func(ctx context.Context, projectSlug, waiverID string) ([]usecase.WaiverEventResp, error)
	checkWaiverMatchFn   func(ctx context.Context, projectSlug, findingID string) (bool, error)
	getProjectStatsFn    func(ctx context.Context, projectSlug string) (*usecase.ProjectStats, error)
	verifyFixFn          func(ctx context.Context, findingID string) (*usecase.VerifyResponse, error)
	getAgingFn           func(ctx context.Context, projectSlug string) (*usecase.AgingResponse, error)
	getWatcherStatusFn   func(ctx context.Context) (*usecase.WatcherStatusResponse, error)
	listScannersFn       func() []usecase.ScannerDescriptorResponse
	createEvidenceFn     func(ctx context.Context, findingID, userID, typ, url, description string) (usecase.EvidenceResponse, error)
	listEvidenceFn       func(ctx context.Context, findingID string) ([]usecase.EvidenceResponse, error)
	deleteEvidenceFn     func(ctx context.Context, evidenceID string) error
	upsertReachabilityFn func(ctx context.Context, findingID, userID, state, evidence string) (*usecase.ReachabilityResponse, error)
	listReachabilityFn   func(ctx context.Context, findingID string) ([]usecase.ReachabilityResponse, error)
	upsertSignoffFn      func(ctx context.Context, findingID, userID, status, comment string) (*usecase.SignoffResponse, error)
	getSignoffFn         func(ctx context.Context, findingID string) (*usecase.SignoffResponse, error)
}

func (m *mockUsecases) CreateProject(ctx context.Context, name, slug, description, creatorID string) (*usecase.ProjectResponse, error) {
	if m.createProjectFn == nil {
		return nil, fmt.Errorf("unexpected call to CreateProject")
	}
	return m.createProjectFn(ctx, name, slug, description, creatorID)
}

func (m *mockUsecases) ListProjectMembers(ctx context.Context, projectSlug string) ([]usecase.ProjectMemberResponse, error) {
	if m.listProjectMembersFn == nil {
		return nil, fmt.Errorf("unexpected call to ListProjectMembers")
	}
	return m.listProjectMembersFn(ctx, projectSlug)
}

func (m *mockUsecases) AddProjectMember(ctx context.Context, projectSlug, userID, role string) (*usecase.ProjectMemberResponse, error) {
	if m.addProjectMemberFn == nil {
		return nil, fmt.Errorf("unexpected call to AddProjectMember")
	}
	return m.addProjectMemberFn(ctx, projectSlug, userID, role)
}

func (m *mockUsecases) IsProjectMember(ctx context.Context, projectID, userID string) (bool, error) {
	if m.isProjectMemberFn == nil {
		return false, fmt.Errorf("unexpected call to IsProjectMember")
	}
	return m.isProjectMemberFn(ctx, projectID, userID)
}

func (m *mockUsecases) ListProjects(ctx context.Context) ([]usecase.ProjectResponse, error) {
	if m.listProjectsFn == nil {
		return nil, fmt.Errorf("unexpected call to ListProjects")
	}
	return m.listProjectsFn(ctx)
}

func (m *mockUsecases) GetProject(ctx context.Context, slug string) (*usecase.ProjectResponse, error) {
	if m.getProjectFn == nil {
		return &usecase.ProjectResponse{ID: "00000000-0000-0000-0000-000000000001", Slug: slug, Name: slug}, nil
	}
	return m.getProjectFn(ctx, slug)
}

func (m *mockUsecases) UpdateProject(ctx context.Context, slug string, name, description *string) (*usecase.ProjectResponse, error) {
	if m.updateProjectFn == nil {
		return nil, fmt.Errorf("unexpected call to UpdateProject")
	}
	return m.updateProjectFn(ctx, slug, name, description)
}

func (m *mockUsecases) DeleteProject(ctx context.Context, slug string) (*usecase.ProjectResponse, error) {
	if m.deleteProjectFn == nil {
		return nil, fmt.Errorf("unexpected call to DeleteProject")
	}
	return m.deleteProjectFn(ctx, slug)
}

func (m *mockUsecases) ListFindings(ctx context.Context, projectSlug string, filter usecase.FindingFilter, limit, offset int32) ([]usecase.FindingResponse, int64, error) {
	if m.listFindingsFn == nil {
		return nil, 0, fmt.Errorf("unexpected call to ListFindings")
	}
	return m.listFindingsFn(ctx, projectSlug, filter, limit, offset)
}

func (m *mockUsecases) GetFinding(ctx context.Context, findingID string) (*usecase.FindingResponse, error) {
	if m.getFindingFn == nil {
		return nil, fmt.Errorf("unexpected call to GetFinding")
	}
	return m.getFindingFn(ctx, findingID)
}

func (m *mockUsecases) ListReports(ctx context.Context, projectSlug string, limit, offset int32) ([]usecase.ReportResponse, error) {
	if m.listReportsFn == nil {
		return nil, fmt.Errorf("unexpected call to ListReports")
	}
	return m.listReportsFn(ctx, projectSlug, limit, offset)
}

func (m *mockUsecases) GetReport(ctx context.Context, reportID string) (*usecase.ReportResponse, error) {
	if m.getReportFn == nil {
		return nil, fmt.Errorf("unexpected call to GetReport")
	}
	return m.getReportFn(ctx, reportID)
}

func (m *mockUsecases) IngestReport(ctx context.Context, input usecase.IngestReportInput) (*usecase.IngestReportOutput, error) {
	if m.ingestReportFn == nil {
		return nil, fmt.Errorf("unexpected call to IngestReport")
	}
	return m.ingestReportFn(ctx, input)
}

func (m *mockUsecases) Register(ctx context.Context, email, password string) (*usecase.AuthResponse, error) {
	if m.registerFn == nil {
		return nil, fmt.Errorf("unexpected call to Register")
	}
	return m.registerFn(ctx, email, password)
}

func (m *mockUsecases) Login(ctx context.Context, email, password string) (*usecase.AuthResponse, error) {
	if m.loginFn == nil {
		return nil, fmt.Errorf("unexpected call to Login")
	}
	return m.loginFn(ctx, email, password)
}

func (m *mockUsecases) FindOrProvisionSSOUser(ctx context.Context, sub, email string, groups []string, allowedDomains []string, adminGroups []string) (string, string, bool, error) {
	return "", "", false, fmt.Errorf("unexpected call to FindOrProvisionSSOUser")
}

func (m *mockUsecases) CreateAPIKey(ctx context.Context, projectSlug, name, createdBy string, expiresAt *time.Time) (*usecase.APIKeyResponse, error) {
	if m.createAPIKeyFn == nil {
		return nil, fmt.Errorf("unexpected call to CreateAPIKey")
	}
	return m.createAPIKeyFn(ctx, projectSlug, name, expiresAt)
}

func (m *mockUsecases) ListAPIKeys(ctx context.Context, projectSlug string) ([]usecase.APIKeyResponse, error) {
	if m.listAPIKeysFn == nil {
		return nil, fmt.Errorf("unexpected call to ListAPIKeys")
	}
	return m.listAPIKeysFn(ctx, projectSlug)
}

func (m *mockUsecases) RevokeAPIKey(ctx context.Context, projectSlug, keyID string) error {
	if m.revokeAPIKeyFn == nil {
		return fmt.Errorf("unexpected call to RevokeAPIKey")
	}
	return m.revokeAPIKeyFn(ctx, projectSlug, keyID)
}

func (m *mockUsecases) TriageFinding(ctx context.Context, input usecase.TriageInput) (*usecase.TriageOutput, error) {
	if m.triageFindingFn == nil {
		return nil, fmt.Errorf("unexpected call to TriageFinding")
	}
	return m.triageFindingFn(ctx, input)
}

func (m *mockUsecases) VerifyFix(ctx context.Context, findingID string) (*usecase.VerifyResponse, error) {
	if m.verifyFixFn == nil {
		return nil, fmt.Errorf("unexpected call to VerifyFix")
	}
	return m.verifyFixFn(ctx, findingID)
}

func (m *mockUsecases) BulkTriage(ctx context.Context, input usecase.BulkTriageInput) ([]usecase.TriageOutput, error) {
	if m.bulkTriageFn == nil {
		return nil, fmt.Errorf("unexpected call to BulkTriage")
	}
	return m.bulkTriageFn(ctx, input)
}

func (m *mockUsecases) GetGateStatus(ctx context.Context, slug string, minRank int16) (*usecase.GateStatusOutput, error) {
	if m.getGateStatusFn == nil {
		return nil, fmt.Errorf("unexpected call to GetGateStatus")
	}
	return m.getGateStatusFn(ctx, slug, minRank)
}

func (m *mockUsecases) GetIntroducedGateStatus(ctx context.Context, slug string, minRank int16, reportID string) (*usecase.GateStatusOutput, error) {
	if m.getIntroducedGateFn == nil {
		return nil, fmt.Errorf("unexpected call to GetIntroducedGateStatus")
	}
	return m.getIntroducedGateFn(ctx, slug, minRank, reportID)
}

func (m *mockUsecases) PreviewPRCheck(ctx context.Context, input usecase.PRCheckPreviewInput) (*usecase.PRCheckPreview, error) {
	if m.previewPRCheckFn == nil {
		return nil, fmt.Errorf("unexpected call to PreviewPRCheck")
	}
	return m.previewPRCheckFn(ctx, input)
}

func (m *mockUsecases) PreviewPatch(ctx context.Context, findingID string) (*patch.Outcome, error) {
	if m.previewPatchFn == nil {
		return nil, fmt.Errorf("unexpected call to PreviewPatch")
	}
	return m.previewPatchFn(ctx, findingID)
}

func (m *mockUsecases) PreviewNotification(ctx context.Context, findingID, channel, target string, alreadyLinked bool) (*notify.Outcome, error) {
	if m.previewNotifyFn == nil {
		return nil, fmt.Errorf("unexpected call to PreviewNotification")
	}
	return m.previewNotifyFn(ctx, findingID, channel, target, alreadyLinked)
}

func (m *mockUsecases) GetAdminStatus(ctx context.Context) (*usecase.AdminStatus, error) {
	if m.adminStatusFn == nil {
		return nil, fmt.Errorf("unexpected call to GetAdminStatus")
	}
	return m.adminStatusFn(ctx)
}

func (m *mockUsecases) PreviewRetention(ctx context.Context, olderThanDays int) (*usecase.RetentionPreview, error) {
	if m.previewRetentionFn == nil {
		return nil, fmt.Errorf("unexpected call to PreviewRetention")
	}
	return m.previewRetentionFn(ctx, olderThanDays)
}

func (m *mockUsecases) PurgeRetention(ctx context.Context, olderThanDays int) (*usecase.RetentionResult, error) {
	if m.purgeRetentionFn == nil {
		return nil, fmt.Errorf("unexpected call to PurgeRetention")
	}
	return m.purgeRetentionFn(ctx, olderThanDays)
}

func (m *mockUsecases) CreatePolicyTemplate(ctx context.Context, name, description string, definition json.RawMessage) (*usecase.PolicyTemplateResponse, error) {
	if m.createPolicyFn == nil {
		return nil, fmt.Errorf("unexpected call to CreatePolicyTemplate")
	}
	return m.createPolicyFn(ctx, name, description, definition)
}

func (m *mockUsecases) ListPolicyTemplates(ctx context.Context) ([]usecase.PolicyTemplateResponse, error) {
	if m.listPoliciesFn == nil {
		return nil, fmt.Errorf("unexpected call to ListPolicyTemplates")
	}
	return m.listPoliciesFn(ctx)
}

func (m *mockUsecases) UpdatePolicyTemplate(ctx context.Context, id, name, description string, definition json.RawMessage) (*usecase.PolicyTemplateResponse, error) {
	if m.updatePolicyFn == nil {
		return nil, fmt.Errorf("unexpected call to UpdatePolicyTemplate")
	}
	return m.updatePolicyFn(ctx, id, name, description, definition)
}

func (m *mockUsecases) DeletePolicyTemplate(ctx context.Context, id string) error {
	if m.deletePolicyFn == nil {
		return fmt.Errorf("unexpected call to DeletePolicyTemplate")
	}
	return m.deletePolicyFn(ctx, id)
}

func (m *mockUsecases) SetProjectPolicy(ctx context.Context, projectSlug, templateName string) (*usecase.PolicyEffectiveResponse, error) {
	if m.setProjectPolicyFn == nil {
		return nil, fmt.Errorf("unexpected call to SetProjectPolicy")
	}
	return m.setProjectPolicyFn(ctx, projectSlug, templateName)
}

func (m *mockUsecases) SetProjectPolicyOverrides(ctx context.Context, projectSlug string, overrides map[string]string) (*usecase.PolicyEffectiveResponse, error) {
	if m.setPolicyOverridesFn == nil {
		return nil, fmt.Errorf("unexpected call to SetProjectPolicyOverrides")
	}
	return m.setPolicyOverridesFn(ctx, projectSlug, overrides)
}

func (m *mockUsecases) EffectivePolicy(ctx context.Context, projectSlug string) (*usecase.PolicyEffectiveResponse, error) {
	if m.effectivePolicyFn == nil {
		return nil, fmt.Errorf("unexpected call to EffectivePolicy")
	}
	return m.effectivePolicyFn(ctx, projectSlug)
}

func (m *mockUsecases) CreateTeam(ctx context.Context, name, description string) (*usecase.TeamResponse, error) {
	if m.createTeamFn == nil {
		return nil, fmt.Errorf("unexpected call to CreateTeam")
	}
	return m.createTeamFn(ctx, name, description)
}

func (m *mockUsecases) ListTeams(ctx context.Context) ([]usecase.TeamResponse, error) {
	if m.listTeamsFn == nil {
		return nil, fmt.Errorf("unexpected call to ListTeams")
	}
	return m.listTeamsFn(ctx)
}

func (m *mockUsecases) DeleteTeam(ctx context.Context, teamID string) error {
	if m.deleteTeamFn == nil {
		return fmt.Errorf("unexpected call to DeleteTeam")
	}
	return m.deleteTeamFn(ctx, teamID)
}

func (m *mockUsecases) AddTeamMember(ctx context.Context, teamID, userID, role string) (*usecase.TeamMemberResponse, error) {
	if m.addTeamMemberFn == nil {
		return nil, fmt.Errorf("unexpected call to AddTeamMember")
	}
	return m.addTeamMemberFn(ctx, teamID, userID, role)
}

func (m *mockUsecases) ListTeamMembers(ctx context.Context, teamID string) ([]usecase.TeamMemberResponse, error) {
	if m.listTeamMembersFn == nil {
		return nil, fmt.Errorf("unexpected call to ListTeamMembers")
	}
	return m.listTeamMembersFn(ctx, teamID)
}

func (m *mockUsecases) RemoveTeamMember(ctx context.Context, teamID, userID string) error {
	if m.removeTeamMemberFn == nil {
		return fmt.Errorf("unexpected call to RemoveTeamMember")
	}
	return m.removeTeamMemberFn(ctx, teamID, userID)
}

func (m *mockUsecases) LinkProjectTeam(ctx context.Context, projectSlug, teamID, role string) (*usecase.ProjectTeamResponse, error) {
	if m.linkProjectTeamFn == nil {
		return nil, fmt.Errorf("unexpected call to LinkProjectTeam")
	}
	return m.linkProjectTeamFn(ctx, projectSlug, teamID, role)
}

func (m *mockUsecases) UnlinkProjectTeam(ctx context.Context, projectSlug, teamID string) error {
	if m.unlinkProjectTeamFn == nil {
		return fmt.Errorf("unexpected call to UnlinkProjectTeam")
	}
	return m.unlinkProjectTeamFn(ctx, projectSlug, teamID)
}

func (m *mockUsecases) ListProjectTeams(ctx context.Context, projectSlug string) ([]usecase.ProjectTeamResponse, error) {
	if m.listProjectTeamsFn == nil {
		return nil, fmt.Errorf("unexpected call to ListProjectTeams")
	}
	return m.listProjectTeamsFn(ctx, projectSlug)
}

func (m *mockUsecases) GetFindingEvents(ctx context.Context, findingID string, eventTypes []string, limit, offset int32) ([]usecase.FindingEvent, error) {
	if m.getFindingEventsFn == nil {
		return nil, nil
	}
	return m.getFindingEventsFn(ctx, findingID, eventTypes, limit, offset)
}

func (m *mockUsecases) Refresh(ctx context.Context, refreshToken string) (*usecase.AuthResponse, error) {
	if m.refreshFn == nil {
		return nil, fmt.Errorf("unexpected call to Refresh")
	}
	return m.refreshFn(ctx, refreshToken)
}

func (m *mockUsecases) Logout(ctx context.Context, refreshToken string) error {
	if m.logoutFn == nil {
		return fmt.Errorf("unexpected call to Logout")
	}
	return m.logoutFn(ctx, refreshToken)
}

func (m *mockUsecases) GetProfile(ctx context.Context, userID string) (*usecase.UserProfile, error) {
	if m.getProfileFn == nil {
		return nil, fmt.Errorf("unexpected call to GetProfile")
	}
	return m.getProfileFn(ctx, userID)
}

func (m *mockUsecases) UpdateProfile(ctx context.Context, userID string, displayName *string) (*usecase.UserProfile, error) {
	if m.updateProfileFn == nil {
		return nil, fmt.Errorf("unexpected call to UpdateProfile")
	}
	return m.updateProfileFn(ctx, userID, displayName)
}

func (m *mockUsecases) ListUsers(ctx context.Context, filter string, limit, offset int32) ([]usecase.UserProfile, error) {
	if m.listUsersFn == nil {
		return nil, fmt.Errorf("unexpected call to ListUsers")
	}
	return m.listUsersFn(ctx, filter, limit, offset)
}

func (m *mockUsecases) ListEnvironments(ctx context.Context, slug string) ([]usecase.EnvironmentResponse, error) {
	if m.listEnvironmentsFn == nil {
		return nil, fmt.Errorf("unexpected call to ListEnvironments")
	}
	return m.listEnvironmentsFn(ctx, slug)
}

func (m *mockUsecases) ListTargets(ctx context.Context, slug string) ([]usecase.TargetResponse, error) {
	if m.listTargetsFn == nil {
		return nil, fmt.Errorf("unexpected call to ListTargets")
	}
	return m.listTargetsFn(ctx, slug)
}

func (m *mockUsecases) ListArtifacts(ctx context.Context, slug string) ([]usecase.ArtifactResponse, error) {
	if m.listArtifactsFn == nil {
		return nil, fmt.Errorf("unexpected call to ListArtifacts")
	}
	return m.listArtifactsFn(ctx, slug)
}

func (m *mockUsecases) CreateWaiver(ctx context.Context, input usecase.CreateWaiverInput) (*usecase.WaiverResponse, error) {
	if m.createWaiverFn == nil {
		return nil, fmt.Errorf("unexpected call to CreateWaiver")
	}
	return m.createWaiverFn(ctx, input)
}

func (m *mockUsecases) ListWaivers(ctx context.Context, projectSlug string) ([]usecase.WaiverResponse, error) {
	if m.listWaiversFn == nil {
		return nil, fmt.Errorf("unexpected call to ListWaivers")
	}
	return m.listWaiversFn(ctx, projectSlug)
}

func (m *mockUsecases) GetWaiver(ctx context.Context, projectSlug, waiverID string) (*usecase.WaiverDetailResponse, error) {
	if m.getWaiverFn == nil {
		return nil, fmt.Errorf("unexpected call to GetWaiver")
	}
	return m.getWaiverFn(ctx, projectSlug, waiverID)
}

func (m *mockUsecases) UpdateWaiver(ctx context.Context, input usecase.UpdateWaiverInput) (*usecase.WaiverResponse, error) {
	if m.updateWaiverFn == nil {
		return nil, fmt.Errorf("unexpected call to UpdateWaiver")
	}
	return m.updateWaiverFn(ctx, input)
}

func (m *mockUsecases) DeleteWaiver(ctx context.Context, projectSlug, waiverID string) error {
	if m.deleteWaiverFn == nil {
		return fmt.Errorf("unexpected call to DeleteWaiver")
	}
	return m.deleteWaiverFn(ctx, projectSlug, waiverID)
}

func (m *mockUsecases) ToggleWaiver(ctx context.Context, projectSlug, waiverID, actorID string) (*usecase.WaiverResponse, error) {
	if m.toggleWaiverFn == nil {
		return nil, fmt.Errorf("unexpected call to ToggleWaiver")
	}
	return m.toggleWaiverFn(ctx, projectSlug, waiverID, actorID)
}

func (m *mockUsecases) ListWaiverEvents(ctx context.Context, projectSlug, waiverID string) ([]usecase.WaiverEventResp, error) {
	if m.listWaiverEventsFn == nil {
		return nil, fmt.Errorf("unexpected call to ListWaiverEvents")
	}
	return m.listWaiverEventsFn(ctx, projectSlug, waiverID)
}

func (m *mockUsecases) CheckWaiverMatch(ctx context.Context, projectSlug, findingID string) (bool, error) {
	if m.checkWaiverMatchFn == nil {
		return false, fmt.Errorf("unexpected call to CheckWaiverMatch")
	}
	return m.checkWaiverMatchFn(ctx, projectSlug, findingID)
}

func (m *mockUsecases) GetProjectStats(ctx context.Context, projectSlug string) (*usecase.ProjectStats, error) {
	if m.getProjectStatsFn == nil {
		return nil, fmt.Errorf("unexpected call to GetProjectStats")
	}
	return m.getProjectStatsFn(ctx, projectSlug)
}

func (m *mockUsecases) GetAging(ctx context.Context, projectSlug string) (*usecase.AgingResponse, error) {
	if m.getAgingFn == nil {
		return nil, fmt.Errorf("unexpected call to GetAging")
	}
	return m.getAgingFn(ctx, projectSlug)
}

func (m *mockUsecases) GetWatcherStatus(ctx context.Context) (*usecase.WatcherStatusResponse, error) {
	if m.getWatcherStatusFn == nil {
		return nil, fmt.Errorf("unexpected call to GetWatcherStatus")
	}
	return m.getWatcherStatusFn(ctx)
}

func (m *mockUsecases) ListScanners() []usecase.ScannerDescriptorResponse {
	if m.listScannersFn == nil {
		return nil
	}
	return m.listScannersFn()
}

func (m *mockUsecases) CreateEvidence(ctx context.Context, findingID, userID, typ, url, description string) (usecase.EvidenceResponse, error) {
	if m.createEvidenceFn == nil {
		return usecase.EvidenceResponse{}, fmt.Errorf("unexpected call to CreateEvidence")
	}
	return m.createEvidenceFn(ctx, findingID, userID, typ, url, description)
}

func (m *mockUsecases) ListEvidence(ctx context.Context, findingID string) ([]usecase.EvidenceResponse, error) {
	if m.listEvidenceFn == nil {
		return nil, fmt.Errorf("unexpected call to ListEvidence")
	}
	return m.listEvidenceFn(ctx, findingID)
}

func (m *mockUsecases) DeleteEvidence(ctx context.Context, evidenceID string) error {
	if m.deleteEvidenceFn == nil {
		return fmt.Errorf("unexpected call to DeleteEvidence")
	}
	return m.deleteEvidenceFn(ctx, evidenceID)
}

func (m *mockUsecases) UpsertReachability(ctx context.Context, findingID, userID, state, evidence string) (*usecase.ReachabilityResponse, error) {
	if m.upsertReachabilityFn == nil {
		return nil, fmt.Errorf("unexpected call to UpsertReachability")
	}
	return m.upsertReachabilityFn(ctx, findingID, userID, state, evidence)
}

func (m *mockUsecases) ListReachability(ctx context.Context, findingID string) ([]usecase.ReachabilityResponse, error) {
	if m.listReachabilityFn == nil {
		return nil, fmt.Errorf("unexpected call to ListReachability")
	}
	return m.listReachabilityFn(ctx, findingID)
}

func (m *mockUsecases) UpsertSignoff(ctx context.Context, findingID, userID, status, comment string) (*usecase.SignoffResponse, error) {
	if m.upsertSignoffFn == nil {
		return nil, fmt.Errorf("unexpected call to UpsertSignoff")
	}
	return m.upsertSignoffFn(ctx, findingID, userID, status, comment)
}

func (m *mockUsecases) GetSignoff(ctx context.Context, findingID string) (*usecase.SignoffResponse, error) {
	if m.getSignoffFn == nil {
		return nil, fmt.Errorf("unexpected call to GetSignoff")
	}
	return m.getSignoffFn(ctx, findingID)
}

var now = time.Date(2026, 6, 30, 12, 0, 0, 0, time.UTC)

func sampleProjects() []usecase.ProjectResponse {
	return []usecase.ProjectResponse{
		{ID: "proj-1", Slug: "my-app", Name: "My App", Description: strPtr("example"), CreatedAt: now, UpdatedAt: now},
	}
}

func sampleFindings() []usecase.FindingResponse {
	return []usecase.FindingResponse{
		{ID: "find-1", ProjectID: "proj-1", FindingKind: "sca", Fingerprint: "fp1", CurrentTitle: "CVE-2026-1234", CurrentSeverity: "high", State: "open", TriageStatus: "untriaged", FirstSeenAt: now, LastSeenAt: now, CreatedAt: now, UpdatedAt: now},
	}
}

func sampleReports() []usecase.ReportResponse {
	return []usecase.ReportResponse{
		{ID: "rep-1", ProjectID: "proj-1", ToolName: "trivy", ScanType: "image", Status: "completed", TotalFindings: int32Ptr(5), CreatedAt: now, CompletedAt: &now},
	}
}

func strPtr(s string) *string { return &s }
func int32Ptr(i int32) *int32 { return &i }

func TestHealthHandler(t *testing.T) {
	req := httptest.NewRequest("GET", "/api/v1/health", nil)
	w := httptest.NewRecorder()

	router := NewRouter(RouterConfig{Usecases: nil, JWTAuth: testJWTAuth})
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var body map[string]string
	err := json.Unmarshal(w.Body.Bytes(), &body)
	require.NoError(t, err)
	assert.Equal(t, "ok", body["status"])
}

func TestRespondJSON(t *testing.T) {
	w := httptest.NewRecorder()
	respondJSON(w, http.StatusCreated, map[string]string{"hello": "world"})

	assert.Equal(t, http.StatusCreated, w.Code)
	assert.Equal(t, "application/json", w.Header().Get("Content-Type"))

	var body map[string]string
	err := json.Unmarshal(w.Body.Bytes(), &body)
	require.NoError(t, err)
	assert.Equal(t, "world", body["hello"])
}

func TestRespondError(t *testing.T) {
	w := httptest.NewRecorder()
	respondError(w, http.StatusBadRequest, "missing_field", "project is required")

	assert.Equal(t, http.StatusBadRequest, w.Code)
	var resp struct {
		Error struct {
			Code    string `json:"code"`
			Message string `json:"message"`
		} `json:"error"`
	}
	err := json.Unmarshal(w.Body.Bytes(), &resp)
	require.NoError(t, err)
	assert.Equal(t, "missing_field", resp.Error.Code)
	assert.Equal(t, "project is required", resp.Error.Message)
}

func TestIngestReport_InvalidJSON(t *testing.T) {
	handler := &Handler{}
	body := strings.NewReader(`not json`)
	req := httptest.NewRequest("POST", "/api/v1/reports", body)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	handler.IngestReport(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)

	var resp struct {
		Error struct {
			Code    string `json:"code"`
			Message string `json:"message"`
		} `json:"error"`
	}
	err := json.Unmarshal(w.Body.Bytes(), &resp)
	require.NoError(t, err)
	assert.Equal(t, "invalid_json", resp.Error.Code)
}

func TestIngestReport_MissingFields(t *testing.T) {
	handler := &Handler{}

	tests := []struct {
		name       string
		body       string
		wantStatus int
		wantCode   string
	}{
		{"missing project", `{"scanner":"trivy","raw_data":{}}`, http.StatusBadRequest, "missing_field"},
		{"missing scanner", `{"project":"test","raw_data":{}}`, http.StatusBadRequest, "missing_field"},
		{"missing raw_data", `{"project":"test","scanner":"trivy"}`, http.StatusBadRequest, "missing_field"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest("POST", "/api/v1/reports", strings.NewReader(tt.body))
			req.Header.Set("Content-Type", "application/json")
			w := httptest.NewRecorder()

			handler.IngestReport(w, req)

			assert.Equal(t, tt.wantStatus, w.Code)

			var resp struct {
				Error struct {
					Code    string `json:"code"`
					Message string `json:"message"`
				} `json:"error"`
			}
			err := json.Unmarshal(w.Body.Bytes(), &resp)
			require.NoError(t, err)
			assert.Equal(t, tt.wantCode, resp.Error.Code)
		})
	}
}

func TestIngestReport_Success(t *testing.T) {
	var got usecase.IngestReportInput
	mock := &mockUsecases{
		ingestReportFn: func(ctx context.Context, input usecase.IngestReportInput) (*usecase.IngestReportOutput, error) {
			got = input
			return &usecase.IngestReportOutput{ReportID: "rep-1", TotalFindings: 3, ThresholdBreached: true}, nil
		},
	}
	router := testRouter(mock)
	body := strings.NewReader(`{"project":"my-app","scanner":"trivy","raw_data":{"image":"myapp:latest"},"branch":"main","commit_sha":"abc","environment":"ci","owner":"team-a","digest":"sha256:deadbeef"}`)
	req := httptest.NewRequest("POST", "/api/v1/reports", body)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusCreated, w.Code)
	var resp struct {
		ReportID          string `json:"report_id"`
		TotalFindings     int    `json:"total_findings"`
		ThresholdBreached bool   `json:"threshold_breached"`
	}
	err := json.Unmarshal(w.Body.Bytes(), &resp)
	require.NoError(t, err)
	assert.Equal(t, "rep-1", resp.ReportID)
	assert.Equal(t, 3, resp.TotalFindings)
	assert.True(t, resp.ThresholdBreached)
	assert.Equal(t, "main", got.Branch)
	assert.Equal(t, "abc", got.CommitSha)
	assert.Equal(t, "ci", got.Environment)
	assert.Equal(t, "team-a", got.Owner)
	assert.Equal(t, "sha256:deadbeef", got.Digest)
}

func TestIngestReport_Duplicate(t *testing.T) {
	mock := &mockUsecases{
		ingestReportFn: func(ctx context.Context, input usecase.IngestReportInput) (*usecase.IngestReportOutput, error) {
			return nil, usecase.ErrDuplicateReport
		},
	}
	router := testRouter(mock)
	body := strings.NewReader(`{"project":"my-app","scanner":"trivy","raw_data":{"image":"myapp:latest"}}`)
	req := httptest.NewRequest("POST", "/api/v1/reports", body)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusConflict, w.Code)
	var resp struct {
		Error struct {
			Code string `json:"code"`
		} `json:"error"`
	}
	err := json.Unmarshal(w.Body.Bytes(), &resp)
	require.NoError(t, err)
	assert.Equal(t, "duplicate_report", resp.Error.Code)
}

func testRouter(mock *mockUsecases) http.Handler {
	r := chi.NewRouter()
	h := NewHandler(mock)
	// Real requests reach these handlers through AuthMiddleware, which always
	// attaches an identity. Slug-scoped handlers enforce tenant membership
	// for session users, so the test router mirrors an authorized
	// operator by authenticating every request as a global admin: handler
	// behavior stays under test while access control is covered by dedicated
	// tests (usecase access_test.go, apikey_authz_test.go, and the admin
	// matrix). Admin-gated global endpoints (watcher status, scanners) are
	// intentionally absent: role enforcement for them is covered against
	// NewRouter, where a real admin bearer token can be presented.
	r.Use(func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx := auth.ContextWithIdentity(r.Context(), &auth.Identity{UserID: "test-user", Role: auth.RoleAdmin})
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	})
	r.Get("/api/v1/projects", h.ListProjects)
	r.Post("/api/v1/projects", h.CreateProject)
	r.Get("/api/v1/projects/{slug}", h.GetProject)
	r.Put("/api/v1/projects/{slug}", h.UpdateProject)
	r.Delete("/api/v1/projects/{slug}", h.DeleteProject)
	r.Get("/api/v1/projects/{slug}/findings", h.ListFindings)
	r.Get("/api/v1/projects/{slug}/reports", h.ListReports)
	r.Get("/api/v1/reports/{id}", h.GetReport)
	r.Post("/api/v1/reports", h.IngestReport)
	r.Post("/api/v1/auth/register", h.Register)
	r.Post("/api/v1/auth/login", h.Login)
	r.Post("/api/v1/auth/apikeys", h.CreateAPIKey)
	r.Get("/api/v1/auth/apikeys", h.ListAPIKeys)
	r.Delete("/api/v1/auth/apikeys/{id}", h.RevokeAPIKey)
	r.Patch("/api/v1/findings/{id}", h.TriageFinding)
	r.Post("/api/v1/findings/{id}/verify", h.VerifyFinding)
	r.Get("/api/v1/findings/{id}/patch-preview", h.PreviewPatch)
	r.Get("/api/v1/findings/{id}/notify-preview", h.PreviewNotification)
	r.Get("/api/v1/admin/status", h.GetAdminStatus)
	r.Get("/api/v1/admin/retention/preview", h.PreviewRetention)
	r.Post("/api/v1/admin/retention/purge", h.PurgeRetention)
	r.Get("/api/v1/policy-templates", h.ListPolicyTemplates)
	r.Post("/api/v1/policy-templates", h.CreatePolicyTemplate)
	r.Put("/api/v1/policy-templates/{id}", h.UpdatePolicyTemplate)
	r.Delete("/api/v1/policy-templates/{id}", h.DeletePolicyTemplate)
	r.Put("/api/v1/projects/{slug}/policy", h.SetProjectPolicy)
	r.Put("/api/v1/projects/{slug}/policy/overrides", h.SetProjectPolicyOverrides)
	r.Get("/api/v1/projects/{slug}/policy", h.GetEffectivePolicy)
	r.Get("/api/v1/teams", h.ListTeams)
	r.Post("/api/v1/teams", h.CreateTeam)
	r.Delete("/api/v1/teams/{id}", h.DeleteTeam)
	r.Get("/api/v1/teams/{id}/members", h.ListTeamMembers)
	r.Post("/api/v1/teams/{id}/members", h.AddTeamMember)
	r.Delete("/api/v1/teams/{id}/members/{userID}", h.RemoveTeamMember)
	r.Get("/api/v1/projects/{slug}/teams", h.ListProjectTeams)
	r.Post("/api/v1/projects/{slug}/teams", h.LinkProjectTeam)
	r.Delete("/api/v1/projects/{slug}/teams/{teamID}", h.UnlinkProjectTeam)
	r.Post("/api/v1/findings/bulk-analysis", h.BulkTriage)
	r.Get("/api/v1/findings/{id}/events", h.ListFindingEvents)
	r.Get("/api/v1/findings/{id}", h.GetFinding)
	r.Post("/api/v1/auth/refresh", h.Refresh)
	r.Post("/api/v1/auth/logout", h.Logout)
	r.Get("/api/v1/me", h.Me)
	r.Put("/api/v1/me", h.UpdateMe)
	r.Get("/api/v1/projects/{slug}/gate", h.GetGateStatus)
	r.Get("/api/v1/projects/{slug}/pr-check", h.PreviewPRCheck)
	r.Get("/api/v1/projects/{slug}/stats", h.GetProjectStats)
	r.Get("/api/v1/projects/{slug}/aging", h.GetAging)
	r.Post("/api/v1/projects/{slug}/members", h.AddProjectMember)
	return r
}

func TestListProjects_Success(t *testing.T) {
	mock := &mockUsecases{
		listProjectsFn: func(ctx context.Context) ([]usecase.ProjectResponse, error) {
			return sampleProjects(), nil
		},
	}
	router := testRouter(mock)
	req := httptest.NewRequest("GET", "/api/v1/projects", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	var resp []usecase.ProjectResponse
	err := json.Unmarshal(w.Body.Bytes(), &resp)
	require.NoError(t, err)
	assert.Len(t, resp, 1)
	assert.Equal(t, "my-app", resp[0].Slug)
}

func TestListProjects_Error(t *testing.T) {
	mock := &mockUsecases{
		listProjectsFn: func(ctx context.Context) ([]usecase.ProjectResponse, error) {
			return nil, fmt.Errorf("db error")
		},
	}
	h := &Handler{usecase: mock}
	req := httptest.NewRequest("GET", "/api/v1/projects", nil)
	w := httptest.NewRecorder()
	h.ListProjects(w, req)

	assert.Equal(t, http.StatusInternalServerError, w.Code)
	var resp struct {
		Error struct {
			Code    string `json:"code"`
			Message string `json:"message"`
		} `json:"error"`
	}
	err := json.Unmarshal(w.Body.Bytes(), &resp)
	require.NoError(t, err)
	assert.Equal(t, "internal_error", resp.Error.Code)
}

func TestGetProject_Success(t *testing.T) {
	mock := &mockUsecases{
		getProjectFn: func(ctx context.Context, slug string) (*usecase.ProjectResponse, error) {
			assert.Equal(t, "my-app", slug)
			return &sampleProjects()[0], nil
		},
	}
	router := testRouter(mock)
	req := httptest.NewRequest("GET", "/api/v1/projects/my-app", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	var resp usecase.ProjectResponse
	err := json.Unmarshal(w.Body.Bytes(), &resp)
	require.NoError(t, err)
	assert.Equal(t, "my-app", resp.Slug)
}

func TestGetProject_NotFound(t *testing.T) {
	mock := &mockUsecases{
		getProjectFn: func(ctx context.Context, slug string) (*usecase.ProjectResponse, error) {
			return nil, fmt.Errorf("not found")
		},
	}
	router := testRouter(mock)
	req := httptest.NewRequest("GET", "/api/v1/projects/nonexistent", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusNotFound, w.Code)
}

func TestCreateProject_Success(t *testing.T) {
	mock := &mockUsecases{
		createProjectFn: func(ctx context.Context, name, slug, description, creatorID string) (*usecase.ProjectResponse, error) {
			return &usecase.ProjectResponse{
				ID:   "proj-1",
				Slug: slug,
				Name: name,
			}, nil
		},
	}
	router := testRouter(mock)
	body := `{"name":"My App","slug":"my-app","description":"test"}`
	req := httptest.NewRequest("POST", "/api/v1/projects", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusCreated, w.Code)
	var resp usecase.ProjectResponse
	err := json.Unmarshal(w.Body.Bytes(), &resp)
	require.NoError(t, err)
	assert.Equal(t, "my-app", resp.Slug)
	assert.Equal(t, "My App", resp.Name)
}

func TestCreateProject_MissingFields(t *testing.T) {
	mock := &mockUsecases{}
	h := &Handler{usecase: mock}
	req := httptest.NewRequest("POST", "/api/v1/projects", strings.NewReader(`{"slug":"my-app"}`))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h.CreateProject(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestUpdateProject_Success(t *testing.T) {
	mock := &mockUsecases{
		updateProjectFn: func(ctx context.Context, slug string, name, description *string) (*usecase.ProjectResponse, error) {
			assert.Equal(t, "my-app", slug)
			require.NotNil(t, name)
			return &usecase.ProjectResponse{ID: "p1", Slug: slug, Name: *name}, nil
		},
	}
	router := testRouter(mock)
	req := httptest.NewRequest("PUT", "/api/v1/projects/my-app", strings.NewReader(`{"name":"Renamed"}`))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	var resp usecase.ProjectResponse
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.Equal(t, "Renamed", resp.Name)
}

func TestUpdateProject_MissingFields(t *testing.T) {
	mock := &mockUsecases{}
	h := &Handler{usecase: mock}
	req := httptest.NewRequest("PUT", "/api/v1/projects/my-app", strings.NewReader(`{}`))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h.UpdateProject(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestUpdateProject_Denied(t *testing.T) {
	mock := &mockUsecases{
		updateProjectFn: func(ctx context.Context, slug string, name, description *string) (*usecase.ProjectResponse, error) {
			return nil, usecase.ErrProjectAccessDenied
		},
	}
	router := testRouter(mock)
	req := httptest.NewRequest("PUT", "/api/v1/projects/my-app", strings.NewReader(`{"name":"Renamed"}`))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusForbidden, w.Code)
}

func TestUpdateProject_NotFound(t *testing.T) {
	mock := &mockUsecases{
		updateProjectFn: func(ctx context.Context, slug string, name, description *string) (*usecase.ProjectResponse, error) {
			return nil, fmt.Errorf("project not found: missing")
		},
	}
	router := testRouter(mock)
	req := httptest.NewRequest("PUT", "/api/v1/projects/missing", strings.NewReader(`{"name":"Renamed"}`))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusNotFound, w.Code)
}

func TestDeleteProject_Success(t *testing.T) {
	mock := &mockUsecases{
		deleteProjectFn: func(ctx context.Context, slug string) (*usecase.ProjectResponse, error) {
			assert.Equal(t, "my-app", slug)
			return &usecase.ProjectResponse{ID: "p1", Slug: slug, Name: "My App"}, nil
		},
	}
	router := testRouter(mock)
	req := httptest.NewRequest("DELETE", "/api/v1/projects/my-app", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	var resp usecase.ProjectResponse
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.Equal(t, "my-app", resp.Slug)
}

func TestDeleteProject_Denied(t *testing.T) {
	mock := &mockUsecases{
		deleteProjectFn: func(ctx context.Context, slug string) (*usecase.ProjectResponse, error) {
			return nil, usecase.ErrProjectAccessDenied
		},
	}
	router := testRouter(mock)
	req := httptest.NewRequest("DELETE", "/api/v1/projects/my-app", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusForbidden, w.Code)
}

func TestDeleteProject_NotFound(t *testing.T) {
	mock := &mockUsecases{
		deleteProjectFn: func(ctx context.Context, slug string) (*usecase.ProjectResponse, error) {
			return nil, fmt.Errorf("project not found: missing")
		},
	}
	router := testRouter(mock)
	req := httptest.NewRequest("DELETE", "/api/v1/projects/missing", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusNotFound, w.Code)
}

func TestListFindings_Success(t *testing.T) {
	mock := &mockUsecases{
		listFindingsFn: func(ctx context.Context, projectSlug string, filter usecase.FindingFilter, limit, offset int32) ([]usecase.FindingResponse, int64, error) {
			assert.Equal(t, "my-app", projectSlug)
			assert.Equal(t, int32(20), limit)
			assert.Equal(t, int32(0), offset)
			return sampleFindings(), 4242, nil
		},
	}
	router := testRouter(mock)
	req := httptest.NewRequest("GET", "/api/v1/projects/my-app/findings", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, "4242", w.Header().Get("X-Total-Count"),
		"the filtered total rides a header so the body stays a bare array")
	var resp []usecase.FindingResponse
	err := json.Unmarshal(w.Body.Bytes(), &resp)
	require.NoError(t, err)
	assert.Len(t, resp, 1)
	assert.Equal(t, "sca", resp[0].FindingKind)
}

func TestListFindings_WithFilters(t *testing.T) {
	mock := &mockUsecases{
		listFindingsFn: func(ctx context.Context, projectSlug string, filter usecase.FindingFilter, limit, offset int32) ([]usecase.FindingResponse, int64, error) {
			assert.Equal(t, []string{"high", "critical"}, filter.Severities)
			assert.Equal(t, []string{"open"}, filter.States)
			assert.Equal(t, []string{"production"}, filter.Environments)
			assert.Equal(t, []string{"web"}, filter.Targets)
			assert.Equal(t, int32(50), limit)
			assert.Equal(t, int32(1000), offset)
			return sampleFindings(), int64(len(sampleFindings())), nil
		},
	}
	router := testRouter(mock)
	req := httptest.NewRequest("GET", "/api/v1/projects/my-app/findings?severity=high,critical&status=open&environment=production&target=web&limit=50&offset=1000", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
}

func TestListFindings_NotFound(t *testing.T) {
	mock := &mockUsecases{
		listFindingsFn: func(ctx context.Context, projectSlug string, filter usecase.FindingFilter, limit, offset int32) ([]usecase.FindingResponse, int64, error) {
			return nil, 0, port.ErrNotFound
		},
	}
	router := testRouter(mock)
	req := httptest.NewRequest("GET", "/api/v1/projects/nonexistent/findings", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusNotFound, w.Code)
}

func TestListFindings_InternalError(t *testing.T) {
	mock := &mockUsecases{
		listFindingsFn: func(ctx context.Context, projectSlug string, filter usecase.FindingFilter, limit, offset int32) ([]usecase.FindingResponse, int64, error) {
			return nil, 0, fmt.Errorf("database unavailable")
		},
	}
	router := testRouter(mock)
	req := httptest.NewRequest("GET", "/api/v1/projects/my-app/findings", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusInternalServerError, w.Code)
}

func TestListReports_Success(t *testing.T) {
	mock := &mockUsecases{
		listReportsFn: func(ctx context.Context, projectSlug string, limit, offset int32) ([]usecase.ReportResponse, error) {
			assert.Equal(t, "my-app", projectSlug)
			assert.Equal(t, int32(20), limit)
			assert.Equal(t, int32(0), offset)
			return sampleReports(), nil
		},
	}
	router := testRouter(mock)
	req := httptest.NewRequest("GET", "/api/v1/projects/my-app/reports", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	var resp []usecase.ReportResponse
	err := json.Unmarshal(w.Body.Bytes(), &resp)
	require.NoError(t, err)
	assert.Len(t, resp, 1)
	assert.Equal(t, "trivy", resp[0].ToolName)
}

func TestListReports_NotFound(t *testing.T) {
	mock := &mockUsecases{
		listReportsFn: func(ctx context.Context, projectSlug string, limit, offset int32) ([]usecase.ReportResponse, error) {
			return nil, port.ErrNotFound
		},
	}
	router := testRouter(mock)
	req := httptest.NewRequest("GET", "/api/v1/projects/nonexistent/reports", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusNotFound, w.Code)
}

func TestListReports_InternalError(t *testing.T) {
	mock := &mockUsecases{
		listReportsFn: func(ctx context.Context, projectSlug string, limit, offset int32) ([]usecase.ReportResponse, error) {
			return nil, fmt.Errorf("database unavailable")
		},
	}
	router := testRouter(mock)
	req := httptest.NewRequest("GET", "/api/v1/projects/my-app/reports", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusInternalServerError, w.Code)
}

func TestGetReport_Success(t *testing.T) {
	mock := &mockUsecases{
		getReportFn: func(ctx context.Context, id string) (*usecase.ReportResponse, error) {
			return &sampleReports()[0], nil
		},
	}
	router := testRouter(mock)
	req := httptest.NewRequest("GET", "/api/v1/reports/550e8400-e29b-41d4-a716-446655440000", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	var resp usecase.ReportResponse
	err := json.Unmarshal(w.Body.Bytes(), &resp)
	require.NoError(t, err)
	assert.Equal(t, "trivy", resp.ToolName)
}

func TestGetReport_NotFound(t *testing.T) {
	mock := &mockUsecases{
		getReportFn: func(ctx context.Context, id string) (*usecase.ReportResponse, error) {
			return nil, fmt.Errorf("not found")
		},
	}
	router := testRouter(mock)
	req := httptest.NewRequest("GET", "/api/v1/reports/550e8400-e29b-41d4-a716-446655440000", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusNotFound, w.Code)
}

func TestGetReport_InvalidID(t *testing.T) {
	router := testRouter(nil)
	req := httptest.NewRequest("GET", "/api/v1/reports/not-a-uuid", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
	var resp struct {
		Error struct {
			Code string `json:"code"`
		} `json:"error"`
	}
	err := json.Unmarshal(w.Body.Bytes(), &resp)
	require.NoError(t, err)
	assert.Equal(t, "invalid_id", resp.Error.Code)
}

var corsMock = &mockUsecases{}

const testJWTSecret = "test-secret-not-for-production-use"

var testJWTAuth = func() *auth.JWTAuthenticator {
	a, err := auth.NewJWTAuthenticator(testJWTSecret)
	if err != nil {
		panic(err)
	}
	return a
}()

func testToken(t *testing.T) string {
	t.Helper()
	a, err := auth.NewJWTAuthenticator(testJWTSecret)
	require.NoError(t, err)
	tok, err := a.CreateToken("test-user", "test@example.com", auth.RoleAdmin)
	require.NoError(t, err)
	return tok
}

func makeTestToken(t *testing.T, role string) string {
	t.Helper()
	a, err := auth.NewJWTAuthenticator(testJWTSecret)
	require.NoError(t, err)
	tok, err := a.CreateToken("test-user", "test@example.com", role)
	require.NoError(t, err)
	return tok
}

func TestCORS_DefaultOrigin(t *testing.T) {
	router := NewRouter(RouterConfig{Usecases: corsMock, CORSOrigins: "", JWTAuth: testJWTAuth})
	req := httptest.NewRequest("OPTIONS", "/api/v1/health", nil)
	req.Header.Set("Origin", "http://localhost:5173")
	req.Header.Set("Access-Control-Request-Method", "GET")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, "http://localhost:5173", w.Header().Get("Access-Control-Allow-Origin"))
	assert.NotEmpty(t, w.Header().Get("Access-Control-Allow-Methods"))
}

func TestCORS_CustomOrigins(t *testing.T) {
	router := NewRouter(RouterConfig{Usecases: corsMock, CORSOrigins: "https://app.example.com,https://admin.example.com", JWTAuth: testJWTAuth})
	req := httptest.NewRequest("OPTIONS", "/api/v1/health", nil)
	req.Header.Set("Origin", "https://app.example.com")
	req.Header.Set("Access-Control-Request-Method", "GET")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, "https://app.example.com", w.Header().Get("Access-Control-Allow-Origin"))
}

func TestCORS_DisallowedOrigin(t *testing.T) {
	router := NewRouter(RouterConfig{Usecases: corsMock, CORSOrigins: "http://localhost:5173", JWTAuth: testJWTAuth})
	req := httptest.NewRequest("OPTIONS", "/api/v1/health", nil)
	req.Header.Set("Origin", "https://evil.com")
	req.Header.Set("Access-Control-Request-Method", "GET")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Empty(t, w.Header().Get("Access-Control-Allow-Origin"))
}

func TestCORS_HeadersOnGET(t *testing.T) {
	router := NewRouter(RouterConfig{Usecases: corsMock, CORSOrigins: "", JWTAuth: testJWTAuth})
	req := httptest.NewRequest("GET", "/api/v1/health", nil)
	req.Header.Set("Origin", "http://localhost:5173")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, "http://localhost:5173", w.Header().Get("Access-Control-Allow-Origin"))
}

func TestNewRouterRoutes(t *testing.T) {
	mock := &mockUsecases{
		listProjectsFn: func(ctx context.Context) ([]usecase.ProjectResponse, error) { return nil, nil },
		getProjectFn: func(ctx context.Context, slug string) (*usecase.ProjectResponse, error) {
			return &usecase.ProjectResponse{ID: "p1", Slug: slug}, nil
		},
		listFindingsFn: func(ctx context.Context, projectSlug string, filter usecase.FindingFilter, limit, offset int32) ([]usecase.FindingResponse, int64, error) {
			return nil, 0, nil
		},
		listReportsFn: func(ctx context.Context, projectSlug string, limit, offset int32) ([]usecase.ReportResponse, error) {
			return nil, nil
		},
		getReportFn: func(ctx context.Context, id string) (*usecase.ReportResponse, error) { return nil, nil },
		registerFn:  func(ctx context.Context, email, password string) (*usecase.AuthResponse, error) { return nil, nil },
		loginFn:     func(ctx context.Context, email, password string) (*usecase.AuthResponse, error) { return nil, nil },
		createAPIKeyFn: func(ctx context.Context, projectSlug, name string, expiresAt *time.Time) (*usecase.APIKeyResponse, error) {
			return nil, nil
		},
		listAPIKeysFn:  func(ctx context.Context, projectSlug string) ([]usecase.APIKeyResponse, error) { return nil, nil },
		revokeAPIKeyFn: func(ctx context.Context, projectSlug, keyID string) error { return nil },
		getFindingFn:   func(ctx context.Context, findingID string) (*usecase.FindingResponse, error) { return nil, nil },
		checkWaiverMatchFn: func(ctx context.Context, projectSlug, findingID string) (bool, error) {
			return true, nil
		},
	}
	router := NewRouter(RouterConfig{Usecases: mock, JWTAuth: testJWTAuth})
	require.NotNil(t, router)

	t.Run("health endpoint returns valid JSON", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/api/v1/health", nil)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)
		assert.Equal(t, http.StatusOK, w.Code)
		var body struct {
			Status string `json:"status"`
		}
		require.NoError(t, json.Unmarshal(w.Body.Bytes(), &body))
		assert.Equal(t, "ok", body.Status)
	})

	t.Run("version endpoint returns build info", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/api/v1/version", nil)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)
		assert.Equal(t, http.StatusOK, w.Code)
		var body struct {
			Version string `json:"version"`
			Commit  string `json:"commit"`
		}
		require.NoError(t, json.Unmarshal(w.Body.Bytes(), &body))
		assert.NotEmpty(t, body.Version)
		assert.NotEmpty(t, body.Commit)
	})

	t.Run("reports POST endpoint exists", func(t *testing.T) {
		req := httptest.NewRequest("POST", "/api/v1/reports", strings.NewReader(`{}`))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)
		assert.NotEqual(t, http.StatusNotFound, w.Code)
	})

	t.Run("projects list endpoint exists", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/api/v1/projects", nil)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)
		assert.NotEqual(t, http.StatusNotFound, w.Code)
	})

	t.Run("project detail endpoint exists", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/api/v1/projects/my-app", nil)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)
		assert.NotEqual(t, http.StatusNotFound, w.Code)
	})

	t.Run("findings list endpoint exists", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/api/v1/projects/my-app/findings", nil)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)
		assert.NotEqual(t, http.StatusNotFound, w.Code)
	})

	t.Run("reports list endpoint exists", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/api/v1/projects/my-app/reports", nil)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)
		assert.NotEqual(t, http.StatusNotFound, w.Code)
	})

	t.Run("report detail endpoint exists", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/api/v1/reports/550e8400-e29b-41d4-a716-446655440000", nil)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)
		assert.NotEqual(t, http.StatusNotFound, w.Code)
	})

	t.Run("waiver check match accepts POST", func(t *testing.T) {
		req := httptest.NewRequest("POST", "/api/v1/projects/my-app/waivers/check-match", strings.NewReader(`{"finding_id":"f1"}`))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer "+testToken(t))
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)
		assert.Equal(t, http.StatusOK, w.Code)
	})

	t.Run("unauthenticated request returns 401", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/api/v1/projects", nil)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)
		assert.Equal(t, http.StatusUnauthorized, w.Code)
	})

	t.Run("unknown route with auth returns 404", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/api/v1/nonexistent", nil)
		req.Header.Set("Authorization", "Bearer "+testToken(t))
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)
		assert.Equal(t, http.StatusNotFound, w.Code)
	})

	t.Run("auth register endpoint exists", func(t *testing.T) {
		req := httptest.NewRequest("POST", "/api/v1/auth/register", strings.NewReader(`{}`))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)
		assert.NotEqual(t, http.StatusNotFound, w.Code)
	})

	t.Run("auth login endpoint exists", func(t *testing.T) {
		req := httptest.NewRequest("POST", "/api/v1/auth/login", strings.NewReader(`{}`))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)
		assert.NotEqual(t, http.StatusNotFound, w.Code)
	})
}

func TestNewRouter_RateLimit(t *testing.T) {
	mock := &mockUsecases{
		loginFn: func(ctx context.Context, email, password string) (*usecase.AuthResponse, error) {
			return &usecase.AuthResponse{Token: "tok"}, nil
		},
	}
	router := NewRouter(RouterConfig{
		Usecases:  mock,
		JWTAuth:   testJWTAuth,
		RateLimit: RateLimitConfig{Enabled: true, RPS: 1, Burst: 2, AuthRPS: 1000, AuthBurst: 2000},
	})

	postLogin := func() *httptest.ResponseRecorder {
		req := httptest.NewRequest("POST", "/api/v1/auth/login", strings.NewReader(`{"email":"a@b.c","password":"secret123"}`))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)
		return w
	}
	assert.Equal(t, http.StatusOK, postLogin().Code)
	assert.Equal(t, http.StatusOK, postLogin().Code)
	limited := postLogin()
	assert.Equal(t, http.StatusTooManyRequests, limited.Code)
	assert.NotEmpty(t, limited.Header().Get("Retry-After"))

	req := httptest.NewRequest("GET", "/api/v1/health", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	assert.Equal(t, http.StatusOK, w.Code, "health stays reachable under flood")
}

func TestRegister_Success(t *testing.T) {
	mock := &mockUsecases{
		registerFn: func(ctx context.Context, email, password string) (*usecase.AuthResponse, error) {
			return &usecase.AuthResponse{Token: "tok", UserID: "u1", Email: email}, nil
		},
	}
	router := testRouter(mock)
	body := strings.NewReader(`{"email":"a@b.com","password":"secret"}`)
	req := httptest.NewRequest("POST", "/api/v1/auth/register", body)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusCreated, w.Code)
	var resp usecase.AuthResponse
	err := json.Unmarshal(w.Body.Bytes(), &resp)
	require.NoError(t, err)
	assert.Equal(t, "a@b.com", resp.Email)
}

func TestRegister_InvalidBody(t *testing.T) {
	router := testRouter(nil)
	req := httptest.NewRequest("POST", "/api/v1/auth/register", strings.NewReader(`not json`))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestRegister_FailureIsGeneric(t *testing.T) {
	// M8: the register endpoint must not reveal whether an email is already
	// registered. Every failure — duplicate email or any internal error —
	// returns the same 422 code and message, so the response cannot be used
	// as an account-enumeration oracle.
	failureCauses := map[string]error{
		"duplicate email": fmt.Errorf("email already registered"),
		"lookup error":    fmt.Errorf("lookup user: connection refused"),
		"internal error":  fmt.Errorf("create user: deadlock detected"),
	}
	for name, cause := range failureCauses {
		t.Run(name, func(t *testing.T) {
			mock := &mockUsecases{
				registerFn: func(ctx context.Context, email, password string) (*usecase.AuthResponse, error) {
					return nil, cause
				},
			}
			router := testRouter(mock)
			body := strings.NewReader(`{"email":"a@b.com","password":"password123"}`)
			req := httptest.NewRequest("POST", "/api/v1/auth/register", body)
			req.Header.Set("Content-Type", "application/json")
			w := httptest.NewRecorder()
			router.ServeHTTP(w, req)

			assert.Equal(t, http.StatusUnprocessableEntity, w.Code)
			var resp struct {
				Error struct {
					Code    string `json:"code"`
					Message string `json:"message"`
				} `json:"error"`
			}
			err := json.Unmarshal(w.Body.Bytes(), &resp)
			require.NoError(t, err)
			assert.Equal(t, "registration_failed", resp.Error.Code)
			assert.Equal(t, "registration failed", resp.Error.Message)
			assert.NotContains(t, w.Body.String(), cause.Error())
		})
	}
}

func TestLogin_Success(t *testing.T) {
	mock := &mockUsecases{
		loginFn: func(ctx context.Context, email, password string) (*usecase.AuthResponse, error) {
			return &usecase.AuthResponse{Token: "tok", UserID: "u1", Email: email}, nil
		},
	}
	router := testRouter(mock)
	body := strings.NewReader(`{"email":"a@b.com","password":"secret"}`)
	req := httptest.NewRequest("POST", "/api/v1/auth/login", body)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	var resp usecase.AuthResponse
	err := json.Unmarshal(w.Body.Bytes(), &resp)
	require.NoError(t, err)
	assert.Equal(t, "a@b.com", resp.Email)
}

func TestLogin_Failure(t *testing.T) {
	mock := &mockUsecases{
		loginFn: func(ctx context.Context, email, password string) (*usecase.AuthResponse, error) {
			return nil, fmt.Errorf("invalid email or password")
		},
	}
	router := testRouter(mock)
	body := strings.NewReader(`{"email":"a@b.com","password":"wrong"}`)
	req := httptest.NewRequest("POST", "/api/v1/auth/login", body)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestCreateAPIKey_Success(t *testing.T) {
	mock := &mockUsecases{
		createAPIKeyFn: func(ctx context.Context, projectSlug, name string, expiresAt *time.Time) (*usecase.APIKeyResponse, error) {
			return &usecase.APIKeyResponse{ID: "k1", Name: name, KeyPrefix: "vuln_abc", RawKey: "vuln_abc...", CreatedAt: "2026-06-30T12:00:00Z"}, nil
		},
	}
	router := testRouter(mock)
	body := strings.NewReader(`{"project":"my-app","name":"ci-key"}`)
	req := httptest.NewRequest("POST", "/api/v1/auth/apikeys", body)
	req.Header.Set("Content-Type", "application/json")
	req = req.WithContext(auth.ContextWithIdentity(req.Context(), &auth.Identity{UserID: "test-user"}))
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusCreated, w.Code)
	var resp usecase.APIKeyResponse
	err := json.Unmarshal(w.Body.Bytes(), &resp)
	require.NoError(t, err)
	assert.Equal(t, "vuln_abc...", resp.RawKey)
}

func TestCreateAPIKey_MissingFields(t *testing.T) {
	router := testRouter(nil)
	body := strings.NewReader(`{}`)
	req := httptest.NewRequest("POST", "/api/v1/auth/apikeys", body)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestCreateAPIKey_InvalidExpiresAt(t *testing.T) {
	mock := &mockUsecases{
		createAPIKeyFn: func(ctx context.Context, projectSlug, name string, expiresAt *time.Time) (*usecase.APIKeyResponse, error) {
			t.Fatal("usecase must not be called with an unparseable expires_at")
			return nil, nil
		},
	}
	router := testRouter(mock)
	body := strings.NewReader(`{"project":"my-app","name":"ci-key","expires_at":"tomorrow"}`)
	req := httptest.NewRequest("POST", "/api/v1/auth/apikeys", body)
	req.Header.Set("Content-Type", "application/json")
	req = req.WithContext(auth.ContextWithIdentity(req.Context(), &auth.Identity{UserID: "test-user"}))
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
	var resp struct {
		Error struct {
			Code string `json:"code"`
		} `json:"error"`
	}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.Equal(t, "invalid_expires_at", resp.Error.Code)
}

func TestCreateAPIKey_ValidExpiresAtForwarded(t *testing.T) {
	var gotExpiry *time.Time
	mock := &mockUsecases{
		createAPIKeyFn: func(ctx context.Context, projectSlug, name string, expiresAt *time.Time) (*usecase.APIKeyResponse, error) {
			gotExpiry = expiresAt
			return &usecase.APIKeyResponse{ID: "k1", Name: name, KeyPrefix: "vuln_abc", RawKey: "vuln_abc...", CreatedAt: "2026-06-30T12:00:00Z"}, nil
		},
	}
	router := testRouter(mock)
	body := strings.NewReader(`{"project":"my-app","name":"ci-key","expires_at":"2030-06-30T12:00:00Z"}`)
	req := httptest.NewRequest("POST", "/api/v1/auth/apikeys", body)
	req.Header.Set("Content-Type", "application/json")
	req = req.WithContext(auth.ContextWithIdentity(req.Context(), &auth.Identity{UserID: "test-user"}))
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusCreated, w.Code)
	require.NotNil(t, gotExpiry)
	assert.Equal(t, "2030-06-30T12:00:00Z", gotExpiry.UTC().Format(time.RFC3339))
}

func TestListAPIKeys_Success(t *testing.T) {
	mock := &mockUsecases{
		listAPIKeysFn: func(ctx context.Context, projectSlug string) ([]usecase.APIKeyResponse, error) {
			return []usecase.APIKeyResponse{{ID: "k1", Name: "ci-key", KeyPrefix: "vuln_abc"}}, nil
		},
	}
	router := testRouter(mock)
	req := httptest.NewRequest("GET", "/api/v1/auth/apikeys?project=my-app", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	var resp []usecase.APIKeyResponse
	err := json.Unmarshal(w.Body.Bytes(), &resp)
	require.NoError(t, err)
	assert.Len(t, resp, 1)
}

func TestListAPIKeys_MissingProject(t *testing.T) {
	router := testRouter(nil)
	req := httptest.NewRequest("GET", "/api/v1/auth/apikeys", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestRevokeAPIKey_Success(t *testing.T) {
	mock := &mockUsecases{
		revokeAPIKeyFn: func(ctx context.Context, projectSlug, keyID string) error { return nil },
	}
	router := testRouter(mock)
	req := httptest.NewRequest("DELETE", "/api/v1/auth/apikeys/k1?project=my-app", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusNoContent, w.Code)
}

func authRequest(method, path, body string) *http.Request {
	r := httptest.NewRequest(method, path, strings.NewReader(body))
	r.Header.Set("Content-Type", "application/json")
	ctx := auth.ContextWithIdentity(r.Context(), &auth.Identity{UserID: "test-user", Role: auth.RoleAdmin})
	return r.WithContext(ctx)
}

func TestTriageFinding_Success(t *testing.T) {
	mock := &mockUsecases{
		triageFindingFn: func(ctx context.Context, input usecase.TriageInput) (*usecase.TriageOutput, error) {
			return &usecase.TriageOutput{FindingID: "abc-123", AnalysisState: "false_positive", GateEffect: "ignore"}, nil
		},
	}
	router := testRouter(mock)
	req := authRequest("PATCH", "/api/v1/findings/abc-123", `{"analysis_state":"false_positive","reason":"test code only"}`)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	var resp usecase.TriageOutput
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.Equal(t, "false_positive", resp.AnalysisState)
}

func TestVerifyFinding_Success(t *testing.T) {
	mock := &mockUsecases{
		verifyFixFn: func(ctx context.Context, findingID string) (*usecase.VerifyResponse, error) {
			assert.Equal(t, "abc-123", findingID)
			return &usecase.VerifyResponse{FindingID: "abc-123", Outcome: usecase.VerifyFixed, Detail: "absent from rescan"}, nil
		},
	}
	router := testRouter(mock)
	req := authRequest("POST", "/api/v1/findings/abc-123/verify", "{}")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	var resp usecase.VerifyResponse
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.Equal(t, usecase.VerifyFixed, resp.Outcome)
}

func TestTriageFinding_MissingReason(t *testing.T) {
	mock := &mockUsecases{
		triageFindingFn: func(ctx context.Context, input usecase.TriageInput) (*usecase.TriageOutput, error) {
			return nil, usecase.ErrReasonRequired
		},
	}
	router := testRouter(mock)
	req := authRequest("PATCH", "/api/v1/findings/abc-123", `{"analysis_state":"false_positive"}`)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusUnprocessableEntity, w.Code)
}

func TestTriageFinding_MissingExpiry(t *testing.T) {
	mock := &mockUsecases{
		triageFindingFn: func(ctx context.Context, input usecase.TriageInput) (*usecase.TriageOutput, error) {
			return nil, usecase.ErrExpiryRequired
		},
	}
	router := testRouter(mock)
	req := authRequest("PATCH", "/api/v1/findings/abc-123", `{"analysis_state":"accepted_risk","reason":"ok for now"}`)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusUnprocessableEntity, w.Code)
}

func TestTriageFinding_InvalidState(t *testing.T) {
	mock := &mockUsecases{
		triageFindingFn: func(ctx context.Context, input usecase.TriageInput) (*usecase.TriageOutput, error) {
			return nil, usecase.ErrInvalidState
		},
	}
	router := testRouter(mock)
	req := authRequest("PATCH", "/api/v1/findings/abc-123", `{"analysis_state":"bogus"}`)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusUnprocessableEntity, w.Code)
}

func TestBulkTriage_InvalidState(t *testing.T) {
	mock := &mockUsecases{
		bulkTriageFn: func(ctx context.Context, input usecase.BulkTriageInput) ([]usecase.TriageOutput, error) {
			return nil, usecase.ErrInvalidState
		},
	}
	router := testRouter(mock)
	req := authRequest("POST", "/api/v1/findings/bulk-analysis", `{"finding_ids":["abc-123"],"analysis_state":"bogus"}`)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusUnprocessableEntity, w.Code)
}

func TestBulkTriage_Success(t *testing.T) {
	mock := &mockUsecases{
		bulkTriageFn: func(ctx context.Context, input usecase.BulkTriageInput) ([]usecase.TriageOutput, error) {
			return []usecase.TriageOutput{
				{FindingID: "abc-123", AnalysisState: "false_positive", GateEffect: "ignore"},
				{FindingID: "def-456", AnalysisState: "false_positive", GateEffect: "ignore"},
			}, nil
		},
	}
	router := testRouter(mock)
	req := authRequest("POST", "/api/v1/findings/bulk-analysis", `{"finding_ids":["abc-123","def-456"],"analysis_state":"false_positive","reason":"test code"}`)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
}

func TestTriageFinding_NilOrEmptyIdentity(t *testing.T) {
	h := &Handler{}

	// nil identity
	req := httptest.NewRequest("PATCH", "/api/v1/findings/abc-123", strings.NewReader(`{"analysis_state":"false_positive"}`))
	req = addChiURLParam(req, "id", "abc-123")
	w := httptest.NewRecorder()
	h.TriageFinding(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)

	// empty UserID (e.g. API key identity)
	ctx := auth.ContextWithIdentity(context.Background(), &auth.Identity{IsAPIKey: true, UserID: ""})
	req2 := httptest.NewRequest("PATCH", "/api/v1/findings/abc-123", strings.NewReader(`{"analysis_state":"false_positive"}`)).WithContext(ctx)
	req2 = addChiURLParam(req2, "id", "abc-123")
	w2 := httptest.NewRecorder()
	h.TriageFinding(w2, req2)
	assert.Equal(t, http.StatusUnauthorized, w2.Code)
}

func TestBulkTriage_NilOrEmptyIdentity(t *testing.T) {
	h := &Handler{}

	// nil identity
	req := httptest.NewRequest("POST", "/api/v1/findings/bulk-analysis", strings.NewReader(`{"finding_ids":["abc-123"],"analysis_state":"false_positive"}`))
	w := httptest.NewRecorder()
	h.BulkTriage(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)

	// empty UserID
	ctx := auth.ContextWithIdentity(context.Background(), &auth.Identity{IsAPIKey: true, UserID: ""})
	req2 := httptest.NewRequest("POST", "/api/v1/findings/bulk-analysis", strings.NewReader(`{"finding_ids":["abc-123"],"analysis_state":"false_positive"}`)).WithContext(ctx)
	w2 := httptest.NewRecorder()
	h.BulkTriage(w2, req2)
	assert.Equal(t, http.StatusUnauthorized, w2.Code)
}

func TestUpsertSignoff_NilOrEmptyIdentity(t *testing.T) {
	h := &Handler{}

	// nil identity
	req := httptest.NewRequest("POST", "/api/v1/findings/abc-123/signoff", strings.NewReader(`{"status":"approved","comment":"ok"}`))
	req = addChiURLParam(req, "findingID", "abc-123")
	w := httptest.NewRecorder()
	h.UpsertSignoff(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)

	// empty UserID
	ctx := auth.ContextWithIdentity(context.Background(), &auth.Identity{IsAPIKey: true, UserID: ""})
	req2 := httptest.NewRequest("POST", "/api/v1/findings/abc-123/signoff", strings.NewReader(`{"status":"approved","comment":"ok"}`)).WithContext(ctx)
	req2 = addChiURLParam(req2, "findingID", "abc-123")
	w2 := httptest.NewRecorder()
	h.UpsertSignoff(w2, req2)
	assert.Equal(t, http.StatusUnauthorized, w2.Code)
}

func TestGateStatus_Success(t *testing.T) {
	mock := &mockUsecases{
		getGateStatusFn: func(ctx context.Context, slug string, minRank int16) (*usecase.GateStatusOutput, error) {
			return &usecase.GateStatusOutput{ThresholdBreached: false, BlockingCount: 0}, nil
		},
	}
	router := testRouter(mock)
	req := httptest.NewRequest("GET", "/api/v1/projects/my-app/gate", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	var resp usecase.GateStatusOutput
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.False(t, resp.ThresholdBreached)
}

func TestGateStatus_Breached(t *testing.T) {
	mock := &mockUsecases{
		getGateStatusFn: func(ctx context.Context, slug string, minRank int16) (*usecase.GateStatusOutput, error) {
			return &usecase.GateStatusOutput{ThresholdBreached: true, BlockingCount: 3}, nil
		},
	}
	router := testRouter(mock)
	req := httptest.NewRequest("GET", "/api/v1/projects/my-app/gate", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
}

// TestGateStatus_WaivedFindingIDsSerialized pins the wire contract: the
// waived ids field is always an array, even when empty, so a UI can render
// per-finding "Waived" badges without nil checks.
func TestGateStatus_WaivedFindingIDsSerialized(t *testing.T) {
	mock := &mockUsecases{
		getGateStatusFn: func(ctx context.Context, slug string, minRank int16) (*usecase.GateStatusOutput, error) {
			return &usecase.GateStatusOutput{
				ThresholdBreached: true,
				BlockingCount:     1,
				WaivedFindingIDs:  []string{},
			}, nil
		},
	}
	router := testRouter(mock)
	req := httptest.NewRequest("GET", "/api/v1/projects/my-app/gate", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	require.Equal(t, http.StatusOK, w.Code)
	var body map[string]json.RawMessage
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &body))
	require.Contains(t, body, "waived_finding_ids", "the field must be present even when empty")
	assert.JSONEq(t, `[]`, string(body["waived_finding_ids"]))
}

func TestGateStatus_IntroducedOnly(t *testing.T) {
	var gotReport string
	mock := &mockUsecases{
		getIntroducedGateFn: func(ctx context.Context, slug string, minRank int16, reportID string) (*usecase.GateStatusOutput, error) {
			gotReport = reportID
			return &usecase.GateStatusOutput{ThresholdBreached: false, BlockingCount: 0}, nil
		},
	}
	router := testRouter(mock)
	req := httptest.NewRequest("GET", "/api/v1/projects/my-app/gate?introduced_only=1&report_id=r1", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, "r1", gotReport)
}

func TestGateStatus_IntroducedOnlyMissingReport(t *testing.T) {
	router := testRouter(&mockUsecases{})
	req := httptest.NewRequest("GET", "/api/v1/projects/my-app/gate?introduced_only=1", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestPreviewPRCheck_Success(t *testing.T) {
	var got usecase.PRCheckPreviewInput
	mock := &mockUsecases{
		previewPRCheckFn: func(ctx context.Context, input usecase.PRCheckPreviewInput) (*usecase.PRCheckPreview, error) {
			got = input
			return &usecase.PRCheckPreview{Provider: "github", CommitSha: "abc123", Conclusion: "failure"}, nil
		},
	}
	router := testRouter(mock)
	req := httptest.NewRequest("GET", "/api/v1/projects/my-app/pr-check?commit=abc123", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, "abc123", got.CommitSha)
}

func TestPreviewPRCheck_MissingCommit(t *testing.T) {
	router := testRouter(&mockUsecases{})
	req := httptest.NewRequest("GET", "/api/v1/projects/my-app/pr-check", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestPreviewPRCheck_UnknownProvider(t *testing.T) {
	mock := &mockUsecases{
		previewPRCheckFn: func(ctx context.Context, input usecase.PRCheckPreviewInput) (*usecase.PRCheckPreview, error) {
			return nil, usecase.ErrUnknownProvider
		},
	}
	router := testRouter(mock)
	req := httptest.NewRequest("GET", "/api/v1/projects/my-app/pr-check?commit=abc123&provider=bitkeeper", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestPreviewPatch_Success(t *testing.T) {
	mock := &mockUsecases{
		previewPatchFn: func(ctx context.Context, findingID string) (*patch.Outcome, error) {
			return &patch.Outcome{Supported: true, Proposal: &patch.Proposal{ID: "patch-abc", Class: patch.ClassDependencyBump}}, nil
		},
	}
	router := testRouter(mock)
	req := httptest.NewRequest("GET", "/api/v1/findings/f1/patch-preview", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
}

func TestPreviewPatch_Unsupported(t *testing.T) {
	mock := &mockUsecases{
		previewPatchFn: func(ctx context.Context, findingID string) (*patch.Outcome, error) {
			return &patch.Outcome{Reason: "secret findings are never auto-patched"}, nil
		},
	}
	router := testRouter(mock)
	req := httptest.NewRequest("GET", "/api/v1/findings/f1/patch-preview", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
}

func TestPreviewNotification_Success(t *testing.T) {
	var gotChannel, gotTarget string
	var gotLinked bool
	mock := &mockUsecases{
		previewNotifyFn: func(ctx context.Context, findingID, channel, target string, alreadyLinked bool) (*notify.Outcome, error) {
			gotChannel, gotTarget, gotLinked = channel, target, alreadyLinked
			return &notify.Outcome{Supported: true, Plan: &notify.Plan{ID: "notify-abc", Action: notify.ActionCreate}}, nil
		},
	}
	router := testRouter(mock)
	req := httptest.NewRequest("GET", "/api/v1/findings/f1/notify-preview?channel=issue&target=SEC&linked=1", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, "issue", gotChannel)
	assert.Equal(t, "SEC", gotTarget)
	assert.True(t, gotLinked)
}

func TestPreviewNotification_MissingChannel(t *testing.T) {
	router := testRouter(&mockUsecases{})
	req := httptest.NewRequest("GET", "/api/v1/findings/f1/notify-preview?target=SEC", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestPreviewNotification_MissingTarget(t *testing.T) {
	router := testRouter(&mockUsecases{})
	req := httptest.NewRequest("GET", "/api/v1/findings/f1/notify-preview?channel=issue", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestGetAdminStatus_Success(t *testing.T) {
	mock := &mockUsecases{
		adminStatusFn: func(ctx context.Context) (*usecase.AdminStatus, error) {
			return &usecase.AdminStatus{Projects: 2, Users: 5, OpenFindings: 10, Reports: 20}, nil
		},
	}
	router := testRouter(mock)
	req := httptest.NewRequest("GET", "/api/v1/admin/status", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
}

func TestPreviewRetention_Success(t *testing.T) {
	var gotDays int
	mock := &mockUsecases{
		previewRetentionFn: func(ctx context.Context, olderThanDays int) (*usecase.RetentionPreview, error) {
			gotDays = olderThanDays
			return &usecase.RetentionPreview{OlderThanDays: olderThanDays, StaleReports: 3}, nil
		},
	}
	router := testRouter(mock)
	req := httptest.NewRequest("GET", "/api/v1/admin/retention/preview?days=30", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, 30, gotDays)
}

func TestPreviewRetention_BadWindow(t *testing.T) {
	router := testRouter(&mockUsecases{})
	req := httptest.NewRequest("GET", "/api/v1/admin/retention/preview?days=0", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestPurgeRetention_Success(t *testing.T) {
	mock := &mockUsecases{
		purgeRetentionFn: func(ctx context.Context, olderThanDays int) (*usecase.RetentionResult, error) {
			return &usecase.RetentionResult{OlderThanDays: olderThanDays, DeletedReports: 2}, nil
		},
	}
	router := testRouter(mock)
	req := httptest.NewRequest("POST", "/api/v1/admin/retention/purge", strings.NewReader(`{"older_than_days":30}`))
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
}

func TestPurgeRetention_BadWindow(t *testing.T) {
	router := testRouter(&mockUsecases{})
	req := httptest.NewRequest("POST", "/api/v1/admin/retention/purge", strings.NewReader(`{"older_than_days":0}`))
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestPolicyTemplates_CRUD(t *testing.T) {
	mock := &mockUsecases{
		createPolicyFn: func(ctx context.Context, name, description string, definition json.RawMessage) (*usecase.PolicyTemplateResponse, error) {
			return &usecase.PolicyTemplateResponse{ID: "t1", Name: name, Version: 1}, nil
		},
		listPoliciesFn: func(ctx context.Context) ([]usecase.PolicyTemplateResponse, error) {
			return []usecase.PolicyTemplateResponse{{ID: "t1", Name: "strict"}}, nil
		},
		updatePolicyFn: func(ctx context.Context, id, name, description string, definition json.RawMessage) (*usecase.PolicyTemplateResponse, error) {
			return &usecase.PolicyTemplateResponse{ID: id, Name: name, Version: 2}, nil
		},
		deletePolicyFn: func(ctx context.Context, id string) error {
			assert.Equal(t, "t1", id)
			return nil
		},
	}
	router := testRouter(mock)

	w := httptest.NewRecorder()
	router.ServeHTTP(w, httptest.NewRequest("POST", "/api/v1/policy-templates", strings.NewReader(`{"name":"strict","definition":{}}`)))
	assert.Equal(t, http.StatusCreated, w.Code)

	w = httptest.NewRecorder()
	router.ServeHTTP(w, httptest.NewRequest("GET", "/api/v1/policy-templates", nil))
	assert.Equal(t, http.StatusOK, w.Code)

	w = httptest.NewRecorder()
	router.ServeHTTP(w, httptest.NewRequest("PUT", "/api/v1/policy-templates/t1", strings.NewReader(`{"name":"strict","definition":{}}`)))
	assert.Equal(t, http.StatusOK, w.Code)

	w = httptest.NewRecorder()
	router.ServeHTTP(w, httptest.NewRequest("DELETE", "/api/v1/policy-templates/t1", nil))
	assert.Equal(t, http.StatusNoContent, w.Code)
}

func TestPolicyTemplates_Conflict(t *testing.T) {
	mock := &mockUsecases{
		createPolicyFn: func(ctx context.Context, name, description string, definition json.RawMessage) (*usecase.PolicyTemplateResponse, error) {
			return nil, usecase.ErrPolicyConflict
		},
	}
	router := testRouter(mock)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, httptest.NewRequest("POST", "/api/v1/policy-templates", strings.NewReader(`{"name":"strict"}`)))
	assert.Equal(t, http.StatusConflict, w.Code)
}

func TestProjectPolicy_Assign(t *testing.T) {
	var gotTemplate string
	mock := &mockUsecases{
		setProjectPolicyFn: func(ctx context.Context, projectSlug, templateName string) (*usecase.PolicyEffectiveResponse, error) {
			gotTemplate = templateName
			return &usecase.PolicyEffectiveResponse{SeverityFloor: "critical", SeveritySource: "template"}, nil
		},
		effectivePolicyFn: func(ctx context.Context, projectSlug string) (*usecase.PolicyEffectiveResponse, error) {
			return &usecase.PolicyEffectiveResponse{SeverityFloor: "high", SeveritySource: "default"}, nil
		},
	}
	router := testRouter(mock)

	w := httptest.NewRecorder()
	router.ServeHTTP(w, httptest.NewRequest("PUT", "/api/v1/projects/my-app/policy", strings.NewReader(`{"template_name":"strict"}`)))
	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, "strict", gotTemplate)

	w = httptest.NewRecorder()
	router.ServeHTTP(w, httptest.NewRequest("GET", "/api/v1/projects/my-app/policy", nil))
	assert.Equal(t, http.StatusOK, w.Code)
}

func TestTeams_CRUD(t *testing.T) {
	mock := &mockUsecases{
		createTeamFn: func(ctx context.Context, name, description string) (*usecase.TeamResponse, error) {
			return &usecase.TeamResponse{ID: "team-1", Name: name}, nil
		},
		listTeamsFn: func(ctx context.Context) ([]usecase.TeamResponse, error) {
			return []usecase.TeamResponse{{ID: "team-1", Name: "backend"}}, nil
		},
		deleteTeamFn: func(ctx context.Context, teamID string) error {
			assert.Equal(t, "team-1", teamID)
			return nil
		},
	}
	router := testRouter(mock)

	w := httptest.NewRecorder()
	router.ServeHTTP(w, httptest.NewRequest("POST", "/api/v1/teams", strings.NewReader(`{"name":"backend"}`)))
	assert.Equal(t, http.StatusCreated, w.Code)

	w = httptest.NewRecorder()
	router.ServeHTTP(w, httptest.NewRequest("GET", "/api/v1/teams", nil))
	assert.Equal(t, http.StatusOK, w.Code)

	w = httptest.NewRecorder()
	router.ServeHTTP(w, httptest.NewRequest("DELETE", "/api/v1/teams/team-1", nil))
	assert.Equal(t, http.StatusNoContent, w.Code)
}

func TestTeams_Conflict(t *testing.T) {
	mock := &mockUsecases{
		createTeamFn: func(ctx context.Context, name, description string) (*usecase.TeamResponse, error) {
			return nil, usecase.ErrTeamConflict
		},
	}
	router := testRouter(mock)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, httptest.NewRequest("POST", "/api/v1/teams", strings.NewReader(`{"name":"backend"}`)))
	assert.Equal(t, http.StatusConflict, w.Code)
}

func TestProjectTeams_LinkUnlink(t *testing.T) {
	var gotRole string
	mock := &mockUsecases{
		linkProjectTeamFn: func(ctx context.Context, projectSlug, teamID, role string) (*usecase.ProjectTeamResponse, error) {
			gotRole = role
			return &usecase.ProjectTeamResponse{ProjectID: "p1", TeamID: teamID, TeamName: "backend", Role: role}, nil
		},
		unlinkProjectTeamFn: func(ctx context.Context, projectSlug, teamID string) error {
			assert.Equal(t, "team-1", teamID)
			return nil
		},
		listProjectTeamsFn: func(ctx context.Context, projectSlug string) ([]usecase.ProjectTeamResponse, error) {
			return []usecase.ProjectTeamResponse{{ProjectID: "p1", TeamID: "team-1", TeamName: "backend", Role: "editor"}}, nil
		},
	}
	router := testRouter(mock)

	w := httptest.NewRecorder()
	router.ServeHTTP(w, httptest.NewRequest("POST", "/api/v1/projects/my-app/teams", strings.NewReader(`{"team_id":"team-1","role":"editor"}`)))
	assert.Equal(t, http.StatusCreated, w.Code)
	assert.Equal(t, "editor", gotRole)

	w = httptest.NewRecorder()
	router.ServeHTTP(w, httptest.NewRequest("GET", "/api/v1/projects/my-app/teams", nil))
	assert.Equal(t, http.StatusOK, w.Code)

	w = httptest.NewRecorder()
	router.ServeHTTP(w, httptest.NewRequest("DELETE", "/api/v1/projects/my-app/teams/team-1", nil))
	assert.Equal(t, http.StatusNoContent, w.Code)
}

func TestTeams_InvalidIDBadRequest(t *testing.T) {
	mock := &mockUsecases{
		deleteTeamFn: func(ctx context.Context, teamID string) error {
			return usecase.ErrInvalidID
		},
	}
	router := testRouter(mock)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, httptest.NewRequest("DELETE", "/api/v1/teams/not-a-uuid", nil))
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestPolicyTemplate_InvalidIDBadRequest(t *testing.T) {
	mock := &mockUsecases{
		deletePolicyFn: func(ctx context.Context, id string) error {
			return usecase.ErrInvalidID
		},
	}
	router := testRouter(mock)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, httptest.NewRequest("DELETE", "/api/v1/policy-templates/not-a-uuid", nil))
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestGateStatus_ProjectNotFound(t *testing.T) {
	mock := &mockUsecases{
		getProjectFn: func(ctx context.Context, slug string) (*usecase.ProjectResponse, error) {
			return nil, fmt.Errorf("not found")
		},
	}
	router := testRouter(mock)
	req := httptest.NewRequest("GET", "/api/v1/projects/nonexistent/gate", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusNotFound, w.Code)
}

func TestStats_Success(t *testing.T) {
	mock := &mockUsecases{
		getProjectStatsFn: func(ctx context.Context, slug string) (*usecase.ProjectStats, error) {
			return &usecase.ProjectStats{
				TotalFindings: 42,
				BlockingCount: 3,
				WaiverCount:   5,
				ReportCount:   10,
				BySeverity: []usecase.SeverityCount{
					{Severity: "critical", Count: 2, BlockingCount: 2},
					{Severity: "high", Count: 10, BlockingCount: 1},
				},
			}, nil
		},
	}
	router := testRouter(mock)
	req := httptest.NewRequest("GET", "/api/v1/projects/my-app/stats", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	var resp usecase.ProjectStats
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.Equal(t, int32(42), resp.TotalFindings)
	assert.Equal(t, int32(3), resp.BlockingCount)
	assert.Equal(t, int32(5), resp.WaiverCount)
	assert.Equal(t, int32(10), resp.ReportCount)
	assert.Len(t, resp.BySeverity, 2)
}

func TestStats_ProjectNotFound(t *testing.T) {
	mock := &mockUsecases{
		getProjectStatsFn: func(ctx context.Context, slug string) (*usecase.ProjectStats, error) {
			return nil, fmt.Errorf("project not found")
		},
	}
	router := testRouter(mock)
	req := httptest.NewRequest("GET", "/api/v1/projects/unknown/stats", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusInternalServerError, w.Code)
}

func TestAging_Success(t *testing.T) {
	mock := &mockUsecases{
		getAgingFn: func(ctx context.Context, slug string) (*usecase.AgingResponse, error) {
			assert.Equal(t, "my-app", slug)
			return &usecase.AgingResponse{
				Buckets:      []usecase.AgingBucketCount{{Bucket: "debt", Count: 2, Overdue: 1}},
				OverdueTotal: 1,
				Reopened:     1,
			}, nil
		},
	}
	router := testRouter(mock)
	req := httptest.NewRequest("GET", "/api/v1/projects/my-app/aging", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	var resp usecase.AgingResponse
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.Equal(t, int32(1), resp.OverdueTotal)
	assert.Equal(t, int32(1), resp.Reopened)
}

func TestListFindingEvents_Success(t *testing.T) {
	mock := &mockUsecases{
		getFindingEventsFn: func(ctx context.Context, findingID string, eventTypes []string, limit, offset int32) ([]usecase.FindingEvent, error) {
			return []usecase.FindingEvent{{EventType: "analysis_changed"}}, nil
		},
	}
	router := testRouter(mock)
	req := httptest.NewRequest("GET", "/api/v1/findings/abc-123/events", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
}

// ----- GetFinding Handler Tests -----

func TestGetFinding_Success(t *testing.T) {
	mock := &mockUsecases{
		getFindingFn: func(ctx context.Context, findingID string) (*usecase.FindingResponse, error) {
			return &usecase.FindingResponse{ID: findingID, FindingKind: "sca", CurrentTitle: "CVE-2026-0001"}, nil
		},
	}
	router := testRouter(mock)
	req := httptest.NewRequest("GET", "/api/v1/findings/550e8400-e29b-41d4-a716-446655440000", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	var resp usecase.FindingResponse
	err := json.Unmarshal(w.Body.Bytes(), &resp)
	require.NoError(t, err)
	assert.Equal(t, "sca", resp.FindingKind)
}

func TestGetFinding_InvalidID(t *testing.T) {
	mock := &mockUsecases{
		getFindingFn: func(ctx context.Context, findingID string) (*usecase.FindingResponse, error) {
			return nil, fmt.Errorf("invalid finding id")
		},
	}
	router := testRouter(mock)
	req := httptest.NewRequest("GET", "/api/v1/findings/not-a-uuid", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestGetFinding_NotFound(t *testing.T) {
	mock := &mockUsecases{
		getFindingFn: func(ctx context.Context, findingID string) (*usecase.FindingResponse, error) {
			return nil, fmt.Errorf("get finding: not found")
		},
	}
	router := testRouter(mock)
	req := httptest.NewRequest("GET", "/api/v1/findings/550e8400-e29b-41d4-a716-446655440000", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusNotFound, w.Code)
}

func TestGetFinding_APIKeyAccessDenied(t *testing.T) {
	mock := &mockUsecases{
		getFindingFn: func(ctx context.Context, findingID string) (*usecase.FindingResponse, error) {
			return nil, usecase.ErrProjectAccessDenied
		},
	}
	h := &Handler{usecase: mock}
	req := httptest.NewRequest("GET", "/api/v1/findings/00000000-0000-0000-0000-000000000021", nil)
	req = req.WithContext(auth.ContextWithIdentity(req.Context(), &auth.Identity{
		UserID: "00000000-0000-0000-0000-000000000040", IsAPIKey: true,
	}))
	req = addChiURLParam(req, "id", "00000000-0000-0000-0000-000000000021")
	w := httptest.NewRecorder()
	h.GetFinding(w, req)

	assert.Equal(t, http.StatusForbidden, w.Code)
}

// ----- Refresh Handler Tests -----

func TestRefresh_Success(t *testing.T) {
	mock := &mockUsecases{
		refreshFn: func(ctx context.Context, refreshToken string) (*usecase.AuthResponse, error) {
			return &usecase.AuthResponse{Token: "new-token", RefreshToken: "new-refresh", UserID: "u1", Email: "test@example.com"}, nil
		},
	}
	router := testRouter(mock)
	body := strings.NewReader(`{"refresh_token":"valid-token"}`)
	req := httptest.NewRequest("POST", "/api/v1/auth/refresh", body)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	var resp usecase.AuthResponse
	err := json.Unmarshal(w.Body.Bytes(), &resp)
	require.NoError(t, err)
	assert.NotEmpty(t, resp.Token)
}

func TestRefresh_InvalidBody(t *testing.T) {
	router := testRouter(nil)
	req := httptest.NewRequest("POST", "/api/v1/auth/refresh", strings.NewReader(`not json`))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestRefresh_Error(t *testing.T) {
	mock := &mockUsecases{
		refreshFn: func(ctx context.Context, refreshToken string) (*usecase.AuthResponse, error) {
			return nil, fmt.Errorf("invalid refresh token")
		},
	}
	router := testRouter(mock)
	body := strings.NewReader(`{"refresh_token":"bad-token"}`)
	req := httptest.NewRequest("POST", "/api/v1/auth/refresh", body)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

// ----- Logout Handler Tests -----

type failingTokenRevoker struct {
	err error
}

func (r failingTokenRevoker) RevokeTokenContext(context.Context, string) error {
	return r.err
}

func TestLogout_AccessTokenRevocationError(t *testing.T) {
	mock := &mockUsecases{
		logoutFn: func(ctx context.Context, refreshToken string) error { return nil },
	}
	h := NewHandler(mock, failingTokenRevoker{err: fmt.Errorf("revocation store unavailable")})
	body := strings.NewReader(`{"refresh_token":"valid-token"}`)
	req := httptest.NewRequest("POST", "/api/v1/auth/logout", body)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer access-token")
	w := httptest.NewRecorder()
	h.Logout(w, req)

	assert.Equal(t, http.StatusInternalServerError, w.Code)
	var resp apiError
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.Equal(t, "logout_failed", resp.Error.Code)
}

func TestLogout_Success(t *testing.T) {
	mock := &mockUsecases{
		logoutFn: func(ctx context.Context, refreshToken string) error { return nil },
	}
	router := testRouter(mock)
	body := strings.NewReader(`{"refresh_token":"valid-token"}`)
	req := httptest.NewRequest("POST", "/api/v1/auth/logout", body)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusNoContent, w.Code)
}

func TestLogout_IgnoresInvalidOrExpiredBearerToken(t *testing.T) {
	const testJWTSecret = "test-secret-for-logout-tests-0123456789"
	jwtAuth, err := auth.NewJWTAuthenticator(testJWTSecret)
	require.NoError(t, err)
	expired := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"iss": "specht", "aud": "specht-api", "sub": "user-1", "jti": "expired", "iat": time.Now().Add(-time.Hour).Unix(), "exp": time.Now().Add(-time.Minute).Unix(),
	})
	expiredToken, err := expired.SignedString([]byte(testJWTSecret))
	require.NoError(t, err)

	for _, token := range []string{"not-a-jwt", expiredToken} {
		t.Run(token[:min(len(token), 8)], func(t *testing.T) {
			mock := &mockUsecases{logoutFn: func(context.Context, string) error { return nil }}
			h := NewHandler(mock, jwtAuth)
			req := httptest.NewRequest("POST", "/api/v1/auth/logout", strings.NewReader(`{"refresh_token":"valid-token"}`))
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("Authorization", "Bearer "+token)
			w := httptest.NewRecorder()
			h.Logout(w, req)
			assert.Equal(t, http.StatusNoContent, w.Code)
		})
	}
}

func TestLogout_EmptyBody(t *testing.T) {
	// Regression: the body-size helper must tolerate empty bodies —
	// logout historically ignored decode errors, so clients sending no
	// body kept working.
	var got string
	mock := &mockUsecases{
		logoutFn: func(ctx context.Context, refreshToken string) error {
			got = refreshToken
			return nil
		},
	}
	router := testRouter(mock)
	req := httptest.NewRequest("POST", "/api/v1/auth/logout", nil)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusNoContent, w.Code)
	assert.Equal(t, "", got)
}

func TestLogout_WithError(t *testing.T) {
	mock := &mockUsecases{
		logoutFn: func(ctx context.Context, refreshToken string) error {
			return fmt.Errorf("db error")
		},
	}
	router := testRouter(mock)
	body := strings.NewReader(`{"refresh_token":"some-token"}`)
	req := httptest.NewRequest("POST", "/api/v1/auth/logout", body)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusInternalServerError, w.Code)
}

// ----- Me Handler Tests -----

func TestListProjects_AccessDenied(t *testing.T) {
	// Second sweep: tenant denial surfaces as 403, never 500.
	mock := &mockUsecases{
		listProjectsFn: func(ctx context.Context) ([]usecase.ProjectResponse, error) {
			return nil, usecase.ErrProjectAccessDenied
		},
	}
	h := &Handler{usecase: mock}
	req := httptest.NewRequest("GET", "/api/v1/projects", nil)
	w := httptest.NewRecorder()
	h.ListProjects(w, req)

	assert.Equal(t, http.StatusForbidden, w.Code)
}

func TestMe_Success(t *testing.T) {
	mock := &mockUsecases{
		getProfileFn: func(ctx context.Context, userID string) (*usecase.UserProfile, error) {
			return &usecase.UserProfile{ID: userID, Email: "test@example.com", Role: "user"}, nil
		},
	}
	router := testRouter(mock)
	req := httptest.NewRequest("GET", "/api/v1/me", nil)
	req = req.WithContext(auth.ContextWithIdentity(req.Context(), &auth.Identity{UserID: "test-user"}))
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	var resp usecase.UserProfile
	err := json.Unmarshal(w.Body.Bytes(), &resp)
	require.NoError(t, err)
	assert.Equal(t, "test@example.com", resp.Email)
}

func TestMe_NoIdentity(t *testing.T) {
	router := NewRouter(RouterConfig{Usecases: &mockUsecases{}, JWTAuth: testJWTAuth})
	req := httptest.NewRequest("GET", "/api/v1/me", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestMe_UserNotFound(t *testing.T) {
	mock := &mockUsecases{
		getProfileFn: func(ctx context.Context, userID string) (*usecase.UserProfile, error) {
			return nil, fmt.Errorf("user not found")
		},
	}
	router := testRouter(mock)
	req := httptest.NewRequest("GET", "/api/v1/me", nil)
	req = req.WithContext(auth.ContextWithIdentity(req.Context(), &auth.Identity{UserID: "nonexistent"}))
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusNotFound, w.Code)
}

func TestUpdateMe_Success(t *testing.T) {
	mock := &mockUsecases{
		updateProfileFn: func(ctx context.Context, userID string, displayName *string) (*usecase.UserProfile, error) {
			require.NotNil(t, displayName)
			return &usecase.UserProfile{ID: userID, Email: "test@example.com", DisplayName: *displayName, Role: "user"}, nil
		},
	}
	router := testRouter(mock)
	req := httptest.NewRequest("PUT", "/api/v1/me", strings.NewReader(`{"display_name":"Alice"}`))
	req.Header.Set("Content-Type", "application/json")
	req = req.WithContext(auth.ContextWithIdentity(req.Context(), &auth.Identity{UserID: "test-user"}))
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	var resp usecase.UserProfile
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.Equal(t, "Alice", resp.DisplayName)
}

func TestUpdateMe_NoIdentity(t *testing.T) {
	router := NewRouter(RouterConfig{Usecases: &mockUsecases{}, JWTAuth: testJWTAuth})
	req := httptest.NewRequest("PUT", "/api/v1/me", strings.NewReader(`{"display_name":"Alice"}`))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestUpdateMe_UserNotFound(t *testing.T) {
	mock := &mockUsecases{
		updateProfileFn: func(ctx context.Context, userID string, displayName *string) (*usecase.UserProfile, error) {
			return nil, fmt.Errorf("user not found")
		},
	}
	router := testRouter(mock)
	req := httptest.NewRequest("PUT", "/api/v1/me", strings.NewReader(`{"display_name":"Alice"}`))
	req.Header.Set("Content-Type", "application/json")
	req = req.WithContext(auth.ContextWithIdentity(req.Context(), &auth.Identity{UserID: "nonexistent"}))
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusNotFound, w.Code)
}

// ----- AuthMiddleware Tests -----

func TestAuthMiddleware_NoHeader(t *testing.T) {
	mw := AuthMiddleware(testJWTAuth)
	handler := mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	req := httptest.NewRequest("GET", "/api/v1/projects", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestAuthMiddleware_InvalidToken(t *testing.T) {
	mw := AuthMiddleware(testJWTAuth)
	handler := mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	req := httptest.NewRequest("GET", "/api/v1/projects", nil)
	req.Header.Set("Authorization", "Bearer invalid-jwt-token")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestAuthMiddleware_ExpiredJWTDoesNotFallThrough(t *testing.T) {
	mw := AuthMiddleware(testJWTAuth, auth.NewAPIKeyAuthenticator(func(ctx context.Context, keyHash string) (string, string, []string, time.Time, error) {
		return "user-1", "project-1", nil, time.Time{}, nil
	}))

	// generate an expired JWT that is well-formed but past expiry
	a, err := auth.NewJWTAuthenticator(testJWTSecret)
	require.NoError(t, err)
	expiredTok, err := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"sub":   "test-user",
		"email": "test@example.com",
		"iat":   time.Now().Add(-2 * time.Hour).Unix(),
		"exp":   time.Now().Add(-1 * time.Hour).Unix(),
	}).SignedString([]byte(testJWTSecret))

	require.NoError(t, err)
	_ = a // silence unused

	handler := mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	req := httptest.NewRequest("GET", "/api/v1/projects", nil)
	req.Header.Set("Authorization", "Bearer "+expiredTok)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestAuthMiddleware_MalformedTokenFallsThrough(t *testing.T) {
	mw := AuthMiddleware(testJWTAuth, auth.NewAPIKeyAuthenticator(func(ctx context.Context, keyHash string) (string, string, []string, time.Time, error) {
		return "user-1", "project-1", nil, time.Time{}, nil
	}))
	var capturedID string
	handler := mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ident := auth.ContextIdentity(r.Context())
		capturedID = ident.UserID
		w.WriteHeader(http.StatusOK)
	}))
	req := httptest.NewRequest("GET", "/api/v1/projects", nil)
	req.Header.Set("Authorization", "Bearer not-a-jwt")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, "user-1", capturedID)
}

func TestAuthMiddleware_NoAuthenticators(t *testing.T) {
	mw := AuthMiddleware()
	handler := mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	req := httptest.NewRequest("GET", "/api/v1/projects", nil)
	req.Header.Set("Authorization", "Bearer some-token")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestAuthMiddleware_APIKeyAuth(t *testing.T) {
	apiKeyAuth := auth.NewAPIKeyAuthenticator(func(ctx context.Context, keyHash string) (string, string, []string, time.Time, error) {
		return "user-1", "project-1", nil, time.Time{}, nil
	})
	mw := AuthMiddleware(testJWTAuth, apiKeyAuth)
	var capturedID string
	handler := mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ident := auth.ContextIdentity(r.Context())
		capturedID = ident.UserID
		w.WriteHeader(http.StatusOK)
	}))
	req := httptest.NewRequest("GET", "/api/v1/projects", nil)
	req.Header.Set("Authorization", "Bearer some-api-key")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, "user-1", capturedID)
}

func TestAPIKeyAuthenticator_IdentitySemantics(t *testing.T) {
	var capturedHash string
	apiKeyAuth := auth.NewAPIKeyAuthenticator(func(ctx context.Context, keyHash string) (string, string, []string, time.Time, error) {
		capturedHash = keyHash
		return "key-1", "project-1", nil, time.Time{}, nil
	})

	ident, err := apiKeyAuth.Authenticate(context.Background(), "vuln_abc123keymaterial")
	require.NoError(t, err)
	assert.Equal(t, "key-1", ident.UserID)
	assert.Equal(t, "", ident.Email)
	assert.Equal(t, "project-1", ident.ProjectID)
	assert.True(t, ident.IsAPIKey)

	h := sha256.Sum256([]byte("vuln_abc123keymaterial"))
	assert.Equal(t, hex.EncodeToString(h[:]), capturedHash)
}

// ----- NewRouter endpoint connectivity -----

func TestNewRouter_RefreshLogoutOutsideAuth(t *testing.T) {
	mock := &mockUsecases{
		refreshFn: func(ctx context.Context, refreshToken string) (*usecase.AuthResponse, error) {
			return &usecase.AuthResponse{Token: "new-tok", RefreshToken: "new-ref", UserID: "u1", Email: "a@b.com"}, nil
		},
		logoutFn: func(ctx context.Context, refreshToken string) error { return nil },
	}
	router := NewRouter(RouterConfig{Usecases: mock, JWTAuth: testJWTAuth})

	t.Run("refresh without auth header succeeds", func(t *testing.T) {
		body := strings.NewReader(`{"refresh_token":"x"}`)
		req := httptest.NewRequest("POST", "/api/v1/auth/refresh", body)
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)
		assert.Equal(t, http.StatusOK, w.Code)
	})

	t.Run("logout without auth header succeeds", func(t *testing.T) {
		req := httptest.NewRequest("POST", "/api/v1/auth/logout", strings.NewReader(`{}`))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)
		assert.Equal(t, http.StatusNoContent, w.Code)
	})

	t.Run("me without token returns 401", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/api/v1/me", nil)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)
		assert.Equal(t, http.StatusUnauthorized, w.Code)
	})
}

func TestNewRouter_MeWithValidToken(t *testing.T) {
	mock := &mockUsecases{
		getProfileFn: func(ctx context.Context, userID string) (*usecase.UserProfile, error) {
			return &usecase.UserProfile{ID: userID, Email: "test@example.com", Role: "user"}, nil
		},
	}
	router := NewRouter(RouterConfig{Usecases: mock, JWTAuth: testJWTAuth})

	req := httptest.NewRequest("GET", "/api/v1/me", nil)
	req.Header.Set("Authorization", "Bearer "+testToken(t))
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
}

// ----- parseMinSeverityRank Tests -----

func TestParseMinSeverityRank(t *testing.T) {
	tests := []struct {
		input string
		want  int16
	}{
		{"", 3},
		{"high", 3},
		{"critical", 4},
		{"medium", 2},
		{"low", 1},
		{"high,critical", 3},
		{"low,medium", 1},
		{"unknown", 3},
	}
	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got := parseMinSeverityRank(tt.input)
			assert.Equal(t, tt.want, got)
		})
	}
}

// ----- parseIntParam Tests -----

func TestParseIntParam(t *testing.T) {
	tests := []struct {
		name       string
		query      string
		defaultVal int32
		want       int32
	}{
		{"no param", "/test", 20, 20},
		{"valid param", "/test?limit=50", 20, 50},
		{"negative param", "/test?limit=-1", 20, 20},
		{"non-numeric", "/test?limit=abc", 20, 20},
		{"zero", "/test?limit=0", 20, 0},
		{"int64 overflow truncated to int32 wraps negative", "/test?limit=4294967295", 20, 20},
		{"int32 overflow", "/test?limit=2147483648", 20, 20},
		{"above max clamps to 500", "/test?limit=1000", 20, 500},
		{"at max allowed", "/test?limit=500", 20, 500},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := httptest.NewRequest("GET", tt.query, nil)
			got := parseIntParam(r, "limit", tt.defaultVal)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestParseOffsetParam(t *testing.T) {
	tests := []struct {
		name       string
		query      string
		defaultVal int32
		want       int32
	}{
		{"no param", "/test", 0, 0},
		{"valid offset above page-size cap", "/test?offset=1000", 0, 1000},
		{"maximum int32", "/test?offset=2147483647", 0, 2147483647},
		{"int32 overflow", "/test?offset=2147483648", 7, 7},
		{"negative offset", "/test?offset=-1", 7, 7},
		{"non-numeric", "/test?offset=abc", 7, 7},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := httptest.NewRequest("GET", tt.query, nil)
			assert.Equal(t, tt.want, parseOffsetParam(r, "offset", tt.defaultVal))
		})
	}
}

func sampleWaiverResponse() usecase.WaiverResponse {
	return usecase.WaiverResponse{
		ID:          "wvr-1",
		ProjectID:   "proj-1",
		Name:        "test-waiver",
		Description: "test description",
		Enabled:     true,
		Conditions:  []usecase.WaiverConditionResp{},
		Contexts:    []usecase.WaiverContextResp{},
		Targets:     []usecase.WaiverFindingTargetResp{},
		CreatedAt:   now.Format(time.RFC3339),
		UpdatedAt:   now.Format(time.RFC3339),
	}
}

// authRouter mirrors testRouter's authorized-operator identity for the
// waiver routes (see testRouter): handler behavior under test, access
// control covered elsewhere.
func authRouter(h *Handler) http.Handler {
	r := chi.NewRouter()
	r.Use(func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx := auth.ContextWithIdentity(r.Context(), &auth.Identity{UserID: "test-user", Role: auth.RoleAdmin})
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	})
	r.Get("/api/v1/projects/{slug}/members", h.ListProjectMembers)
	r.Post("/api/v1/projects/{slug}/members", h.AddProjectMember)
	r.Route("/api/v1/projects/{slug}/waivers", func(r chi.Router) {
		r.Get("/", h.ListWaivers)
		r.Post("/", h.CreateWaiver)
		r.Get("/{id}", h.GetWaiver)
		r.Put("/{id}", h.UpdateWaiver)
		r.Delete("/{id}", h.DeleteWaiver)
		r.Post("/{id}/toggle", h.ToggleWaiver)
		r.Get("/{id}/events", h.ListWaiverEvents)
		r.Post("/check-match", h.CheckWaiverMatch)
	})
	return r
}

func TestCreateWaiver_Success(t *testing.T) {
	mock := &mockUsecases{
		createWaiverFn: func(ctx context.Context, input usecase.CreateWaiverInput) (*usecase.WaiverResponse, error) {
			assert.Equal(t, "my-app", input.ProjectSlug)
			assert.Equal(t, "test-waiver", input.Name)
			assert.Equal(t, "test-user", input.ActorID)
			r := sampleWaiverResponse()
			return &r, nil
		},
	}
	h := NewHandler(mock)
	router := authRouter(h)
	body := strings.NewReader(`{"name":"test-waiver","description":"test description"}`)
	req := httptest.NewRequest("POST", "/api/v1/projects/my-app/waivers", body)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusCreated, w.Code)
	var resp usecase.WaiverResponse
	err := json.Unmarshal(w.Body.Bytes(), &resp)
	require.NoError(t, err)
	assert.Equal(t, "test-waiver", resp.Name)
}

func TestCreateWaiver_MissingName(t *testing.T) {
	handler := &Handler{}
	body := strings.NewReader(`{"name":""}`)
	req := httptest.NewRequest("POST", "/api/v1/projects/my-app/waivers", body)
	req = req.WithContext(auth.ContextWithIdentity(req.Context(), &auth.Identity{UserID: "test-user", Role: auth.RoleAdmin}))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	handler.CreateWaiver(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestListWaivers_Success(t *testing.T) {
	mock := &mockUsecases{
		listWaiversFn: func(ctx context.Context, projectSlug string) ([]usecase.WaiverResponse, error) {
			assert.Equal(t, "my-app", projectSlug)
			return []usecase.WaiverResponse{sampleWaiverResponse()}, nil
		},
	}
	h := NewHandler(mock)
	router := authRouter(h)
	req := httptest.NewRequest("GET", "/api/v1/projects/my-app/waivers", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	var resp []usecase.WaiverResponse
	err := json.Unmarshal(w.Body.Bytes(), &resp)
	require.NoError(t, err)
	assert.Len(t, resp, 1)
}

func TestGetWaiver_Success(t *testing.T) {
	mock := &mockUsecases{
		getWaiverFn: func(ctx context.Context, projectSlug, waiverID string) (*usecase.WaiverDetailResponse, error) {
			assert.Equal(t, "my-app", projectSlug)
			assert.Equal(t, "wvr-1", waiverID)
			return &usecase.WaiverDetailResponse{WaiverResponse: sampleWaiverResponse()}, nil
		},
	}
	h := NewHandler(mock)
	router := authRouter(h)
	req := httptest.NewRequest("GET", "/api/v1/projects/my-app/waivers/wvr-1", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
}

func TestDeleteWaiver_Success(t *testing.T) {
	mock := &mockUsecases{
		deleteWaiverFn: func(ctx context.Context, projectSlug, waiverID string) error {
			assert.Equal(t, "my-app", projectSlug)
			assert.Equal(t, "wvr-1", waiverID)
			return nil
		},
	}
	h := NewHandler(mock)
	router := authRouter(h)
	req := httptest.NewRequest("DELETE", "/api/v1/projects/my-app/waivers/wvr-1", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusNoContent, w.Code)
}

func TestToggleWaiver_Success(t *testing.T) {
	mock := &mockUsecases{
		toggleWaiverFn: func(ctx context.Context, projectSlug, waiverID, actorID string) (*usecase.WaiverResponse, error) {
			assert.Equal(t, "my-app", projectSlug)
			assert.Equal(t, "wvr-1", waiverID)
			assert.Equal(t, "test-user", actorID)
			r := sampleWaiverResponse()
			r.Enabled = false
			return &r, nil
		},
	}
	h := NewHandler(mock)
	router := authRouter(h)
	req := httptest.NewRequest("POST", "/api/v1/projects/my-app/waivers/wvr-1/toggle", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	var resp usecase.WaiverResponse
	err := json.Unmarshal(w.Body.Bytes(), &resp)
	require.NoError(t, err)
	assert.False(t, resp.Enabled)
}

func TestCheckWaiverMatch_Success(t *testing.T) {
	mock := &mockUsecases{
		checkWaiverMatchFn: func(ctx context.Context, projectSlug, findingID string) (bool, error) {
			assert.Equal(t, "my-app", projectSlug)
			assert.Equal(t, "find-1", findingID)
			return true, nil
		},
	}
	h := NewHandler(mock)
	router := authRouter(h)
	body := strings.NewReader(`{"finding_id":"find-1"}`)
	req := httptest.NewRequest("POST", "/api/v1/projects/my-app/waivers/check-match", body)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	var resp map[string]bool
	err := json.Unmarshal(w.Body.Bytes(), &resp)
	require.NoError(t, err)
	assert.True(t, resp["matched"])
}

func addChiURLParam(r *http.Request, key, value string) *http.Request {
	chiCtx := chi.NewRouteContext()
	chiCtx.URLParams.Add(key, value)
	return r.WithContext(context.WithValue(r.Context(), chi.RouteCtxKey, chiCtx))
}

func TestCheckWaiverMatch_MissingFindingID(t *testing.T) {
	handler := &Handler{}
	body := strings.NewReader(`{}`)
	req := httptest.NewRequest("POST", "/api/v1/projects/my-app/waivers/check-match", body)
	req = req.WithContext(auth.ContextWithIdentity(req.Context(), &auth.Identity{UserID: "test-user", Role: auth.RoleAdmin}))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	handler.CheckWaiverMatch(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestListProjectMembers_Success(t *testing.T) {
	mock := &mockUsecases{
		getProjectFn: func(ctx context.Context, slug string) (*usecase.ProjectResponse, error) {
			return &usecase.ProjectResponse{ID: "00000000-0000-0000-0000-000000000001", Slug: slug}, nil
		},
		isProjectMemberFn: func(ctx context.Context, projectID, userID string) (bool, error) {
			return true, nil
		},
		listProjectMembersFn: func(ctx context.Context, projectSlug string) ([]usecase.ProjectMemberResponse, error) {
			return []usecase.ProjectMemberResponse{{ProjectID: "00000000-0000-0000-0000-000000000001", UserID: "u1", Role: auth.RoleViewer}}, nil
		},
	}
	h := NewHandler(mock)
	router := authRouter(h)
	req := httptest.NewRequest("GET", "/api/v1/projects/my-app/members", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
}

func TestAddProjectMember_Success(t *testing.T) {
	mock := &mockUsecases{
		getProjectFn: func(ctx context.Context, slug string) (*usecase.ProjectResponse, error) {
			return &usecase.ProjectResponse{ID: "00000000-0000-0000-0000-000000000001", Slug: slug}, nil
		},
		isProjectMemberFn: func(ctx context.Context, projectID, userID string) (bool, error) {
			return true, nil
		},
		addProjectMemberFn: func(ctx context.Context, projectSlug, userID, role string) (*usecase.ProjectMemberResponse, error) {
			return &usecase.ProjectMemberResponse{ProjectID: "00000000-0000-0000-0000-000000000001", UserID: userID, Role: role}, nil
		},
	}
	h := NewHandler(mock)
	router := authRouter(h)
	body := strings.NewReader(`{"user_id":"new-1","role":"editor"}`)
	req := httptest.NewRequest("POST", "/api/v1/projects/my-app/members", body)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	assert.Equal(t, http.StatusCreated, w.Code)
}

func TestListProjectMembers_NonMemberDenied(t *testing.T) {
	mock := &mockUsecases{
		getProjectFn: func(ctx context.Context, slug string) (*usecase.ProjectResponse, error) {
			return &usecase.ProjectResponse{ID: "00000000-0000-0000-0000-000000000001", Slug: slug}, nil
		},
		isProjectMemberFn: func(ctx context.Context, projectID, userID string) (bool, error) {
			return false, nil
		},
	}
	h := NewHandler(mock)
	router := authRouter(h)
	req := httptest.NewRequest("GET", "/api/v1/projects/my-app/members", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	assert.Equal(t, http.StatusForbidden, w.Code)
}

// ----- enforceProjectAccess Tests -----

// Session users are authorized by tenant membership: members pass,
// non-members are denied, global admins bypass, and nil identities are
// denied outright.
func TestEnforceProjectAccess_SessionMembership(t *testing.T) {
	projectID := "00000000-0000-0000-0000-000000000001"
	newHandler := func(isMember bool) *Handler {
		return &Handler{usecase: &mockUsecases{
			getProjectFn: func(ctx context.Context, slug string) (*usecase.ProjectResponse, error) {
				if slug == "nonexistent" {
					return nil, fmt.Errorf("not found")
				}
				return &usecase.ProjectResponse{ID: projectID, Slug: slug}, nil
			},
			isProjectMemberFn: func(ctx context.Context, pid, uid string) (bool, error) {
				assert.Equal(t, projectID, pid)
				assert.Equal(t, "user-1", uid)
				return isMember, nil
			},
		}}
	}
	withIdent := func(ident *auth.Identity) *http.Request {
		req := httptest.NewRequest("GET", "/api/v1/projects/my-app", nil)
		return req.WithContext(auth.ContextWithIdentity(req.Context(), ident))
	}

	assert.NoError(t, newHandler(true).enforceProjectAccess(withIdent(&auth.Identity{UserID: "user-1"}), "my-app"), "member passes")
	assert.Error(t, newHandler(false).enforceProjectAccess(withIdent(&auth.Identity{UserID: "user-1"}), "my-app"), "non-member denied")
	assert.NoError(t, newHandler(false).enforceProjectAccess(withIdent(&auth.Identity{UserID: "admin-1", Role: auth.RoleAdmin}), "my-app"), "global admin bypasses")
	assert.ErrorIs(t, newHandler(false).enforceProjectAccess(withIdent(&auth.Identity{UserID: "admin-1", Role: auth.RoleAdmin}), "nonexistent"), errProjectNotFound, "admin on nonexistent project returns not found")

	reqNil := httptest.NewRequest("GET", "/api/v1/projects/my-app", nil)
	assert.Error(t, newHandler(true).enforceProjectAccess(reqNil, "my-app"), "nil identity denied")
}

func TestEnforceProjectAccess_APIKeyMatching(t *testing.T) {
	projectID := "00000000-0000-0000-0000-000000000001"
	h := &Handler{usecase: &mockUsecases{
		getProjectFn: func(ctx context.Context, slug string) (*usecase.ProjectResponse, error) {
			assert.Equal(t, "my-app", slug)
			return &usecase.ProjectResponse{ID: projectID, Slug: slug}, nil
		},
	}}
	req := httptest.NewRequest("GET", "/api/v1/projects/my-app", nil)
	req = req.WithContext(auth.ContextWithIdentity(req.Context(), &auth.Identity{UserID: "key-1", ProjectID: projectID, IsAPIKey: true}))
	err := h.enforceProjectAccess(req, "my-app")
	assert.NoError(t, err)
}

func TestEnforceProjectAccess_APIKeyNonMatching(t *testing.T) {
	projectID := "00000000-0000-0000-0000-000000000001"
	otherProjectID := "00000000-0000-0000-0000-000000000002"
	h := &Handler{usecase: &mockUsecases{
		getProjectFn: func(ctx context.Context, slug string) (*usecase.ProjectResponse, error) {
			assert.Equal(t, "other-project", slug)
			return &usecase.ProjectResponse{ID: otherProjectID, Slug: slug}, nil
		},
	}}
	req := httptest.NewRequest("GET", "/api/v1/projects/other-project", nil)
	req = req.WithContext(auth.ContextWithIdentity(req.Context(), &auth.Identity{UserID: "key-1", ProjectID: projectID, IsAPIKey: true}))
	err := h.enforceProjectAccess(req, "other-project")
	assert.Error(t, err)
}

func TestEnforceProjectAccess_NilIdentity(t *testing.T) {
	h := &Handler{}
	req := httptest.NewRequest("GET", "/api/v1/projects/my-app", nil)
	err := h.enforceProjectAccess(req, "my-app")
	assert.Error(t, err)
}

// ----- Handler-level enforcement test -----

func TestListFindings_APIKeyAccessDenied(t *testing.T) {
	projectID := "00000000-0000-0000-0000-000000000001"
	otherProjectID := "00000000-0000-0000-0000-000000000002"
	mock := &mockUsecases{
		getProjectFn: func(ctx context.Context, slug string) (*usecase.ProjectResponse, error) {
			return &usecase.ProjectResponse{ID: otherProjectID, Slug: slug}, nil
		},
	}
	handler := &Handler{usecase: mock}
	req := httptest.NewRequest("GET", "/api/v1/projects/my-app/findings", nil)
	req = req.WithContext(auth.ContextWithIdentity(req.Context(), &auth.Identity{
		UserID: "key-1", ProjectID: projectID, IsAPIKey: true,
	}))
	req = addChiURLParam(req, "slug", "my-app")
	w := httptest.NewRecorder()
	handler.ListFindings(w, req)

	assert.Equal(t, http.StatusForbidden, w.Code)
	var resp struct {
		Error struct {
			Code string `json:"code"`
		} `json:"error"`
	}
	err := json.Unmarshal(w.Body.Bytes(), &resp)
	require.NoError(t, err)
	assert.Equal(t, "project_access_denied", resp.Error.Code)
}

func TestListFindings_APIKeyAllowed(t *testing.T) {
	projectID := "00000000-0000-0000-0000-000000000001"
	mock := &mockUsecases{
		getProjectFn: func(ctx context.Context, slug string) (*usecase.ProjectResponse, error) {
			return &usecase.ProjectResponse{ID: projectID, Slug: slug}, nil
		},
		listFindingsFn: func(ctx context.Context, projectSlug string, filter usecase.FindingFilter, limit, offset int32) ([]usecase.FindingResponse, int64, error) {
			return sampleFindings(), int64(len(sampleFindings())), nil
		},
	}
	handler := &Handler{usecase: mock}
	req := httptest.NewRequest("GET", "/api/v1/projects/my-app/findings", nil)
	req = req.WithContext(auth.ContextWithIdentity(req.Context(), &auth.Identity{
		UserID: "key-1", ProjectID: projectID, IsAPIKey: true,
	}))
	req = addChiURLParam(req, "slug", "my-app")
	w := httptest.NewRecorder()
	handler.ListFindings(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
}

func TestWatcherStatusHandler(t *testing.T) {
	mock := &mockUsecases{
		getWatcherStatusFn: func(ctx context.Context) (*usecase.WatcherStatusResponse, error) {
			return &usecase.WatcherStatusResponse{
				LastSuccessfulPollAt: "2026-09-03T10:00:00Z",
				ConsecutiveFailures:  0,
				Healthy:              true,
			}, nil
		},
	}
	router := NewRouter(RouterConfig{Usecases: mock, JWTAuth: testJWTAuth})
	req := httptest.NewRequest("GET", "/api/v1/watcher/status", nil)
	req.Header.Set("Authorization", "Bearer "+makeTestToken(t, auth.RoleAdmin))
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	var resp usecase.WatcherStatusResponse
	err := json.Unmarshal(w.Body.Bytes(), &resp)
	require.NoError(t, err)
	assert.True(t, resp.Healthy)
	assert.Equal(t, "2026-09-03T10:00:00Z", resp.LastSuccessfulPollAt)
}

func TestGetGateStatus_APIKeyUUIDProject(t *testing.T) {
	projectID := "00000000-0000-0000-0000-000000000001"
	mock := &mockUsecases{
		getProjectFn: func(ctx context.Context, slug string) (*usecase.ProjectResponse, error) {
			return &usecase.ProjectResponse{ID: projectID, Slug: slug}, nil
		},
		getGateStatusFn: func(ctx context.Context, slug string, minRank int16) (*usecase.GateStatusOutput, error) {
			assert.Equal(t, "my-app", slug)
			return &usecase.GateStatusOutput{}, nil
		},
	}
	req := httptest.NewRequest("GET", "/api/v1/projects/my-app/gate", nil)
	req = req.WithContext(auth.ContextWithIdentity(req.Context(), &auth.Identity{
		UserID: "key-1", ProjectID: projectID, IsAPIKey: true,
	}))
	w := httptest.NewRecorder()
	testRouter(mock).ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
}

func TestReachabilityHandlers_InvalidFindingID(t *testing.T) {
	tests := []struct {
		name   string
		method string
		body   string
		handle func(*Handler, http.ResponseWriter, *http.Request)
	}{
		{
			name:   "list",
			method: "GET",
			handle: (*Handler).ListReachability,
		},
		{
			name:   "upsert",
			method: "POST",
			body:   `{"state":"unknown"}`,
			handle: (*Handler).UpsertReachability,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mock := &mockUsecases{}
			if tt.name == "list" {
				mock.listReachabilityFn = func(ctx context.Context, findingID string) ([]usecase.ReachabilityResponse, error) {
					return nil, usecase.ErrInvalidFindingID
				}
			} else {
				mock.upsertReachabilityFn = func(ctx context.Context, findingID, userID, state, evidence string) (*usecase.ReachabilityResponse, error) {
					return nil, usecase.ErrInvalidFindingID
				}
			}
			h := &Handler{usecase: mock}
			req := httptest.NewRequest(tt.method, "/api/v1/findings/not-a-uuid/reachability", strings.NewReader(tt.body))
			req = addChiURLParam(req, "findingID", "not-a-uuid")
			if tt.name == "upsert" {
				req = req.WithContext(auth.ContextWithIdentity(req.Context(), &auth.Identity{UserID: "user-1"}))
			}
			w := httptest.NewRecorder()
			tt.handle(h, w, req)

			assert.Equal(t, http.StatusBadRequest, w.Code)
			var resp apiError
			require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
			assert.Equal(t, "invalid_id", resp.Error.Code)
		})
	}
}

func TestListScannersHandler(t *testing.T) {
	mock := &mockUsecases{
		listScannersFn: func() []usecase.ScannerDescriptorResponse {
			return []usecase.ScannerDescriptorResponse{
				{Name: "trivy", Version: "2", FindingKinds: []string{"sca", "secret", "iac"}, ProvidesPackages: true},
				{Name: "semgrep", Version: "2.1", FindingKinds: []string{"sast"}},
			}
		},
	}
	router := NewRouter(RouterConfig{Usecases: mock, JWTAuth: testJWTAuth})
	req := httptest.NewRequest("GET", "/api/v1/scanners", nil)
	req.Header.Set("Authorization", "Bearer "+makeTestToken(t, auth.RoleAdmin))
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	var resp []usecase.ScannerDescriptorResponse
	err := json.Unmarshal(w.Body.Bytes(), &resp)
	require.NoError(t, err)
	require.Len(t, resp, 2)
	assert.Equal(t, "trivy", resp[0].Name)
	assert.Equal(t, []string{"sca", "secret", "iac"}, resp[0].FindingKinds)
	assert.Equal(t, "semgrep", resp[1].Name)
}

// TestListUsersHandler pins the directory contract the admin UIs pick from:
// the email filter and pagination pass through untouched, and the response is
// the account shape without any credential material.
func TestListUsersHandler(t *testing.T) {
	var gotFilter string
	var gotLimit, gotOffset int32
	mock := &mockUsecases{
		listUsersFn: func(ctx context.Context, filter string, limit, offset int32) ([]usecase.UserProfile, error) {
			gotFilter, gotLimit, gotOffset = filter, limit, offset
			return []usecase.UserProfile{
				{ID: "u1", Email: "alice@example.com", DisplayName: "Alice", Role: "admin", CreatedAt: "2026-01-01T00:00:00Z"},
				{ID: "u2", Email: "bob@example.com", Role: "member", CreatedAt: "2026-01-02T00:00:00Z"},
			}, nil
		},
	}
	router := NewRouter(RouterConfig{Usecases: mock, JWTAuth: testJWTAuth})
	req := httptest.NewRequest("GET", "/api/v1/users?email=example.com&limit=5&offset=1000", nil)
	req.Header.Set("Authorization", "Bearer "+makeTestToken(t, auth.RoleAdmin))
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	require.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, "example.com", gotFilter, "the filter reaches the use case verbatim")
	assert.EqualValues(t, 5, gotLimit)
	assert.EqualValues(t, 1000, gotOffset)

	var resp []usecase.UserProfile
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	require.Len(t, resp, 2)
	assert.Equal(t, "alice@example.com", resp[0].Email)
	assert.Equal(t, "Alice", resp[0].DisplayName)
	assert.Equal(t, "admin", resp[0].Role)
	assert.NotContains(t, w.Body.String(), "password", "the account shape carries no credential material")
}

// TestGlobalStatusEndpoints_AdminOnly guards the fix for unscoped global
// daemon state (watcher health, scanner capabilities) and for the account
// directory: any authenticated principal could previously read daemon state,
// and a project-scoped key must never enumerate the organization. Non-admin
// session users and project-scoped API keys are denied; only admin session
// users pass.
func TestGlobalStatusEndpoints_AdminOnly(t *testing.T) {
	mock := &mockUsecases{
		getWatcherStatusFn: func(ctx context.Context) (*usecase.WatcherStatusResponse, error) {
			return &usecase.WatcherStatusResponse{Healthy: true}, nil
		},
		listScannersFn: func() []usecase.ScannerDescriptorResponse {
			return []usecase.ScannerDescriptorResponse{{Name: "trivy"}}
		},
		listUsersFn: func(ctx context.Context, filter string, limit, offset int32) ([]usecase.UserProfile, error) {
			return []usecase.UserProfile{{ID: "u1", Email: "admin@example.com", Role: "admin"}}, nil
		},
	}
	router := NewRouter(RouterConfig{
		Usecases: mock,
		JWTAuth:  testJWTAuth,
		APIKeyLookup: func(ctx context.Context, keyHash string) (string, string, []string, time.Time, error) {
			return "key-user", "project-1", nil, time.Time{}, nil
		},
	})

	tests := []struct {
		name string
		path string
		auth func(*http.Request)
		want int
	}{
		{
			name: "watcher status non-admin session user forbidden",
			path: "/api/v1/watcher/status",
			auth: func(req *http.Request) {
				req.Header.Set("Authorization", "Bearer "+makeTestToken(t, auth.RoleViewer))
			},
			want: http.StatusForbidden,
		},
		{
			name: "watcher status admin session user allowed",
			path: "/api/v1/watcher/status",
			auth: func(req *http.Request) {
				req.Header.Set("Authorization", "Bearer "+makeTestToken(t, auth.RoleAdmin))
			},
			want: http.StatusOK,
		},
		{
			name: "watcher status API key forbidden",
			path: "/api/v1/watcher/status",
			auth: func(req *http.Request) {
				req.Header.Set("Authorization", "Bearer vuln_testapikey")
			},
			want: http.StatusForbidden,
		},
		{
			name: "scanners non-admin session user forbidden",
			path: "/api/v1/scanners",
			auth: func(req *http.Request) {
				req.Header.Set("Authorization", "Bearer "+makeTestToken(t, auth.RoleViewer))
			},
			want: http.StatusForbidden,
		},
		{
			name: "scanners admin session user allowed",
			path: "/api/v1/scanners",
			auth: func(req *http.Request) {
				req.Header.Set("Authorization", "Bearer "+makeTestToken(t, auth.RoleAdmin))
			},
			want: http.StatusOK,
		},
		{
			name: "scanners API key forbidden",
			path: "/api/v1/scanners",
			auth: func(req *http.Request) {
				req.Header.Set("Authorization", "Bearer vuln_testapikey")
			},
			want: http.StatusForbidden,
		},
		{
			name: "users non-admin session user forbidden",
			path: "/api/v1/users",
			auth: func(req *http.Request) {
				req.Header.Set("Authorization", "Bearer "+makeTestToken(t, auth.RoleViewer))
			},
			want: http.StatusForbidden,
		},
		{
			name: "users admin session user allowed",
			path: "/api/v1/users",
			auth: func(req *http.Request) {
				req.Header.Set("Authorization", "Bearer "+makeTestToken(t, auth.RoleAdmin))
			},
			want: http.StatusOK,
		},
		{
			name: "users API key forbidden",
			path: "/api/v1/users",
			auth: func(req *http.Request) {
				req.Header.Set("Authorization", "Bearer vuln_testapikey")
			},
			want: http.StatusForbidden,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest("GET", tt.path, nil)
			tt.auth(req)
			w := httptest.NewRecorder()
			router.ServeHTTP(w, req)
			assert.Equal(t, tt.want, w.Code)
		})
	}
}

func TestRequireRole_AdminAllowed(t *testing.T) {
	tok := makeTestToken(t, auth.RoleAdmin)
	mw := AuthMiddleware(testJWTAuth)
	roleMw := RequireRole(auth.RoleAdmin)
	handler := mw(roleMw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})))
	req := httptest.NewRequest("POST", "/api/v1/projects", nil)
	req.Header.Set("Authorization", "Bearer "+tok)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
}

func TestRequireRole_ViewerDenied(t *testing.T) {
	tok := makeTestToken(t, auth.RoleViewer)
	mw := AuthMiddleware(testJWTAuth)
	roleMw := RequireRole(auth.RoleAdmin)
	handler := mw(roleMw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})))
	req := httptest.NewRequest("POST", "/api/v1/projects", nil)
	req.Header.Set("Authorization", "Bearer "+tok)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	assert.Equal(t, http.StatusForbidden, w.Code)
}

func TestRequireRole_UnauthenticatedDenied(t *testing.T) {
	roleMw := RequireRole(auth.RoleAdmin)
	handler := roleMw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	req := httptest.NewRequest("POST", "/api/v1/projects", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

// TestRequireRole_RejectsUnknownRole guards the RequireRole allowlist: a JWT
// carrying a role outside the canonical vocabulary (admin/editor/viewer) must
// be denied even when it is not the guarded role. Before the fix, RequireRole
// compared ident.Role only against the demanded roles, so the legacy DB role
// "member" embedded verbatim in a token sailed through any middleware that
// did not name it — an unknown role was treated as "authenticated, nothing
// demanded matches, allow" instead of "not a known principal, deny".
func TestRequireRole_RejectsUnknownRole(t *testing.T) {
	mw := AuthMiddleware(testJWTAuth)

	tests := []struct {
		name string
		role string
	}{
		{name: "legacy member role", role: "member"},
		{name: "empty role", role: ""},
		{name: "garbage role", role: "superuser"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tok := makeTestToken(t, tt.role)
			roleMw := RequireRole(auth.RoleEditor, auth.RoleViewer)
			handler := mw(roleMw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
			})))
			req := httptest.NewRequest("POST", "/api/v1/projects", nil)
			req.Header.Set("Authorization", "Bearer "+tok)
			w := httptest.NewRecorder()
			handler.ServeHTTP(w, req)

			assert.Equal(t, http.StatusForbidden, w.Code)
		})
	}
}
