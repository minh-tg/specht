package usecase

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/minh-tg/specht/internal/auth"
	"github.com/minh-tg/specht/internal/domain"
	"github.com/minh-tg/specht/internal/gate"
	"github.com/minh-tg/specht/internal/port"
	"github.com/minh-tg/specht/internal/scanner"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type mockProjectRepo struct {
	port.ProjectStore
	createFn            func(context.Context, port.CreateProjectInput) (port.Project, error)
	listFn              func(context.Context) ([]port.Project, error)
	listByIDsFn         func(context.Context, []string) ([]port.Project, error)
	getBySlugFn         func(context.Context, string) (port.Project, error)
	getByIDFn           func(context.Context, string) (port.Project, error)
	updateFn            func(context.Context, string, string, *string) (port.Project, error)
	updateSettingsFn    func(context.Context, string, json.RawMessage) (port.Project, error)
	deleteFn            func(context.Context, string) (port.Project, error)
	upsertMemberFn      func(context.Context, string, string, string) (port.ProjectMember, error)
	listMembersFn       func(context.Context, string) ([]port.ProjectMember, error)
	isMemberFn          func(context.Context, string, string) (bool, error)
	listMemberIDsFn     func(context.Context, string) ([]string, error)
	isMemberEffectiveFn func(context.Context, string, string) (bool, error)
	listAccessibleIDsFn func(context.Context, string) ([]string, error)
	effectiveRoleFn     func(context.Context, string, string) (string, error)
}

func (m *mockProjectRepo) GetByID(ctx context.Context, id string) (port.Project, error) {
	if m.getByIDFn != nil {
		return m.getByIDFn(ctx, id)
	}
	return port.Project{}, fmt.Errorf("unexpected call to GetByID")
}

func (m *mockProjectRepo) ListByIDs(ctx context.Context, ids []string) ([]port.Project, error) {
	if m.listByIDsFn != nil {
		return m.listByIDsFn(ctx, ids)
	}
	if m.listFn != nil {
		all, err := m.listFn(ctx)
		if err != nil {
			return nil, err
		}
		idMap := make(map[string]bool, len(ids))
		for _, id := range ids {
			idMap[id] = true
		}
		var out []port.Project
		for _, p := range all {
			if idMap[p.ID] {
				out = append(out, p)
			}
		}
		return out, nil
	}
	return []port.Project{}, nil
}

func (m *mockProjectRepo) UpsertMember(ctx context.Context, projectID, userID, role string) (port.ProjectMember, error) {
	if m.upsertMemberFn == nil {
		return port.ProjectMember{}, fmt.Errorf("unexpected call to UpsertMember")
	}
	return m.upsertMemberFn(ctx, projectID, userID, role)
}

func (m *mockProjectRepo) ListMembers(ctx context.Context, projectID string) ([]port.ProjectMember, error) {
	if m.listMembersFn == nil {
		return nil, fmt.Errorf("unexpected call to ListMembers")
	}
	return m.listMembersFn(ctx, projectID)
}

func (m *mockProjectRepo) IsMember(ctx context.Context, projectID, userID string) (bool, error) {
	if m.isMemberFn == nil {
		return false, fmt.Errorf("unexpected call to IsMember")
	}
	return m.isMemberFn(ctx, projectID, userID)
}

func (m *mockProjectRepo) IsMemberEffective(ctx context.Context, projectID, userID string) (bool, error) {
	if m.isMemberEffectiveFn != nil {
		return m.isMemberEffectiveFn(ctx, projectID, userID)
	}
	// Compatibility shim: harnesses predating team-conferred access stub
	// direct membership only.
	if m.isMemberFn != nil {
		return m.isMemberFn(ctx, projectID, userID)
	}
	return false, fmt.Errorf("unexpected call to IsMemberEffective")
}

func (m *mockProjectRepo) ListAccessibleProjectIDs(ctx context.Context, userID string) ([]string, error) {
	if m.listAccessibleIDsFn != nil {
		return m.listAccessibleIDsFn(ctx, userID)
	}
	if m.listMemberIDsFn != nil {
		return m.listMemberIDsFn(ctx, userID)
	}
	return nil, fmt.Errorf("unexpected call to ListAccessibleProjectIDs")
}

func (m *mockProjectRepo) EffectiveRole(ctx context.Context, projectID, userID string) (string, error) {
	if m.effectiveRoleFn != nil {
		return m.effectiveRoleFn(ctx, projectID, userID)
	}
	if m.listMembersFn != nil {
		members, err := m.listMembersFn(ctx, projectID)
		if err != nil {
			return "", err
		}
		for _, member := range members {
			if member.UserID == userID {
				return member.Role, nil
			}
		}
		return "", port.ErrNotFound
	}
	if m.isMemberEffectiveFn != nil {
		member, err := m.isMemberEffectiveFn(ctx, projectID, userID)
		if err != nil {
			return "", err
		}
		if !member {
			return "", port.ErrNotFound
		}
		return auth.RoleEditor, nil
	}
	if m.isMemberFn != nil {
		member, err := m.isMemberFn(ctx, projectID, userID)
		if err != nil {
			return "", err
		}
		if !member {
			return "", port.ErrNotFound
		}
		return auth.RoleEditor, nil
	}
	return "", fmt.Errorf("unexpected call to EffectiveRole")
}

type mockTeamRepo struct {
	port.TeamStore
	createFn       func(context.Context, string, string) (port.Team, error)
	getByIDFn      func(context.Context, string) (port.Team, error)
	getByNameFn    func(context.Context, string) (port.Team, error)
	listFn         func(context.Context) ([]port.Team, error)
	deleteFn       func(context.Context, string) error
	upsertMemberFn func(context.Context, string, string, string) (port.TeamMember, error)
	listMembersFn  func(context.Context, string) ([]port.TeamMember, error)
	removeMemberFn func(context.Context, string, string) error
	isMemberFn     func(context.Context, string, string) (bool, error)
	isAdminFn      func(context.Context, string, string) (bool, error)
	linkFn         func(context.Context, string, string, string) (port.ProjectTeam, error)
	unlinkFn       func(context.Context, string, string) error
	listLinksFn    func(context.Context, string) ([]port.ProjectTeam, error)
}

func (m *mockTeamRepo) CreateTeam(ctx context.Context, name, description string) (port.Team, error) {
	if m.createFn == nil {
		return port.Team{}, fmt.Errorf("unexpected call to CreateTeam")
	}
	return m.createFn(ctx, name, description)
}

func (m *mockTeamRepo) GetTeamByID(ctx context.Context, id string) (port.Team, error) {
	if m.getByIDFn == nil {
		return port.Team{}, fmt.Errorf("unexpected call to GetTeamByID")
	}
	return m.getByIDFn(ctx, id)
}

func (m *mockTeamRepo) GetTeamByName(ctx context.Context, name string) (port.Team, error) {
	if m.getByNameFn == nil {
		return port.Team{}, fmt.Errorf("unexpected call to GetTeamByName")
	}
	return m.getByNameFn(ctx, name)
}

func (m *mockTeamRepo) ListTeams(ctx context.Context) ([]port.Team, error) {
	if m.listFn == nil {
		return nil, fmt.Errorf("unexpected call to ListTeams")
	}
	return m.listFn(ctx)
}

func (m *mockTeamRepo) DeleteTeam(ctx context.Context, id string) error {
	if m.deleteFn == nil {
		return fmt.Errorf("unexpected call to DeleteTeam")
	}
	return m.deleteFn(ctx, id)
}

func (m *mockTeamRepo) UpsertTeamMember(ctx context.Context, teamID, userID, role string) (port.TeamMember, error) {
	if m.upsertMemberFn == nil {
		return port.TeamMember{}, fmt.Errorf("unexpected call to UpsertTeamMember")
	}
	return m.upsertMemberFn(ctx, teamID, userID, role)
}

func (m *mockTeamRepo) ListTeamMembers(ctx context.Context, teamID string) ([]port.TeamMember, error) {
	if m.listMembersFn == nil {
		return nil, fmt.Errorf("unexpected call to ListTeamMembers")
	}
	return m.listMembersFn(ctx, teamID)
}

func (m *mockTeamRepo) RemoveTeamMember(ctx context.Context, teamID, userID string) error {
	if m.removeMemberFn == nil {
		return fmt.Errorf("unexpected call to RemoveTeamMember")
	}
	return m.removeMemberFn(ctx, teamID, userID)
}

func (m *mockTeamRepo) IsTeamMember(ctx context.Context, teamID, userID string) (bool, error) {
	if m.isMemberFn == nil {
		return false, fmt.Errorf("unexpected call to IsTeamMember")
	}
	return m.isMemberFn(ctx, teamID, userID)
}

func (m *mockTeamRepo) IsTeamAdmin(ctx context.Context, teamID, userID string) (bool, error) {
	if m.isAdminFn == nil {
		return false, fmt.Errorf("unexpected call to IsTeamAdmin")
	}
	return m.isAdminFn(ctx, teamID, userID)
}

func (m *mockTeamRepo) LinkProjectTeam(ctx context.Context, projectID, teamID, role string) (port.ProjectTeam, error) {
	if m.linkFn == nil {
		return port.ProjectTeam{}, fmt.Errorf("unexpected call to LinkProjectTeam")
	}
	return m.linkFn(ctx, projectID, teamID, role)
}

func (m *mockTeamRepo) UnlinkProjectTeam(ctx context.Context, projectID, teamID string) error {
	if m.unlinkFn == nil {
		return fmt.Errorf("unexpected call to UnlinkProjectTeam")
	}
	return m.unlinkFn(ctx, projectID, teamID)
}

func (m *mockTeamRepo) ListProjectTeams(ctx context.Context, projectID string) ([]port.ProjectTeam, error) {
	if m.listLinksFn == nil {
		return nil, fmt.Errorf("unexpected call to ListProjectTeams")
	}
	return m.listLinksFn(ctx, projectID)
}

func (m *mockProjectRepo) ListMemberProjectIDs(ctx context.Context, userID string) ([]string, error) {
	if m.listMemberIDsFn == nil {
		return nil, fmt.Errorf("unexpected call to ListMemberProjectIDs")
	}
	return m.listMemberIDsFn(ctx, userID)
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

func (m *mockProjectRepo) Update(ctx context.Context, slug, name string, description *string) (port.Project, error) {
	if m.updateFn == nil {
		return port.Project{}, fmt.Errorf("unexpected call to Update")
	}
	return m.updateFn(ctx, slug, name, description)
}

func (m *mockProjectRepo) UpdateSettings(ctx context.Context, projectID string, settings json.RawMessage) (port.Project, error) {
	if m.updateSettingsFn == nil {
		return port.Project{}, fmt.Errorf("unexpected call to UpdateSettings")
	}
	return m.updateSettingsFn(ctx, projectID, settings)
}

func (m *mockProjectRepo) Delete(ctx context.Context, slug string) (port.Project, error) {
	if m.deleteFn == nil {
		return port.Project{}, fmt.Errorf("unexpected call to Delete")
	}
	return m.deleteFn(ctx, slug)
}

type mockReportRepo struct {
	port.ReportStore
	createFn              func(context.Context, port.CreateReportInput) (port.Report, error)
	getByIDFn             func(context.Context, string) (port.Report, error)
	listByProjectFn       func(context.Context, string, int32, int32) ([]port.Report, error)
	updateStatusFn        func(context.Context, string, string, string, int32, *string) (port.Report, error)
	latestReportFn        func(context.Context, string, string) (port.CompletedReport, error)
	byCommitFn            func(context.Context, string, string, string) (port.CompletedReport, error)
	countStaleFn          func(context.Context, time.Time) (int64, error)
	deleteStaleFn         func(context.Context, time.Time) ([]string, error)
	findCompletedByHashFn func(context.Context, string, string) (string, error)
	deleteReportFn        func(context.Context, string, string) error
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

func (m *mockReportRepo) GetCompletedByCommit(ctx context.Context, projectID, scanner, commit string) (port.CompletedReport, error) {
	if m.byCommitFn == nil {
		return port.CompletedReport{}, port.ErrNotFound
	}
	return m.byCommitFn(ctx, projectID, scanner, commit)
}

func (m *mockReportRepo) CountStaleReports(ctx context.Context, cutoff time.Time) (int64, error) {
	if m.countStaleFn == nil {
		return 0, fmt.Errorf("unexpected call to CountStaleReports")
	}
	return m.countStaleFn(ctx, cutoff)
}

func (m *mockReportRepo) DeleteStaleReports(ctx context.Context, cutoff time.Time) ([]string, error) {
	if m.deleteStaleFn == nil {
		return nil, fmt.Errorf("unexpected call to DeleteStaleReports")
	}
	return m.deleteStaleFn(ctx, cutoff)
}

func (m *mockReportRepo) FindCompletedByHash(ctx context.Context, projectID, rawHash string) (string, error) {
	if m.findCompletedByHashFn == nil {
		return "", port.ErrNotFound
	}
	return m.findCompletedByHashFn(ctx, projectID, rawHash)
}

func (m *mockReportRepo) DeleteReport(ctx context.Context, id, projectID string) error {
	if m.deleteReportFn == nil {
		return fmt.Errorf("unexpected call to DeleteReport")
	}
	return m.deleteReportFn(ctx, id, projectID)
}

type mockPolicyRepo struct {
	port.PolicyStore
	createFn     func(context.Context, port.PolicyTemplateInput) (port.PolicyTemplate, error)
	getByIDFn    func(context.Context, string) (port.PolicyTemplate, error)
	getByNameFn  func(context.Context, string) (port.PolicyTemplate, error)
	listFn       func(context.Context) ([]port.PolicyTemplate, error)
	updateFn     func(context.Context, string, port.PolicyTemplateInput) (port.PolicyTemplate, error)
	deleteFn     func(context.Context, string) error
	setProjectFn func(context.Context, string, *string) (port.Project, error)
}

func (m *mockPolicyRepo) CreateTemplate(ctx context.Context, input port.PolicyTemplateInput) (port.PolicyTemplate, error) {
	if m.createFn == nil {
		return port.PolicyTemplate{}, fmt.Errorf("unexpected call to CreateTemplate")
	}
	return m.createFn(ctx, input)
}

func (m *mockPolicyRepo) GetTemplateByID(ctx context.Context, id string) (port.PolicyTemplate, error) {
	if m.getByIDFn == nil {
		return port.PolicyTemplate{}, fmt.Errorf("unexpected call to GetTemplateByID")
	}
	return m.getByIDFn(ctx, id)
}

func (m *mockPolicyRepo) GetTemplateByName(ctx context.Context, name string) (port.PolicyTemplate, error) {
	if m.getByNameFn == nil {
		return port.PolicyTemplate{}, fmt.Errorf("unexpected call to GetTemplateByName")
	}
	return m.getByNameFn(ctx, name)
}

func (m *mockPolicyRepo) ListTemplates(ctx context.Context) ([]port.PolicyTemplate, error) {
	if m.listFn == nil {
		return nil, fmt.Errorf("unexpected call to ListTemplates")
	}
	return m.listFn(ctx)
}

func (m *mockPolicyRepo) UpdateTemplate(ctx context.Context, id string, input port.PolicyTemplateInput) (port.PolicyTemplate, error) {
	if m.updateFn == nil {
		return port.PolicyTemplate{}, fmt.Errorf("unexpected call to UpdateTemplate")
	}
	return m.updateFn(ctx, id, input)
}

func (m *mockPolicyRepo) DeleteTemplate(ctx context.Context, id string) error {
	if m.deleteFn == nil {
		return fmt.Errorf("unexpected call to DeleteTemplate")
	}
	return m.deleteFn(ctx, id)
}

func (m *mockPolicyRepo) SetProjectTemplate(ctx context.Context, projectID string, templateID *string) (port.Project, error) {
	if m.setProjectFn == nil {
		return port.Project{}, fmt.Errorf("unexpected call to SetProjectTemplate")
	}
	return m.setProjectFn(ctx, projectID, templateID)
}

type mockAdminRepo struct {
	port.AdminStore
	overviewFn func(context.Context) (port.AdminOverview, error)
}

func (m *mockAdminRepo) Overview(ctx context.Context) (port.AdminOverview, error) {
	if m.overviewFn == nil {
		return port.AdminOverview{}, fmt.Errorf("unexpected call to Overview")
	}
	return m.overviewFn(ctx)
}

type mockFindingRepo struct {
	port.FindingStore
	hasOccurrenceFn                   func(context.Context, string, string) (bool, error)
	markFixedFn                       func(context.Context, string) (port.Finding, error)
	createOccurrenceFn                func(context.Context, port.OccurrenceInput) (port.Occurrence, error)
	upsertDimensionFn                 func(context.Context, port.DimensionInput) error
	listByProjectFn                   func(context.Context, string, port.ListFindingsParams) ([]port.Finding, error)
	getDisplayContextFn               func(context.Context, string) (port.FindingDisplayContext, error)
	listFindingDisplayContextsByIDsFn func(context.Context, []string) ([]port.FindingDisplayContext, error)
	listDimensionsFn                  func(context.Context, string) ([]port.FindingDimension, error)
	upsertFn                          func(context.Context, port.UpsertFindingInput) (port.Finding, error)
	getByFingerprintFn                func(context.Context, string, string, string) (port.Finding, error)
	getByIDFn                         func(context.Context, string) (port.Finding, error)
	listByIDsFn                       func(context.Context, []string) ([]port.Finding, error)
	hasDimensionFn                    func(context.Context, string, string) (bool, error)
	updateAnalysisFn                  func(context.Context, port.UpdateAnalysisInput) (port.Finding, error)
	bulkUpdateAnalysisFn              func(context.Context, port.UpdateAnalysisInput, []string) ([]port.Finding, error)
	bulkTriageFn                      func(context.Context, port.UpdateAnalysisInput, []string, port.FindingEventInput) ([]port.Finding, error)
	createEventFn                     func(context.Context, port.FindingEventInput) (port.FindingEvent, error)
	listEventsFn                      func(context.Context, string, []string, int32, int32) ([]port.FindingEvent, error)
	listBlockingFindingsFn            func(context.Context, string, int16) ([]port.Finding, error)
	listGateCandidatesFn              func(context.Context, string, int16) ([]port.GateCandidate, error)
	listIntroducedGateCandidatesFn    func(context.Context, string, int16) ([]port.GateCandidate, error)
	listFindingsByFingerprintsFn      func(context.Context, string, string, []string) ([]port.Finding, error)
	listFindingIDsPresentInReportFn   func(context.Context, string, []string) ([]string, error)
	recordReportIntroducedFindingsFn  func(context.Context, string, *string, []port.IntroducedFindingEntry) error
	listFindingsIntroducedByCommitFn  func(context.Context, string, string) ([]port.Finding, error)
	getFindingContextFn               func(context.Context, string) (port.FindingContext, error)
	setIntroducedByFn                 func(context.Context, string, string, *string) (port.Finding, error)
	listIntroducedByFn                func(context.Context, string, string) ([]port.Finding, error)
	knownFpByID                       map[string]string
}

func (m *mockFindingRepo) Upsert(ctx context.Context, input port.UpsertFindingInput) (port.Finding, error) {
	if m.upsertFn == nil {
		return port.Finding{}, fmt.Errorf("unexpected call to Upsert")
	}
	return m.upsertFn(ctx, input)
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

func (m *mockFindingRepo) ListByProject(ctx context.Context, projectID string, params port.ListFindingsParams) ([]port.Finding, error) {
	if m.listByProjectFn == nil {
		return []port.Finding{}, nil
	}
	return m.listByProjectFn(ctx, projectID, params)
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

func (m *mockFindingRepo) BulkTriage(ctx context.Context, arg port.UpdateAnalysisInput, ids []string, event port.FindingEventInput) ([]port.Finding, error) {
	if m.bulkTriageFn != nil {
		return m.bulkTriageFn(ctx, arg, ids, event)
	}
	findings, err := m.BulkUpdateAnalysis(ctx, arg, ids)
	if err != nil {
		return nil, err
	}
	for _, f := range findings {
		ev := event
		ev.FindingID = f.ID
		if _, err := m.CreateEvent(ctx, ev); err != nil {
			return nil, err
		}
	}
	return findings, nil
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

func (m *mockFindingRepo) ListIntroducedGateCandidates(ctx context.Context, reportID string, minSeverityRank int16) ([]port.GateCandidate, error) {
	if m.listIntroducedGateCandidatesFn == nil {
		if m.listGateCandidatesFn != nil {
			all, err := m.listGateCandidatesFn(ctx, "", minSeverityRank)
			if err != nil {
				return nil, err
			}
			var res []port.GateCandidate
			for _, c := range all {
				if reportID == "" || c.IntroducedByReportID == nil || *c.IntroducedByReportID == reportID {
					res = append(res, c)
				}
			}
			return res, nil
		}
		return []port.GateCandidate{}, nil
	}
	return m.listIntroducedGateCandidatesFn(ctx, reportID, minSeverityRank)
}

func (m *mockFindingRepo) ListFindingsByFingerprints(ctx context.Context, projectID, findingKind string, fingerprints []string) ([]port.Finding, error) {
	if m.listFindingsByFingerprintsFn != nil {
		return m.listFindingsByFingerprintsFn(ctx, projectID, findingKind, fingerprints)
	}
	if m.getByFingerprintFn != nil {
		var res []port.Finding
		for _, fp := range fingerprints {
			f, err := m.getByFingerprintFn(ctx, projectID, findingKind, fp)
			if err == nil {
				f.Fingerprint = fp
				f.FindingKind = findingKind
				if m.knownFpByID == nil {
					m.knownFpByID = make(map[string]string)
				}
				m.knownFpByID[f.ID] = fp
				res = append(res, f)
			}
		}
		return res, nil
	}
	return nil, nil
}

func (m *mockFindingRepo) ListFindingIDsPresentInReport(ctx context.Context, reportID string, findingIDs []string) ([]string, error) {
	if m.listFindingIDsPresentInReportFn != nil {
		return m.listFindingIDsPresentInReportFn(ctx, reportID, findingIDs)
	}
	if m.hasOccurrenceFn == nil {
		return nil, nil
	}
	var res []string
	for _, fid := range findingIDs {
		if m.findingIDInReport(ctx, fid, reportID) {
			res = append(res, fid)
		}
	}
	return res, nil
}

// findingIDInReport probes the occurrence hook under the id variants the
// fixtures use: the raw id, the "finding-"+id synthetic id, and the known
// fingerprint mapping when present.
func (m *mockFindingRepo) findingIDInReport(ctx context.Context, fid, reportID string) bool {
	if has, err := m.hasOccurrenceFn(ctx, fid, reportID); err == nil && has {
		return true
	}
	if h, _ := m.hasOccurrenceFn(ctx, "finding-"+fid, reportID); h {
		return true
	}
	if fp, ok := m.knownFpByID[fid]; ok {
		if h, _ := m.hasOccurrenceFn(ctx, "finding-"+fp, reportID); h {
			return true
		}
	}
	return false
}

func (m *mockFindingRepo) RecordReportIntroducedFindings(ctx context.Context, reportID string, baselineReportID *string, entries []port.IntroducedFindingEntry) error {
	if m.recordReportIntroducedFindingsFn == nil {
		return nil
	}
	return m.recordReportIntroducedFindingsFn(ctx, reportID, baselineReportID, entries)
}

func (m *mockFindingRepo) ListFindingsIntroducedByCommit(ctx context.Context, projectID, commitSha string) ([]port.Finding, error) {
	if m.listFindingsIntroducedByCommitFn == nil {
		return nil, nil
	}
	return m.listFindingsIntroducedByCommitFn(ctx, projectID, commitSha)
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

func (m *mockFindingRepo) ListFindingDisplayContextsByIDs(ctx context.Context, findingIDs []string) ([]port.FindingDisplayContext, error) {
	if m.listFindingDisplayContextsByIDsFn != nil {
		return m.listFindingDisplayContextsByIDsFn(ctx, findingIDs)
	}
	if m.getDisplayContextFn != nil {
		var out []port.FindingDisplayContext
		for _, id := range findingIDs {
			dc, err := m.getDisplayContextFn(ctx, id)
			if err == nil {
				dc.FindingID = id
				out = append(out, dc)
			}
		}
		return out, nil
	}
	return []port.FindingDisplayContext{}, nil
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

func (m *mockFindingRepo) SetFindingIntroducedBy(ctx context.Context, findingID, reportID string, commitSha *string) (port.Finding, error) {
	if m.setIntroducedByFn == nil {
		return port.Finding{ID: findingID}, nil
	}
	return m.setIntroducedByFn(ctx, findingID, reportID, commitSha)
}

func (m *mockFindingRepo) ListIntroducedByReport(ctx context.Context, projectID, reportID string) ([]port.Finding, error) {
	if m.listIntroducedByFn == nil {
		return nil, fmt.Errorf("unexpected call to ListIntroducedByReport")
	}
	return m.listIntroducedByFn(ctx, projectID, reportID)
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
	createFn            func(context.Context, string, *string, *string) (port.User, error)
	getByEmailFn        func(context.Context, string) (port.User, error)
	getByIDFn           func(context.Context, string) (port.User, error)
	updateDisplayNameFn func(context.Context, string, *string) (port.User, error)
	setRoleFn           func(context.Context, string, string) (port.User, error)
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

func (m *mockUserRepo) UpdateDisplayName(ctx context.Context, userID string, displayName *string) (port.User, error) {
	if m.updateDisplayNameFn == nil {
		return port.User{}, fmt.Errorf("unexpected call to UpdateDisplayName")
	}
	return m.updateDisplayNameFn(ctx, userID, displayName)
}

func (m *mockUserRepo) SetRole(ctx context.Context, userID, role string) (port.User, error) {
	if m.setRoleFn == nil {
		return port.User{}, fmt.Errorf("unexpected call to SetRole")
	}
	return m.setRoleFn(ctx, userID, role)
}

type mockRefreshTokenRepo struct {
	port.RefreshTokenStore
	createFn    func(context.Context, string, string, time.Time) (port.RefreshToken, error)
	getByHashFn func(context.Context, string) (port.RefreshToken, error)
	revokeFn    func(context.Context, string) (port.RefreshToken, error)
	revokeAllFn func(context.Context, string) error
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

func (m *mockRefreshTokenRepo) RevokeAllForUser(ctx context.Context, userID string) error {
	if m.revokeAllFn == nil {
		return fmt.Errorf("unexpected call to RevokeAllForUser")
	}
	return m.revokeAllFn(ctx, userID)
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
	createWithDetailsFn             func(context.Context, port.CreateWaiverInput) (port.Waiver, error)
	listFn                          func(context.Context, string) ([]port.Waiver, error)
	getByIDFn                       func(context.Context, string, string) (port.Waiver, error)
	updateWithDetailsFn             func(context.Context, port.Waiver, *[]port.WaiverCondition, *[]port.WaiverContext, *[]port.WaiverFindingTarget, port.WaiverEventInput) (port.Waiver, error)
	deleteFn                        func(context.Context, string, string) error
	toggleWithEventFn               func(context.Context, string, string, string) (port.Waiver, error)
	listActiveFn                    func(context.Context, string) ([]port.Waiver, error)
	listConditionsFn                func(context.Context, string) ([]port.WaiverCondition, error)
	listContextsFn                  func(context.Context, string) ([]port.WaiverContext, error)
	listFindingTargetsFn            func(context.Context, string) ([]port.WaiverFindingTarget, error)
	listConditionsByWaiverIDsFn     func(context.Context, []string) ([]port.WaiverCondition, error)
	listContextsByWaiverIDsFn       func(context.Context, []string) ([]port.WaiverContext, error)
	listFindingTargetsByWaiverIDsFn func(context.Context, []string) ([]port.WaiverFindingTarget, error)
	listEventsFn                    func(context.Context, string) ([]port.WaiverEvent, error)
}

func (m *mockWaiverRepo) CreateWithDetails(ctx context.Context, input port.CreateWaiverInput) (port.Waiver, error) {
	if m.createWithDetailsFn == nil {
		return port.Waiver{}, fmt.Errorf("unexpected call to CreateWithDetails")
	}
	return m.createWithDetailsFn(ctx, input)
}

func (m *mockWaiverRepo) List(ctx context.Context, projectID string) ([]port.Waiver, error) {
	if m.listFn == nil {
		return nil, fmt.Errorf("unexpected call to List")
	}
	return m.listFn(ctx, projectID)
}

func (m *mockWaiverRepo) GetByID(ctx context.Context, id, projectID string) (port.Waiver, error) {
	if m.getByIDFn == nil {
		return port.Waiver{}, fmt.Errorf("unexpected call to GetByID")
	}
	return m.getByIDFn(ctx, id, projectID)
}

func (m *mockWaiverRepo) UpdateWithDetails(ctx context.Context, waiver port.Waiver, conditions *[]port.WaiverCondition, contexts *[]port.WaiverContext, targets *[]port.WaiverFindingTarget, event port.WaiverEventInput) (port.Waiver, error) {
	if m.updateWithDetailsFn == nil {
		return port.Waiver{}, fmt.Errorf("unexpected call to UpdateWithDetails")
	}
	return m.updateWithDetailsFn(ctx, waiver, conditions, contexts, targets, event)
}

func (m *mockWaiverRepo) Delete(ctx context.Context, id, projectID string) error {
	if m.deleteFn == nil {
		return fmt.Errorf("unexpected call to Delete")
	}
	return m.deleteFn(ctx, id, projectID)
}

func (m *mockWaiverRepo) ListEvents(ctx context.Context, waiverID string) ([]port.WaiverEvent, error) {
	if m.listEventsFn == nil {
		return nil, fmt.Errorf("unexpected call to ListEvents")
	}
	return m.listEventsFn(ctx, waiverID)
}

func (m *mockWaiverRepo) ToggleWithEvent(ctx context.Context, id, projectID, actorID string) (port.Waiver, error) {
	if m.toggleWithEventFn == nil {
		return port.Waiver{}, fmt.Errorf("unexpected call to ToggleWithEvent")
	}
	return m.toggleWithEventFn(ctx, id, projectID, actorID)
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

func (m *mockWaiverRepo) ListConditionsByWaiverIDs(ctx context.Context, waiverIDs []string) ([]port.WaiverCondition, error) {
	if m.listConditionsByWaiverIDsFn != nil {
		return m.listConditionsByWaiverIDsFn(ctx, waiverIDs)
	}
	if m.listConditionsFn != nil {
		var out []port.WaiverCondition
		for _, wid := range waiverIDs {
			conds, err := m.listConditionsFn(ctx, wid)
			if err != nil {
				return nil, err
			}
			for _, c := range conds {
				c.WaiverID = wid
				out = append(out, c)
			}
		}
		return out, nil
	}
	return []port.WaiverCondition{}, nil
}

func (m *mockWaiverRepo) ListContexts(ctx context.Context, waiverID string) ([]port.WaiverContext, error) {
	if m.listContextsFn == nil {
		return []port.WaiverContext{}, nil
	}
	return m.listContextsFn(ctx, waiverID)
}

func (m *mockWaiverRepo) ListContextsByWaiverIDs(ctx context.Context, waiverIDs []string) ([]port.WaiverContext, error) {
	if m.listContextsByWaiverIDsFn != nil {
		return m.listContextsByWaiverIDsFn(ctx, waiverIDs)
	}
	if m.listContextsFn != nil {
		var out []port.WaiverContext
		for _, wid := range waiverIDs {
			contexts, err := m.listContextsFn(ctx, wid)
			if err != nil {
				return nil, err
			}
			for _, c := range contexts {
				c.WaiverID = wid
				out = append(out, c)
			}
		}
		return out, nil
	}
	return []port.WaiverContext{}, nil
}

func (m *mockWaiverRepo) ListFindingTargets(ctx context.Context, waiverID string) ([]port.WaiverFindingTarget, error) {
	if m.listFindingTargetsFn == nil {
		return []port.WaiverFindingTarget{}, nil
	}
	return m.listFindingTargetsFn(ctx, waiverID)
}

func (m *mockWaiverRepo) ListFindingTargetsByWaiverIDs(ctx context.Context, waiverIDs []string) ([]port.WaiverFindingTarget, error) {
	if m.listFindingTargetsByWaiverIDsFn != nil {
		return m.listFindingTargetsByWaiverIDsFn(ctx, waiverIDs)
	}
	if m.listFindingTargetsFn != nil {
		var out []port.WaiverFindingTarget
		for _, wid := range waiverIDs {
			targets, err := m.listFindingTargetsFn(ctx, wid)
			if err != nil {
				return nil, err
			}
			for _, t := range targets {
				t.WaiverID = wid
				out = append(out, t)
			}
		}
		return out, nil
	}
	return []port.WaiverFindingTarget{}, nil
}

type mockScanner struct {
	name        string
	parseFn     func(context.Context, []byte) (*domain.NormalizedReport, error)
	incremental bool
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
func (m *mockScanner) SupportsIncremental() bool     { return m.incremental }
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

// memberProjects returns a project store mock reporting the caller as a
// member of every project, for tests exercising membership-gated paths
// where membership itself is not under test.
func memberProjects() *mockProjectRepo {
	pr := &mockProjectRepo{}
	pr.isMemberFn = func(ctx context.Context, projectID, userID string) (bool, error) {
		return true, nil
	}
	return pr
}

func makeTestRepos() (*mockProjectRepo, *mockReportRepo, *mockFindingRepo) {
	pr := &mockProjectRepo{}
	pr.isMemberFn = func(ctx context.Context, projectID, userID string) (bool, error) {
		return true, nil
	}
	return pr, &mockReportRepo{}, &mockFindingRepo{}
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
	var gotRole string
	pr.upsertMemberFn = func(ctx context.Context, projectID, userID, role string) (port.ProjectMember, error) {
		gotRole = role
		return port.ProjectMember{ProjectID: projectID, UserID: userID, Role: role}, nil
	}

	uc := New(Deps{
		Stores: &port.Stores{Projects: pr},
	})

	result, err := uc.CreateProject(sessionCtx("creator-1", auth.RoleAdmin), "My App", "my-app", "test description", "creator-1")
	require.NoError(t, err)
	require.NotNil(t, result)
	assert.Equal(t, "my-app", result.Slug)
	assert.Equal(t, "My App", result.Name)
	assert.Equal(t, auth.RoleAdmin, gotRole, "project creator must become admin member")
}

func TestCreateProject_APIKeyCannotCreatePlatformProject(t *testing.T) {
	pr, _, _ := makeTestRepos()
	uc := New(Deps{Stores: &port.Stores{Projects: pr}})

	_, err := uc.CreateProject(apiKeyCtx("key-1", findingFixtureProjectID), "My App", "my-app", "description", "key-1")
	require.ErrorIs(t, err, ErrProjectAccessDenied)
}

func TestCreateProject_MembershipFailureRollsBack(t *testing.T) {
	pr, _, _ := makeTestRepos()

	pr.createFn = func(ctx context.Context, arg port.CreateProjectInput) (port.Project, error) {
		return makeProject(true), nil
	}
	pr.upsertMemberFn = func(ctx context.Context, projectID, userID, role string) (port.ProjectMember, error) {
		return port.ProjectMember{}, fmt.Errorf("db unavailable")
	}
	var gotDeleteSlug string
	pr.deleteFn = func(ctx context.Context, slug string) (port.Project, error) {
		gotDeleteSlug = slug
		return makeProject(true), nil
	}

	uc := New(Deps{
		Stores: &port.Stores{Projects: pr},
	})

	_, err := uc.CreateProject(sessionCtx("creator-1", auth.RoleAdmin), "My App", "my-app", "test description", "creator-1")
	require.Error(t, err)
	assert.ErrorContains(t, err, "grant creator admin membership")
	assert.Equal(t, "my-app", gotDeleteSlug, "orphaned project must be removed when admin grant fails")
}

func TestIngestReport_ProjectViewerCannotIngest(t *testing.T) {
	pr := &mockProjectRepo{}
	pr.getBySlugFn = func(ctx context.Context, slug string) (port.Project, error) {
		return makeProject(true), nil
	}
	pr.effectiveRoleFn = func(ctx context.Context, projectID, userID string) (string, error) {
		return auth.RoleViewer, nil
	}
	uc := New(Deps{Stores: &port.Stores{Projects: pr}})

	result, err := uc.IngestReport(sessionCtx("viewer", auth.RoleViewer), IngestReportInput{
		ProjectSlug: "my-app", Scanner: "trivy", RawData: []byte(`{"Results":[]}`),
	})
	assert.ErrorIs(t, err, ErrProjectAccessDenied)
	assert.Nil(t, result)
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
	fr.upsertFn = func(ctx context.Context, in port.UpsertFindingInput) (port.Finding, error) {
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

	fr.upsertFn = func(ctx context.Context, in port.UpsertFindingInput) (port.Finding, error) {
		return makeFinding(1), nil
	}

	fr.createOccurrenceFn = func(ctx context.Context, arg port.OccurrenceInput) (port.Occurrence, error) {
		return port.Occurrence{}, nil
	}

	fr.upsertDimensionFn = func(ctx context.Context, arg port.DimensionInput) error {
		return nil
	}

	fr.listByProjectFn = func(ctx context.Context, projectID string, params port.ListFindingsParams) ([]port.Finding, error) {
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
	fr.upsertFn = func(ctx context.Context, in port.UpsertFindingInput) (port.Finding, error) {
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
	fr.upsertFn = func(ctx context.Context, in port.UpsertFindingInput) (port.Finding, error) {
		return makeFinding(1), nil
	}
	fr.createOccurrenceFn = func(ctx context.Context, arg port.OccurrenceInput) (port.Occurrence, error) {
		return port.Occurrence{}, nil
	}
	fr.upsertDimensionFn = func(ctx context.Context, arg port.DimensionInput) error {
		return nil
	}

	var failedStatus string
	var failedError *string
	rr.updateStatusFn = func(ctx context.Context, id, projectID string, status string, totalFindings int32, errorMsg *string) (port.Report, error) {
		failedStatus = status
		failedError = errorMsg
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
	assert.Equal(t, "failed", failedStatus, "a failed inventory batch must mark the report failed, not leave it processing")
	require.NotNil(t, failedError, "a failed report must record why it failed")
	assert.Contains(t, *failedError, "persist package inventory")
}

func TestIngestReport_FindingsFailureMarksReportFailed(t *testing.T) {
	pr, rr, fr := makeTestRepos()

	pr.getBySlugFn = func(ctx context.Context, slug string) (port.Project, error) {
		return makeProject(true), nil
	}

	rr.createFn = func(ctx context.Context, arg port.CreateReportInput) (port.Report, error) {
		r := makeReport()
		r.Status = "processing"
		return r, nil
	}

	var updateCalls []string
	rr.updateStatusFn = func(ctx context.Context, id, projectID string, status string, totalFindings int32, errorMsg *string) (port.Report, error) {
		updateCalls = append(updateCalls, status)
		r := makeReport()
		r.Status = status
		return r, nil
	}

	fr.getByFingerprintFn = func(ctx context.Context, projectID, findingKind, fingerprint string) (port.Finding, error) {
		return port.Finding{}, port.ErrNotFound
	}
	fr.upsertFn = func(ctx context.Context, in port.UpsertFindingInput) (port.Finding, error) {
		// Second finding fails to persist: the report row was already
		// created with status 'processing'.
		return port.Finding{}, fmt.Errorf("db unavailable")
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
	assert.ErrorContains(t, err, "upsert finding")
	assert.Equal(t, []string{"failed"}, updateCalls,
		"a findings-persistence failure must mark the report failed exactly once, never completed")
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

func TestRegister_InvalidEmail(t *testing.T) {
	uc := New(Deps{})
	for _, invalid := range []string{"not-an-email", "missingat.com", "@missinglocal.com", "spaces in@email.com"} {
		_, err := uc.Register(context.Background(), invalid, "password123")
		assert.EqualError(t, err, "invalid email address", "expected %q to be rejected", invalid)
	}
}

func TestRegister_EmailNormalized(t *testing.T) {
	ur := &mockUserRepo{}
	var createdEmail string
	ur.getByEmailFn = func(ctx context.Context, email string) (port.User, error) {
		return port.User{}, port.ErrNotFound
	}
	ur.createFn = func(ctx context.Context, email string, displayName, passwordHash *string) (port.User, error) {
		createdEmail = email
		u := makeUser("00000000-0000-0000-0000-000000000041")
		u.Email = email
		return u, nil
	}
	rr := &mockRefreshTokenRepo{
		createFn: func(ctx context.Context, userID string, tokenHash string, expiresAt time.Time) (port.RefreshToken, error) {
			return makeRefreshToken(false), nil
		},
	}
	uc := New(Deps{
		Stores:    &port.Stores{Users: ur, RefreshTokens: rr},
		Tokens:    testJWT(t),
		Passwords: auth.NewPasswordHasher(),
	})

	resp, err := uc.Register(context.Background(), "MixedCase@Example.COM", "password123")
	require.NoError(t, err)
	assert.Equal(t, "mixedcase@example.com", resp.Email)
	assert.Equal(t, "mixedcase@example.com", createdEmail)
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
	require.Error(t, err)
	// M8: a duplicate email must fail with the generic registration error so
	// the endpoint cannot be used to enumerate registered accounts.
	assert.ErrorIs(t, err, ErrRegistrationFailed)
	assert.EqualError(t, err, "registration failed")
	assert.NotContains(t, err.Error(), "already registered")
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

// TestLogin_DBMemberRoleMapsToViewerClaim guards the role vocabulary seam
// between the users table and the JWT. The DB CHECK allows only
// ('admin', 'member') for users.role and self-registration always creates
// 'member'; the JWT/RBAC vocabulary is admin/editor/viewer. Embedding the
// DB role verbatim in a token mints "member" claims that no RequireRole
// allowlist recognizes, so a freshly registered user could never pass any
// role gate (and, worse, "member" sailed past gates that did not name it).
// Login must translate the legacy DB role to the canonical token role.
func TestLogin_DBMemberRoleMapsToViewerClaim(t *testing.T) {
	ur := &mockUserRepo{}
	rr := &mockRefreshTokenRepo{}
	jwt := testJWT(t)

	hash, err := auth.HashPassword("correct-password")
	require.NoError(t, err)

	ur.getByEmailFn = func(ctx context.Context, email string) (port.User, error) {
		u := makeUser("00000000-0000-0000-0000-000000000040")
		u.Role = "member" // DB CHECK ('admin','member') legacy role
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
	assert.NotEmpty(t, resp.Token)

	ident, err := jwt.Authenticate(context.Background(), resp.Token)
	require.NoError(t, err)
	assert.Equal(t, auth.RoleViewer, ident.Role, "legacy DB role 'member' must map to canonical viewer claim")
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
	var allRevoked bool
	rr.getByHashFn = func(ctx context.Context, tokenHash string) (port.RefreshToken, error) {
		return makeRefreshToken(true), nil
	}
	rr.revokeAllFn = func(ctx context.Context, userID string) error {
		allRevoked = true
		return nil
	}

	uc := New(Deps{
		Stores: &port.Stores{RefreshTokens: rr},
	})

	_, err := uc.Refresh(context.Background(), "revoked-token")
	assert.EqualError(t, err, "refresh token has been revoked")
	assert.True(t, allRevoked, "a revoked-token replay is reuse: the user's whole token family must be revoked")
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

// simulateAtomicRevoke drives a mock that behaves like the guarded SQL
// revoke-then-issue primitive: Revoke succeeds exactly once and fails with
// port.ErrNotFound on every later attempt (as the atomic UPDATE ... WHERE
// revoked_at IS NULL RETURNING does via pgx.ErrNoRows). The reuse flag
// records whether the second path was entered.
func simulateAtomicRevoke(rr *mockRefreshTokenRepo, userID string) *bool {
	reuse := new(bool)
	var mu sync.Mutex
	revoked := false
	rr.revokeFn = func(ctx context.Context, id string) (port.RefreshToken, error) {
		mu.Lock()
		defer mu.Unlock()
		if revoked {
			return port.RefreshToken{}, port.ErrNotFound
		}
		revoked = true
		return makeRefreshToken(true), nil
	}
	rr.revokeAllFn = func(ctx context.Context, uid string) error {
		mu.Lock()
		defer mu.Unlock()
		*reuse = true
		return nil
	}
	rr.createFn = func(ctx context.Context, userID string, tokenHash string, expiresAt time.Time) (port.RefreshToken, error) {
		return makeRefreshToken(false), nil
	}
	return reuse
}

// TestRefresh_SecondUseFails pins the reuse-detection contract: a refresh
// token must be usable exactly once. After a first successful rotation the
// token is revoked, and any later attempt with the same token must fail even
// though the row still exists (reuse of a stolen token is how an attacker is
// detected and the user's whole session family is invalidated).
func TestRefresh_SecondUseFails(t *testing.T) {
	ur := &mockUserRepo{}
	rr := &mockRefreshTokenRepo{}
	jwt := testJWT(t)

	token := makeRefreshToken(false)
	rr.getByHashFn = func(ctx context.Context, tokenHash string) (port.RefreshToken, error) {
		if token.RevokedAt != nil {
			return port.RefreshToken{}, port.ErrNotFound
		}
		return token, nil
	}
	reuse := simulateAtomicRevoke(rr, token.UserID)
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

	// The row is now revoked, so a second refresh with the same token is a
	// replay of a rotated token: it must fail, not mint another session.
	_, err = uc.Refresh(context.Background(), "some-valid-refresh-token")
	require.Error(t, err)
	assert.True(t, *reuse, "reuse of a rotated token must revoke all of the user's tokens")
}

// TestRefresh_ConcurrentOnlyOneSucceeds pins the atomicity contract: two
// racing refreshes with the same token must produce exactly one success and
// one failure. The revoke must behave as a single atomic compare-and-set on
// the token row; both requests must never mint sessions.
func TestRefresh_ConcurrentOnlyOneSucceeds(t *testing.T) {
	ur := &mockUserRepo{}
	rr := &mockRefreshTokenRepo{}
	jwt := testJWT(t)

	token := makeRefreshToken(false)
	rr.getByHashFn = func(ctx context.Context, tokenHash string) (port.RefreshToken, error) {
		return token, nil
	}
	reuse := simulateAtomicRevoke(rr, token.UserID)
	ur.getByIDFn = func(ctx context.Context, id string) (port.User, error) {
		return makeUser("00000000-0000-0000-0000-000000000040"), nil
	}

	uc := New(Deps{
		Stores:    &port.Stores{RefreshTokens: rr, Users: ur},
		Tokens:    jwt,
		Passwords: auth.NewPasswordHasher(),
	})

	const n = 8
	var wg sync.WaitGroup
	errs := make([]error, n)
	results := make([]*AuthResponse, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			results[i], errs[i] = uc.Refresh(context.Background(), "some-valid-refresh-token")
		}(i)
	}
	wg.Wait()

	successes := 0
	for i := 0; i < n; i++ {
		if results[i] != nil && errs[i] == nil {
			successes++
		} else if errs[i] == nil {
			t.Fatalf("goroutine %d returned a nil response with no error", i)
		}
	}
	assert.Equal(t, 1, successes, "exactly one concurrent refresh may succeed")
	// The losers raced a token that was already rotated: that is reuse, so
	// the whole token family for the user must be revoked, not just the one
	// row. Pre-fix the losers fail on a raw revoke error and never revoke
	// the family.
	assert.True(t, *reuse, "concurrent losers must be treated as reuse and revoke all of the user's tokens")
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

func TestUpdateProfile_Success(t *testing.T) {
	ur := &mockUserRepo{}
	ur.updateDisplayNameFn = func(ctx context.Context, userID string, displayName *string) (port.User, error) {
		u := makeUser("00000000-0000-0000-0000-000000000040")
		u.DisplayName = displayName
		return u, nil
	}

	uc := New(Deps{
		Stores: &port.Stores{Users: ur},
	})

	name := "Alice"
	profile, err := uc.UpdateProfile(context.Background(), "00000000-0000-0000-0000-000000000040", &name)
	require.NoError(t, err)
	require.NotNil(t, profile)
	assert.Equal(t, "Alice", profile.DisplayName)
}

func TestUpdateProfile_InvalidUUID(t *testing.T) {
	uc := New(Deps{})
	_, err := uc.UpdateProfile(context.Background(), "not-a-uuid", nil)
	assert.ErrorContains(t, err, "invalid user id")
}

func TestUpdateProfile_UserNotFound(t *testing.T) {
	ur := &mockUserRepo{}
	ur.updateDisplayNameFn = func(ctx context.Context, userID string, displayName *string) (port.User, error) {
		return port.User{}, port.ErrNotFound
	}

	uc := New(Deps{
		Stores: &port.Stores{Users: ur},
	})

	_, err := uc.UpdateProfile(context.Background(), "00000000-0000-0000-0000-000000000001", nil)
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
		Stores: &port.Stores{Findings: fr, Projects: memberProjects()},
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
	fr.listByProjectFn = func(ctx context.Context, projectID string, params port.ListFindingsParams) ([]port.Finding, error) {
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

	projects, err := uc.ListProjects(sessionCtx("admin-1", auth.RoleAdmin))
	require.NoError(t, err)
	assert.Len(t, projects, 1)
	assert.Equal(t, "my-app", projects[0].Slug)
}

func TestListProjects_MemberBatchLookup(t *testing.T) {
	pr := &mockProjectRepo{}
	pr.listFn = func(ctx context.Context) ([]port.Project, error) {
		return []port.Project{
			{ID: "00000000-0000-0000-0000-000000000001", Slug: "mine", Name: "Mine"},
			{ID: "00000000-0000-0000-0000-000000000002", Slug: "theirs", Name: "Theirs"},
		}, nil
	}
	calls := 0
	pr.listMemberIDsFn = func(ctx context.Context, userID string) ([]string, error) {
		calls++
		assert.Equal(t, "u1", userID)
		return []string{"00000000-0000-0000-0000-000000000001"}, nil
	}
	// isMemberFn intentionally nil: any per-project lookup fails the test.

	uc := New(Deps{
		Stores: &port.Stores{Projects: pr},
	})

	projects, err := uc.ListProjects(sessionCtx("u1", auth.RoleViewer))
	require.NoError(t, err)
	require.Len(t, projects, 1)
	assert.Equal(t, "mine", projects[0].Slug)
	assert.Equal(t, 1, calls, "membership must resolve in a single batched query")
}

// ----- GetProject Tests -----

func TestGetProject_Success(t *testing.T) {
	pr := &mockProjectRepo{}
	pr.getBySlugFn = func(ctx context.Context, slug string) (port.Project, error) {
		return makeProject(true), nil
	}
	pr.isMemberFn = func(ctx context.Context, projectID, userID string) (bool, error) {
		return true, nil
	}

	uc := New(Deps{
		Stores: &port.Stores{Projects: pr},
	})

	proj, err := uc.GetProject(sessionCtx("u1", auth.RoleViewer), "my-app")
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
		Stores: &port.Stores{Reports: rr, Projects: memberProjects()},
	})

	report, err := uc.GetReport(findingScopeCtx(findingFixtureProjectID), "00000000-0000-0000-0000-000000000001")
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

// makeReport belongs to findingFixtureProjectID (project A); the API-key
// identities below are scoped like the other project-access tests.
func TestGetReport_APIKeyCrossProjectDenied(t *testing.T) {
	report := makeReport()
	rr := &mockReportRepo{}
	rr.getByIDFn = func(ctx context.Context, id string) (port.Report, error) {
		return report, nil
	}

	uc := New(Deps{
		Stores: &port.Stores{Reports: rr},
	})
	ctx := auth.ContextWithIdentity(context.Background(), &auth.Identity{
		UserID:    "00000000-0000-0000-0000-000000000040",
		ProjectID: "00000000-0000-0000-0000-000000000002", // API key scoped to project B
		IsAPIKey:  true,
	})

	// An API key scoped to project B must not read a report owned by
	// project A (findingFixtureProjectID).
	_, err := uc.GetReport(ctx, report.ID)
	require.ErrorIs(t, err, ErrProjectAccessDenied)
}

func TestGetReport_APIKeySameProjectAllowed(t *testing.T) {
	report := makeReport()
	rr := &mockReportRepo{}
	rr.getByIDFn = func(ctx context.Context, id string) (port.Report, error) {
		return report, nil
	}

	uc := New(Deps{
		Stores: &port.Stores{Reports: rr},
	})
	ctx := auth.ContextWithIdentity(context.Background(), &auth.Identity{
		UserID:    "00000000-0000-0000-0000-000000000040",
		ProjectID: findingFixtureProjectID, // API key scoped to the report's project A
		IsAPIKey:  true,
	})

	resp, err := uc.GetReport(ctx, report.ID)
	require.NoError(t, err)
	require.NotNil(t, resp)
	assert.Equal(t, "trivy", resp.ToolName)
}

// ----- CreateAPIKey Tests -----

func TestCreateAPIKey_Success(t *testing.T) {
	pr := &mockProjectRepo{}
	akr := &mockAPIKeyRepo{}

	pr.getBySlugFn = func(ctx context.Context, slug string) (port.Project, error) {
		return makeProject(true), nil
	}
	var storedKey port.CreateAPIKeyInput
	akr.createFn = func(ctx context.Context, arg port.CreateAPIKeyInput) (port.APIKey, error) {
		storedKey = arg
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

	resp, err := uc.CreateAPIKey(context.Background(), "my-app", "ci-key", "00000000-0000-0000-0000-000000000001", nil)
	require.NoError(t, err)
	require.NotNil(t, resp)
	assert.Equal(t, "ci-key", resp.Name)
	require.Len(t, resp.RawKey, len("vuln_")+64)
	assert.Equal(t, "vuln_", resp.RawKey[:len("vuln_")])
	keySuffix := resp.RawKey[len("vuln_"):]
	_, err = hex.DecodeString(keySuffix)
	require.NoError(t, err, "the secret suffix must be hexadecimal key material")
	assert.Equal(t, strings.ToLower(keySuffix), keySuffix)
	keyHash := sha256.Sum256([]byte(resp.RawKey))
	assert.Equal(t, hex.EncodeToString(keyHash[:]), storedKey.KeyHash, "only the hash of the one-time raw key is persisted")
	assert.Equal(t, resp.RawKey[:12], storedKey.KeyPrefix)
	assert.Equal(t, storedKey.KeyPrefix, resp.KeyPrefix)
	assert.Equal(t, resp.RawKey[len(resp.RawKey)-4:], storedKey.LastFour)
	require.NotNil(t, resp.LastFour)
	assert.Equal(t, storedKey.LastFour, *resp.LastFour)
	assert.JSONEq(t, `["ingest","read"]`, string(storedKey.Scopes), "a CI key must both ingest and read back its own gate")
	assert.Nil(t, resp.ExpiresAt, "no expiry requested means no expires_at in the response")
}

func TestCreateAPIKey_ExpiresAtRoundTrip(t *testing.T) {
	pr := &mockProjectRepo{}
	akr := &mockAPIKeyRepo{}
	expiry := time.Date(2030, 6, 30, 12, 0, 0, 0, time.UTC)
	var gotExpiry *time.Time

	pr.getBySlugFn = func(ctx context.Context, slug string) (port.Project, error) {
		return makeProject(true), nil
	}
	akr.createFn = func(ctx context.Context, arg port.CreateAPIKeyInput) (port.APIKey, error) {
		gotExpiry = arg.ExpiresAt
		return port.APIKey{
			ID:        "00000000-0000-0000-0000-000000000050",
			Name:      arg.Name,
			KeyPrefix: arg.KeyPrefix,
			LastFour:  new(arg.LastFour),
			ProjectID: arg.ProjectID,
			CreatedBy: new(arg.CreatedBy),
			CreatedAt: time.Now(),
			ExpiresAt: arg.ExpiresAt,
		}, nil
	}

	uc := New(Deps{
		Stores: &port.Stores{Projects: pr, APIKeys: akr},
	})

	resp, err := uc.CreateAPIKey(context.Background(), "my-app", "ci-key", "00000000-0000-0000-0000-000000000001", &expiry)
	require.NoError(t, err)
	require.NotNil(t, gotExpiry, "expiry must be forwarded to the store")
	assert.True(t, gotExpiry.Equal(expiry), "store must receive the requested expiry")
	require.NotNil(t, resp.ExpiresAt, "expires_at must be present in the response")
	assert.Equal(t, expiry.Format(time.RFC3339), *resp.ExpiresAt)
}

func TestCreateAPIKey_ProjectNotFound(t *testing.T) {
	pr := &mockProjectRepo{}
	pr.getBySlugFn = func(ctx context.Context, slug string) (port.Project, error) {
		return port.Project{}, port.ErrNotFound
	}

	uc := New(Deps{
		Stores: &port.Stores{Projects: pr},
	})

	_, err := uc.CreateAPIKey(context.Background(), "nonexistent", "ci-key", "00000000-0000-0000-0000-000000000001", nil)
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
	assert.Empty(t, keys[0].RawKey, "listing keys must never reveal the one-time secret")
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
		Stores: &port.Stores{Findings: fr, Projects: memberProjects()},
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
		Stores: &port.Stores{Findings: fr, Projects: memberProjects()},
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
		Stores: &port.Stores{Findings: fr, Projects: memberProjects()},
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
		Stores: &port.Stores{Findings: fr, Projects: memberProjects()},
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
		Stores: &port.Stores{Findings: fr, Projects: memberProjects()},
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
	uc := New(Deps{Stores: &port.Stores{Findings: fr, Reachability: rch, Projects: memberProjects()}})

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
	storeErr := fmt.Errorf("missing finding")
	fr.getByIDFn = func(ctx context.Context, id string) (port.Finding, error) {
		findingLookups++
		return port.Finding{}, storeErr
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

	// A persistence error from the store must propagate (surfacing as a 500
	// at the handler layer), not be masked as a not-found.
	_, err := uc.ListReachability(ctx, findingID)
	require.ErrorIs(t, err, storeErr)
	require.NotErrorIs(t, err, ErrFindingNotFound)

	_, err = uc.UpsertReachability(ctx, findingID, "00000000-0000-0000-0000-000000000002", "unknown", "")
	require.ErrorIs(t, err, storeErr)
	require.NotErrorIs(t, err, ErrFindingNotFound)
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
	_, err := uc.CreateAPIKey(context.Background(), "my-app", "ci-key", "00000000-0000-0000-0000-000000000001", nil)
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
	fr.upsertFn = func(ctx context.Context, in port.UpsertFindingInput) (port.Finding, error) {
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
	fr.upsertFn = func(ctx context.Context, in port.UpsertFindingInput) (port.Finding, error) {
		upsertedSeverity = in.Severity
		return port.Finding{
			ID: "find-1", ProjectID: in.ProjectID, FindingKind: in.FindingKind,
			Fingerprint: in.Fingerprint, CurrentTitle: in.Title, CurrentSeverity: in.Severity,
			CurrentSeverityRank: in.SeverityRank, State: "open", AnalysisState: "unanalyzed",
			GateEffect: "block", FirstSeenAt: in.FirstSeen, LastSeenAt: in.LastSeen,
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
