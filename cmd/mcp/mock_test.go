package main

import "github.com/minh-tg/specht/internal/client"

type mockClient struct {
	client.Client
	findings         []client.Finding
	gate             *client.GateStatus
	waivers          []client.Waiver
	waiver           *client.Waiver
	waiverReq        *client.CreateWaiverRequest
	waiverDet        *client.WaiverDetail
	events           []client.WaiverEvent
	assessment       *client.ReachabilityAssessment
	watcher          *client.WatcherStatus
	preview          *client.PRCheckPreview
	patch            *client.PatchOutcome
	notification     *client.NotifyOutcome
	notifiedLinked   bool
	adminStatus      *client.AdminStatus
	retention        *client.RetentionPreview
	retentionDays    int
	policy           *client.PolicyEffective
	policyProject    string
	teams            []client.Team
	projectTeams     []client.ProjectTeam
	introducedReport string
	projects         []client.Project
	stats            *client.ProjectStats
	aging            *client.AgingResponse
	reports          []client.Report
	environments     []client.Environment
	targets          []client.Target
	artifacts        []client.Artifact
	findingEvents    []client.FindingEvent
	eventTypes       []string
	eventLimit       int32
	scanners         []client.ScannerDescriptor
	triageID         string
	triageReq        *client.TriageRequest
	triageResp       *client.TriageResponse
	requestedWaiver  *client.RequestWaiverRequest
	withdrawn        string
	err              error
}

func (m *mockClient) ListFindings(projectSlug string, severities, states []string, limit, offset int32) ([]client.Finding, error) {
	return m.findings, m.err
}

func (m *mockClient) GetFinding(findingID string) (*client.Finding, error) {
	if len(m.findings) > 0 {
		return &m.findings[0], m.err
	}
	return nil, m.err
}

func (m *mockClient) GetGateStatus(projectSlug string, severity string) (*client.GateStatus, error) {
	return m.gate, m.err
}

func (m *mockClient) GetIntroducedGateStatus(projectSlug string, severity string, reportID string) (*client.GateStatus, error) {
	m.introducedReport = reportID
	return m.gate, m.err
}

func (m *mockClient) PreviewPRCheck(projectSlug string, commit string, provider string, reportID string, severity string) (*client.PRCheckPreview, error) {
	return m.preview, m.err
}

func (m *mockClient) PreviewPatch(findingID string) (*client.PatchOutcome, error) {
	return m.patch, m.err
}

func (m *mockClient) PreviewNotification(findingID string, channel string, target string, linked bool) (*client.NotifyOutcome, error) {
	m.notifiedLinked = linked
	return m.notification, m.err
}

func (m *mockClient) GetAdminStatus() (*client.AdminStatus, error) {
	return m.adminStatus, m.err
}

func (m *mockClient) PreviewRetention(days int) (*client.RetentionPreview, error) {
	m.retentionDays = days
	return m.retention, m.err
}

func (m *mockClient) GetEffectivePolicy(projectSlug string) (*client.PolicyEffective, error) {
	m.policyProject = projectSlug
	return m.policy, m.err
}

func (m *mockClient) ListTeams() ([]client.Team, error) {
	return m.teams, m.err
}

func (m *mockClient) ListProjectTeams(projectSlug string) ([]client.ProjectTeam, error) {
	return m.projectTeams, m.err
}

func (m *mockClient) UpsertReachability(findingID, state, evidence string) (*client.ReachabilityAssessment, error) {
	if m.assessment == nil {
		return nil, m.err
	}
	return m.assessment, m.err
}

func (m *mockClient) ListReachability(findingID string) ([]client.ReachabilityAssessment, error) {
	if m.assessment == nil {
		return nil, m.err
	}
	return []client.ReachabilityAssessment{*m.assessment}, m.err
}

func (m *mockClient) GetWatcherStatus() (*client.WatcherStatus, error) {
	return m.watcher, m.err
}

func (m *mockClient) ListWaivers(projectSlug string) ([]client.Waiver, error) {
	return m.waivers, m.err
}

func (m *mockClient) GetWaiver(projectSlug, waiverID string) (*client.WaiverDetail, error) {
	return m.waiverDet, m.err
}

func (m *mockClient) CreateWaiver(projectSlug string, req *client.CreateWaiverRequest) (*client.Waiver, error) {
	m.waiverReq = req
	return m.waiver, m.err
}

func (m *mockClient) ToggleWaiver(projectSlug, waiverID string) (*client.Waiver, error) {
	return m.waiver, m.err
}

func (m *mockClient) ListWaiverEvents(projectSlug, waiverID string) ([]client.WaiverEvent, error) {
	return m.events, m.err
}

func (m *mockClient) ListProjects() ([]client.Project, error) { return m.projects, m.err }

func (m *mockClient) GetProject(slug string) (*client.Project, error) {
	if len(m.projects) == 0 {
		return nil, m.err
	}
	return &m.projects[0], m.err
}

func (m *mockClient) GetProjectStats(projectSlug string) (*client.ProjectStats, error) {
	return m.stats, m.err
}

func (m *mockClient) GetAging(projectSlug string) (*client.AgingResponse, error) {
	return m.aging, m.err
}

func (m *mockClient) ListReports(projectSlug string, limit, offset int32) ([]client.Report, error) {
	return m.reports, m.err
}

func (m *mockClient) GetReport(reportID string) (*client.Report, error) {
	if len(m.reports) == 0 {
		return nil, m.err
	}
	return &m.reports[0], m.err
}

func (m *mockClient) ListEnvironments(projectSlug string) ([]client.Environment, error) {
	return m.environments, m.err
}

func (m *mockClient) ListTargets(projectSlug string) ([]client.Target, error) {
	return m.targets, m.err
}

func (m *mockClient) ListArtifacts(projectSlug string) ([]client.Artifact, error) {
	return m.artifacts, m.err
}

func (m *mockClient) ListFindingEvents(findingID string, eventTypes []string, limit, offset int32) ([]client.FindingEvent, error) {
	m.eventTypes, m.eventLimit = eventTypes, limit
	return m.findingEvents, m.err
}

func (m *mockClient) ListScanners() ([]client.ScannerDescriptor, error) { return m.scanners, m.err }

func (m *mockClient) TriageFinding(findingID string, req *client.TriageRequest) (*client.TriageResponse, error) {
	m.triageID, m.triageReq = findingID, req
	return m.triageResp, m.err
}

func (m *mockClient) RequestWaiver(projectSlug string, req *client.RequestWaiverRequest) (*client.Waiver, error) {
	m.requestedWaiver = req
	return m.waiver, m.err
}

func (m *mockClient) WithdrawWaiver(projectSlug, waiverID string) (*client.Waiver, error) {
	m.withdrawn = waiverID
	return m.waiver, m.err
}
