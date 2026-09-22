package main

import "github.com/minh-tg/specht/internal/client"

type mockClient struct {
	client.Client
	findings         []client.Finding
	gate             *client.GateStatus
	waivers          []client.Waiver
	waiver           *client.Waiver
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
	return m.waiver, m.err
}

func (m *mockClient) ToggleWaiver(projectSlug, waiverID string) (*client.Waiver, error) {
	return m.waiver, m.err
}

func (m *mockClient) ListWaiverEvents(projectSlug, waiverID string) ([]client.WaiverEvent, error) {
	return m.events, m.err
}
