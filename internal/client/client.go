package client

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// defaultRequestTimeout bounds API requests made by the default HTTP client.
const defaultRequestTimeout = 60 * time.Second

// API path prefixes centralize route construction for the Specht API.
const (
	apiProjectsPrefix = "/api/v1/projects/"
	apiFindingsPrefix = "/api/v1/findings/"
	apiTeamsPrefix    = "/api/v1/teams/"
	waiverSegment     = "/waivers/"
)

// Client is a typed HTTP client for the Specht API.
type Client struct {
	baseURL        string
	httpClient     *http.Client
	token          string
	requestContext context.Context
}

// New builds a client for the given base URL (e.g. http://localhost:8080).
// Requests use a 60-second timeout unless WithHTTPClient replaces the default.
func New(baseURL string, opts ...Option) *Client {
	c := &Client{
		baseURL:    strings.TrimRight(baseURL, "/"),
		httpClient: &http.Client{Timeout: defaultRequestTimeout},
	}
	for _, o := range opts {
		o(c)
	}
	return c
}

// Option configures a Client at construction.
type Option func(*Client)

// WithHTTPClient overrides the default HTTP client (e.g. for tests).
func WithHTTPClient(hc *http.Client) Option {
	return func(c *Client) {
		c.httpClient = hc
	}
}

// WithToken sets a bearer token sent on every request.
func WithToken(token string) Option {
	return func(c *Client) {
		c.token = token
	}
}

// WithContext returns a shallow copy of c whose requests are canceled when
// ctx is done. It is useful for binding all requests made by one CLI command
// to that command's context; the original client remains unchanged.
func (c *Client) WithContext(ctx context.Context) *Client {
	if ctx == nil {
		ctx = context.Background()
	}
	bound := *c
	bound.requestContext = ctx
	return &bound
}

// newClientRequest builds an authenticated JSON request for the Specht API.
func (c *Client) newClientRequest(ctx context.Context, method, path string, body any) (*http.Request, error) {
	var reqBody io.Reader
	if body != nil {
		data, err := json.Marshal(body)
		if err != nil {
			return nil, fmt.Errorf("marshal request: %w", err)
		}
		reqBody = bytes.NewReader(data)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.baseURL+path, reqBody)
	if err != nil {
		return nil, fmt.Errorf("create request: %w", err)
	}
	if c.token != "" {
		req.Header.Set("Authorization", "Bearer "+c.token)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	return req, nil
}

// apiResponseError maps a non-2xx response body to a typed Error.
func apiResponseError(statusCode int, respBody []byte) *Error {
	var wrapper apiErrorWrapper
	if json.Unmarshal(respBody, &wrapper) == nil && wrapper.Error.Code != "" {
		return &Error{Code: wrapper.Error.Code, Message: wrapper.Error.Message, StatusCode: statusCode}
	}
	return &Error{
		StatusCode: statusCode,
		Message:    strings.TrimSpace(string(respBody)),
	}
}

// decodeAPIResponse unmarshals a non-empty success body into out.
func decodeAPIResponse(respBody []byte, out any) error {
	if out != nil && len(respBody) > 0 {
		if err := json.Unmarshal(respBody, out); err != nil {
			return fmt.Errorf("decode response: %w", err)
		}
	}
	return nil
}

func (c *Client) do(ctx context.Context, method, path string, body, out any) error {
	if c.requestContext != nil {
		ctx = c.requestContext
	}
	req, err := c.newClientRequest(ctx, method, path, body)
	if err != nil {
		return err
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("http request: %w", err)
	}
	// The response body is read below; close errors are cleanup-only.
	defer func() {
		_ = resp.Body.Close()
	}()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("read response: %w", err)
	}

	if resp.StatusCode >= 400 {
		return apiResponseError(resp.StatusCode, respBody)
	}

	return decodeAPIResponse(respBody, out)
}

// Error is a non-2xx API response, carrying the server error code when present.
type Error struct {
	Code       string
	Message    string
	StatusCode int
}

func (e *Error) Error() string {
	if e.Code != "" {
		return fmt.Sprintf("[%d] %s: %s", e.StatusCode, e.Code, e.Message)
	}
	return fmt.Sprintf("[%d] %s", e.StatusCode, e.Message)
}

func (e *Error) Unauthorized() bool { return e.StatusCode == http.StatusUnauthorized }
func (e *Error) NotFound() bool     { return e.StatusCode == http.StatusNotFound }
func (e *Error) Forbidden() bool    { return e.StatusCode == http.StatusForbidden }

// Health.

func (c *Client) Health() (string, error) {
	var resp struct {
		Status string `json:"status"`
	}
	if err := c.do(context.Background(), "GET", "/api/v1/health", nil, &resp); err != nil {
		return "", err
	}
	return resp.Status, nil
}

// Auth.

func (c *Client) Register(email, password string) (*AuthResponse, error) {
	var resp AuthResponse
	if err := c.do(context.Background(), "POST", "/api/v1/auth/register", RegisterRequest{Email: email, Password: password}, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

func (c *Client) Login(email, password string) (*AuthResponse, error) {
	var resp AuthResponse
	if err := c.do(context.Background(), "POST", "/api/v1/auth/login", LoginRequest{Email: email, Password: password}, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

func (c *Client) Refresh(refreshToken string) (*AuthResponse, error) {
	var resp AuthResponse
	if err := c.do(context.Background(), "POST", "/api/v1/auth/refresh", RefreshRequest{RefreshToken: refreshToken}, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

func (c *Client) Logout(refreshToken string) error {
	return c.do(context.Background(), "POST", "/api/v1/auth/logout", RefreshRequest{RefreshToken: refreshToken}, nil)
}

func (c *Client) Me() (*UserProfile, error) {
	var resp UserProfile
	if err := c.do(context.Background(), "GET", "/api/v1/me", nil, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

// ListScanners returns the deterministic scanner capability list.
func (c *Client) ListScanners() ([]ScannerDescriptor, error) {
	var resp []ScannerDescriptor
	if err := c.do(context.Background(), "GET", "/api/v1/scanners", nil, &resp); err != nil {
		return nil, err
	}
	return resp, nil
}

// API Keys.

func (c *Client) CreateAPIKey(project, name string) (*APIKey, error) {
	var resp APIKey
	if err := c.do(context.Background(), "POST", "/api/v1/auth/apikeys", CreateAPIKeyRequest{Project: project, Name: name}, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

func (c *Client) ListAPIKeys(project string) ([]APIKey, error) {
	var resp []APIKey
	if err := c.do(context.Background(), "GET", "/api/v1/auth/apikeys?project="+url.QueryEscape(project), nil, &resp); err != nil {
		return nil, err
	}
	return resp, nil
}

func (c *Client) RevokeAPIKey(project, keyID string) error {
	return c.do(context.Background(), "DELETE", "/api/v1/auth/apikeys/"+url.PathEscape(keyID)+"?project="+url.QueryEscape(project), nil, nil)
}

// Projects.

func (c *Client) CreateProject(name, slug, description string) (*Project, error) {
	var resp Project
	if err := c.do(context.Background(), "POST", "/api/v1/projects", CreateProjectRequest{Name: name, Slug: slug, Description: description}, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

func (c *Client) ListProjects() ([]Project, error) {
	var resp []Project
	if err := c.do(context.Background(), "GET", "/api/v1/projects", nil, &resp); err != nil {
		return nil, err
	}
	return resp, nil
}

func (c *Client) GetProject(slug string) (*Project, error) {
	var resp Project
	if err := c.do(context.Background(), "GET", apiProjectsPrefix+url.PathEscape(slug), nil, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

// Reports.

func (c *Client) IngestReport(payload *IngestPayload) (*IngestResponse, error) {
	var resp IngestResponse
	if err := c.do(context.Background(), "POST", "/api/v1/reports", payload, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

func (c *Client) ListReports(projectSlug string, limit, offset int32) ([]Report, error) {
	var resp []Report
	path := apiProjectsPrefix + url.PathEscape(projectSlug) + "/reports"
	if limit > 0 || offset > 0 {
		q := url.Values{}
		if limit > 0 {
			q.Set("limit", strconv.Itoa(int(limit)))
		}
		if offset > 0 {
			q.Set("offset", strconv.Itoa(int(offset)))
		}
		path += "?" + q.Encode()
	}
	if err := c.do(context.Background(), "GET", path, nil, &resp); err != nil {
		return nil, err
	}
	return resp, nil
}

func (c *Client) GetReport(reportID string) (*Report, error) {
	var resp Report
	if err := c.do(context.Background(), "GET", "/api/v1/reports/"+url.PathEscape(reportID), nil, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

// Findings.

func (c *Client) ListFindings(projectSlug string, severities, states []string, limit, offset int32) ([]Finding, error) {
	q := url.Values{}
	if len(severities) > 0 {
		q.Set("severity", strings.Join(severities, ","))
	}
	if len(states) > 0 {
		q.Set("status", strings.Join(states, ","))
	}
	if limit > 0 {
		q.Set("limit", strconv.Itoa(int(limit)))
	}
	if offset > 0 {
		q.Set("offset", strconv.Itoa(int(offset)))
	}
	path := apiProjectsPrefix + url.PathEscape(projectSlug) + "/findings"
	if len(q) > 0 {
		path += "?" + q.Encode()
	}
	var resp []Finding
	if err := c.do(context.Background(), "GET", path, nil, &resp); err != nil {
		return nil, err
	}
	return resp, nil
}

func (c *Client) GetFinding(findingID string) (*Finding, error) {
	var resp Finding
	if err := c.do(context.Background(), "GET", apiFindingsPrefix+url.PathEscape(findingID), nil, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

func (c *Client) TriageFinding(findingID string, req *TriageRequest) (*TriageResponse, error) {
	var resp TriageResponse
	if err := c.do(context.Background(), "PATCH", apiFindingsPrefix+url.PathEscape(findingID), req, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

func (c *Client) BulkTriage(req *BulkTriageRequest) ([]TriageResponse, error) {
	var resp []TriageResponse
	if err := c.do(context.Background(), "POST", "/api/v1/findings/bulk-analysis", req, &resp); err != nil {
		return nil, err
	}
	return resp, nil
}

func (c *Client) ListFindingEvents(findingID string, eventTypes []string, limit, offset int32) ([]FindingEvent, error) {
	q := url.Values{}
	for _, et := range eventTypes {
		q.Add("type", et)
	}
	if limit > 0 {
		q.Set("limit", strconv.Itoa(int(limit)))
	}
	if offset > 0 {
		q.Set("offset", strconv.Itoa(int(offset)))
	}
	path := apiFindingsPrefix + url.PathEscape(findingID) + "/events"
	if len(q) > 0 {
		path += "?" + q.Encode()
	}
	var resp []FindingEvent
	if err := c.do(context.Background(), "GET", path, nil, &resp); err != nil {
		return nil, err
	}
	return resp, nil
}

// Gate.

func (c *Client) GetGateStatus(projectSlug string, severity string) (*GateStatus, error) {
	path := apiProjectsPrefix + url.PathEscape(projectSlug) + "/gate"
	if severity != "" {
		path += "?severity=" + url.QueryEscape(severity)
	}
	var resp GateStatus
	if err := c.do(context.Background(), "GET", path, nil, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

// GetIntroducedGateStatus evaluates the gate over findings one report
// introduced (change-scoped CI feedback).
func (c *Client) GetIntroducedGateStatus(projectSlug string, severity string, reportID string) (*GateStatus, error) {
	q := url.Values{}
	q.Set("introduced_only", "1")
	q.Set("report_id", reportID)
	if severity != "" {
		q.Set("severity", severity)
	}
	path := apiProjectsPrefix + url.PathEscape(projectSlug) + "/gate?" + q.Encode()
	var resp GateStatus
	if err := c.do(context.Background(), "GET", path, nil, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

// PreviewPRCheck plans (but never publishes) the pull-request check for a
// change.
func (c *Client) PreviewPRCheck(projectSlug string, commit string, provider string, reportID string, severity string) (*PRCheckPreview, error) {
	q := url.Values{}
	q.Set("commit", commit)
	if provider != "" {
		q.Set("provider", provider)
	}
	if reportID != "" {
		q.Set("report_id", reportID)
	}
	if severity != "" {
		q.Set("severity", severity)
	}
	path := apiProjectsPrefix + url.PathEscape(projectSlug) + "/pr-check?" + q.Encode()
	var resp PRCheckPreview
	if err := c.do(context.Background(), "GET", path, nil, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

// PreviewPatch plans (but never applies) the safe patch for a finding.
func (c *Client) PreviewPatch(findingID string) (*PatchOutcome, error) {
	path := apiFindingsPrefix + url.PathEscape(findingID) + "/patch-preview"
	var resp PatchOutcome
	if err := c.do(context.Background(), "GET", path, nil, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

// PreviewNotification plans (but never sends) the issue-tracker or
// messaging action for a finding.
func (c *Client) PreviewNotification(findingID string, channel string, target string, linked bool) (*NotifyOutcome, error) {
	q := url.Values{}
	q.Set("channel", channel)
	q.Set("target", target)
	if linked {
		q.Set("linked", "1")
	}
	path := apiFindingsPrefix + url.PathEscape(findingID) + "/notify-preview?" + q.Encode()
	var resp NotifyOutcome
	if err := c.do(context.Background(), "GET", path, nil, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

// GetAdminStatus returns the platform observability snapshot.
func (c *Client) GetAdminStatus() (*AdminStatus, error) {
	var resp AdminStatus
	if err := c.do(context.Background(), "GET", "/api/v1/admin/status", nil, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

// PreviewRetention counts settled reports a purge would delete.
func (c *Client) PreviewRetention(days int) (*RetentionPreview, error) {
	q := url.Values{}
	q.Set("days", strconv.Itoa(days))
	var resp RetentionPreview
	if err := c.do(context.Background(), "GET", "/api/v1/admin/retention/preview?"+q.Encode(), nil, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

// PurgeRetention deletes settled reports older than the window.
func (c *Client) PurgeRetention(days int) (*RetentionResult, error) {
	var resp RetentionResult
	if err := c.do(context.Background(), "POST", "/api/v1/admin/retention/purge",
		map[string]any{"older_than_days": days}, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

// ListPolicyTemplates returns every policy baseline in name order.
func (c *Client) ListPolicyTemplates() ([]PolicyTemplate, error) {
	var resp []PolicyTemplate
	if err := c.do(context.Background(), "GET", "/api/v1/policy-templates", nil, &resp); err != nil {
		return nil, err
	}
	return resp, nil
}

// CreatePolicyTemplate stores a reusable baseline.
func (c *Client) CreatePolicyTemplate(name, description string, definition map[string]string) (*PolicyTemplate, error) {
	body, err := json.Marshal(map[string]any{"name": name, "description": description, "definition": definition})
	if err != nil {
		return nil, err
	}
	var resp PolicyTemplate
	if err := c.do(context.Background(), "POST", "/api/v1/policy-templates", body, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

// UpdatePolicyTemplate replaces a baseline (version bumps in storage).
func (c *Client) UpdatePolicyTemplate(id, name, description string, definition map[string]string) (*PolicyTemplate, error) {
	body, err := json.Marshal(map[string]any{"name": name, "description": description, "definition": definition})
	if err != nil {
		return nil, err
	}
	var resp PolicyTemplate
	if err := c.do(context.Background(), "PUT", "/api/v1/policy-templates/"+url.PathEscape(id), body, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

// DeletePolicyTemplate removes a baseline; linked projects fall back.
func (c *Client) DeletePolicyTemplate(id string) error {
	return c.do(context.Background(), "DELETE", "/api/v1/policy-templates/"+url.PathEscape(id), nil, nil)
}

// SetProjectPolicy links a project to a baseline by name (empty unlinks).
func (c *Client) SetProjectPolicy(projectSlug string, templateName string) (*PolicyEffective, error) {
	body, err := json.Marshal(map[string]any{"template_name": templateName})
	if err != nil {
		return nil, err
	}
	var resp PolicyEffective
	if err := c.do(context.Background(), "PUT", apiProjectsPrefix+url.PathEscape(projectSlug)+"/policy", body, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

// SetProjectPolicyOverrides replaces a project's per-key overrides.
func (c *Client) SetProjectPolicyOverrides(projectSlug string, overrides map[string]string) (*PolicyEffective, error) {
	body, err := json.Marshal(map[string]any{"overrides": overrides})
	if err != nil {
		return nil, err
	}
	var resp PolicyEffective
	if err := c.do(context.Background(), "PUT", apiProjectsPrefix+url.PathEscape(projectSlug)+"/policy/overrides", body, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

// GetEffectivePolicy resolves one project's policy with provenance.
func (c *Client) GetEffectivePolicy(projectSlug string) (*PolicyEffective, error) {
	var resp PolicyEffective
	if err := c.do(context.Background(), "GET", apiProjectsPrefix+url.PathEscape(projectSlug)+"/policy", nil, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

// ListTeams returns every team in name order.
func (c *Client) ListTeams() ([]Team, error) {
	var resp []Team
	if err := c.do(context.Background(), "GET", "/api/v1/teams", nil, &resp); err != nil {
		return nil, err
	}
	return resp, nil
}

// CreateTeam creates a team; the creator becomes its admin.
func (c *Client) CreateTeam(name, description string) (*Team, error) {
	body, err := json.Marshal(map[string]any{"name": name, "description": description})
	if err != nil {
		return nil, err
	}
	var resp Team
	if err := c.do(context.Background(), "POST", "/api/v1/teams", body, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

// DeleteTeam removes a team; project links cascade.
func (c *Client) DeleteTeam(id string) error {
	return c.do(context.Background(), "DELETE", apiTeamsPrefix+url.PathEscape(id), nil, nil)
}

// ListTeamMembers returns a team's roster.
func (c *Client) ListTeamMembers(teamID string) ([]TeamMember, error) {
	var resp []TeamMember
	if err := c.do(context.Background(), "GET", apiTeamsPrefix+url.PathEscape(teamID)+"/members", nil, &resp); err != nil {
		return nil, err
	}
	return resp, nil
}

// AddTeamMember adds a user to a team.
func (c *Client) AddTeamMember(teamID, userID, role string) (*TeamMember, error) {
	body, err := json.Marshal(map[string]any{"user_id": userID, "role": role})
	if err != nil {
		return nil, err
	}
	var resp TeamMember
	if err := c.do(context.Background(), "POST", apiTeamsPrefix+url.PathEscape(teamID)+"/members", body, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

// RemoveTeamMember removes a user from a team.
func (c *Client) RemoveTeamMember(teamID, userID string) error {
	return c.do(context.Background(), "DELETE", apiTeamsPrefix+url.PathEscape(teamID)+"/members/"+url.PathEscape(userID), nil, nil)
}

// ListProjectTeams returns every team linked to a project.
func (c *Client) ListProjectTeams(projectSlug string) ([]ProjectTeam, error) {
	var resp []ProjectTeam
	if err := c.do(context.Background(), "GET", apiProjectsPrefix+url.PathEscape(projectSlug)+"/teams", nil, &resp); err != nil {
		return nil, err
	}
	return resp, nil
}

// LinkProjectTeam confers a project role on every team member.
func (c *Client) LinkProjectTeam(projectSlug, teamID, role string) (*ProjectTeam, error) {
	body, err := json.Marshal(map[string]any{"team_id": teamID, "role": role})
	if err != nil {
		return nil, err
	}
	var resp ProjectTeam
	if err := c.do(context.Background(), "POST", apiProjectsPrefix+url.PathEscape(projectSlug)+"/teams", body, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

// UnlinkProjectTeam revokes the conferred role.
func (c *Client) UnlinkProjectTeam(projectSlug, teamID string) error {
	return c.do(context.Background(), "DELETE", apiProjectsPrefix+url.PathEscape(projectSlug)+"/teams/"+url.PathEscape(teamID), nil, nil)
}

// Environments, Targets, Artifacts.

func (c *Client) ListEnvironments(projectSlug string) ([]Environment, error) {
	var resp []Environment
	if err := c.do(context.Background(), "GET", apiProjectsPrefix+url.PathEscape(projectSlug)+"/environments", nil, &resp); err != nil {
		return nil, err
	}
	return resp, nil
}

func (c *Client) ListTargets(projectSlug string) ([]Target, error) {
	var resp []Target
	if err := c.do(context.Background(), "GET", apiProjectsPrefix+url.PathEscape(projectSlug)+"/targets", nil, &resp); err != nil {
		return nil, err
	}
	return resp, nil
}

func (c *Client) ListArtifacts(projectSlug string) ([]Artifact, error) {
	var resp []Artifact
	if err := c.do(context.Background(), "GET", apiProjectsPrefix+url.PathEscape(projectSlug)+"/artifacts", nil, &resp); err != nil {
		return nil, err
	}
	return resp, nil
}

func (c *Client) GetProjectStats(projectSlug string) (*ProjectStats, error) {
	var resp ProjectStats
	if err := c.do(context.Background(), "GET", apiProjectsPrefix+url.PathEscape(projectSlug)+"/stats", nil, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

func (c *Client) GetAging(projectSlug string) (*AgingResponse, error) {
	var resp AgingResponse
	if err := c.do(context.Background(), "GET", apiProjectsPrefix+url.PathEscape(projectSlug)+"/aging", nil, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

func (c *Client) VerifyFinding(findingID string) (*VerifyResponse, error) {
	var resp VerifyResponse
	if err := c.do(context.Background(), "POST", apiFindingsPrefix+url.PathEscape(findingID)+"/verify", nil, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

// Waivers.

func (c *Client) CreateWaiver(projectSlug string, req *CreateWaiverRequest) (*Waiver, error) {
	var resp Waiver
	if err := c.do(context.Background(), "POST", apiProjectsPrefix+url.PathEscape(projectSlug)+"/waivers", req, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

func (c *Client) ListWaivers(projectSlug string) ([]Waiver, error) {
	var resp []Waiver
	if err := c.do(context.Background(), "GET", apiProjectsPrefix+url.PathEscape(projectSlug)+"/waivers", nil, &resp); err != nil {
		return nil, err
	}
	return resp, nil
}

func (c *Client) GetWaiver(projectSlug, waiverID string) (*WaiverDetail, error) {
	var resp WaiverDetail
	if err := c.do(context.Background(), "GET", apiProjectsPrefix+url.PathEscape(projectSlug)+waiverSegment+url.PathEscape(waiverID), nil, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

func (c *Client) UpdateWaiver(projectSlug, waiverID string, req *UpdateWaiverRequest) (*Waiver, error) {
	var resp Waiver
	if err := c.do(context.Background(), "PUT", apiProjectsPrefix+url.PathEscape(projectSlug)+waiverSegment+url.PathEscape(waiverID), req, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

func (c *Client) DeleteWaiver(projectSlug, waiverID string) error {
	return c.do(context.Background(), "DELETE", apiProjectsPrefix+url.PathEscape(projectSlug)+waiverSegment+url.PathEscape(waiverID), nil, nil)
}

func (c *Client) ToggleWaiver(projectSlug, waiverID string) (*Waiver, error) {
	var resp Waiver
	if err := c.do(context.Background(), "POST", apiProjectsPrefix+url.PathEscape(projectSlug)+waiverSegment+url.PathEscape(waiverID)+"/toggle", nil, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

func (c *Client) ListWaiverEvents(projectSlug, waiverID string) ([]WaiverEvent, error) {
	var resp []WaiverEvent
	if err := c.do(context.Background(), "GET", apiProjectsPrefix+url.PathEscape(projectSlug)+waiverSegment+url.PathEscape(waiverID)+"/events", nil, &resp); err != nil {
		return nil, err
	}
	return resp, nil
}

func (c *Client) CheckWaiverMatch(projectSlug, findingID string) (bool, error) {
	var resp CheckWaiverMatchResponse
	if err := c.do(context.Background(), "POST", apiProjectsPrefix+url.PathEscape(projectSlug)+"/waivers/check-match", map[string]string{"finding_id": findingID}, &resp); err != nil {
		return false, err
	}
	return resp.Matched, nil
}

// UpsertReachability sets a finding's reachability assessment (state is one
// of reachable, not_reachable, unknown, not_applicable).
func (c *Client) UpsertReachability(findingID, state, evidence string) (*ReachabilityAssessment, error) {
	var resp ReachabilityAssessment
	if err := c.do(context.Background(), "POST", apiFindingsPrefix+url.PathEscape(findingID)+"/reachability", &UpsertReachabilityRequest{State: state, Evidence: evidence}, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

// ListReachability returns a finding's reachability assessment history.
func (c *Client) ListReachability(findingID string) ([]ReachabilityAssessment, error) {
	var resp []ReachabilityAssessment
	if err := c.do(context.Background(), "GET", apiFindingsPrefix+url.PathEscape(findingID)+"/reachability", nil, &resp); err != nil {
		return nil, err
	}
	return resp, nil
}

// GetWatcherStatus returns the CVE watcher daemon's health.
func (c *Client) GetWatcherStatus() (*WatcherStatus, error) {
	var resp WatcherStatus
	if err := c.do(context.Background(), "GET", "/api/v1/watcher/status", nil, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}
