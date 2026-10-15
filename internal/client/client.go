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

	"github.com/minh-tg/specht/internal/netutil"
)

// defaultRequestTimeout bounds API requests made by the default HTTP client.
const defaultRequestTimeout = 60 * time.Second

// API path prefixes centralize route construction for the Specht API.
const (
	// maxResponseBytes bounds any single API response the client will read.
	maxResponseBytes  = 64 << 20
	apiProjectsPrefix = "/api/v1/projects/"
	apiFindingsPrefix = "/api/v1/findings/"
	apiTeamsPrefix    = "/api/v1/teams/"
	waiverSegment     = "/waivers/"
	membersSegment    = "/members"
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
	switch b := body.(type) {
	case nil:
	case []byte:
		// Already encoded by the caller. Marshalling it again would turn the
		// bytes into a base64 JSON string that the server rejects.
		reqBody = bytes.NewReader(b)
	default:
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
	_, err := c.doWithHeader(ctx, method, path, body, out)
	return err
}

// doWithHeader is do for the few calls that also need a response header.
func (c *Client) doWithHeader(ctx context.Context, method, path string, body, out any) (http.Header, error) {
	if c.requestContext != nil {
		ctx = c.requestContext
	}
	req, err := c.newClientRequest(ctx, method, path, body)
	if err != nil {
		return nil, err
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("http request: %w", err)
	}
	// The response body is read below; close errors are cleanup-only.
	defer func() {
		_ = resp.Body.Close()
	}()

	respBody, err := netutil.ReadAllLimited(resp.Body, maxResponseBytes)
	if err != nil {
		return nil, fmt.Errorf("read response: %w", err)
	}

	if resp.StatusCode >= 400 {
		return nil, apiResponseError(resp.StatusCode, respBody)
	}

	return resp.Header, decodeAPIResponse(respBody, out)
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
	// The endpoint answers with {"results": [...]}, not a bare list.
	var resp struct {
		Results []TriageResponse `json:"results"`
	}
	if err := c.do(context.Background(), "POST", "/api/v1/findings/bulk-analysis", req, &resp); err != nil {
		return nil, err
	}
	return resp.Results, nil
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
	if err := c.do(context.Background(), "GET", apiTeamsPrefix+url.PathEscape(teamID)+membersSegment, nil, &resp); err != nil {
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
	if err := c.do(context.Background(), "POST", apiTeamsPrefix+url.PathEscape(teamID)+membersSegment, body, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

// RemoveTeamMember removes a user from a team.
func (c *Client) RemoveTeamMember(teamID, userID string) error {
	return c.do(context.Background(), "DELETE", apiTeamsPrefix+url.PathEscape(teamID)+membersSegment+"/"+url.PathEscape(userID), nil, nil)
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

// ListProjectMembers returns direct members of a project.
func (c *Client) ListProjectMembers(projectSlug string) ([]ProjectMember, error) {
	var resp []ProjectMember
	if err := c.do(context.Background(), "GET", apiProjectsPrefix+url.PathEscape(projectSlug)+membersSegment, nil, &resp); err != nil {
		return nil, err
	}
	return resp, nil
}

// AddProjectMember adds or updates a user's role on a project.
func (c *Client) AddProjectMember(projectSlug, userID, role string) (*ProjectMember, error) {
	body, err := json.Marshal(map[string]any{"user_id": userID, "role": role})
	if err != nil {
		return nil, err
	}
	var resp ProjectMember
	if err := c.do(context.Background(), "POST", apiProjectsPrefix+url.PathEscape(projectSlug)+membersSegment, body, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

// RemoveProjectMember removes a user from a project.
func (c *Client) RemoveProjectMember(projectSlug, userID string) error {
	return c.do(context.Background(), "DELETE", apiProjectsPrefix+url.PathEscape(projectSlug)+membersSegment+"/"+url.PathEscape(userID), nil, nil)
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

// RequestWaiver files a pending waiver request. It needs a signed-in person,
// not an API key.
func (c *Client) RequestWaiver(projectSlug string, req *RequestWaiverRequest) (*Waiver, error) {
	var resp Waiver
	if err := c.do(context.Background(), "POST", apiProjectsPrefix+url.PathEscape(projectSlug)+"/waivers/requests", req, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

// ApproveWaiver approves a pending waiver request. The note is optional.
func (c *Client) ApproveWaiver(projectSlug, waiverID, note string) (*Waiver, error) {
	return c.decideWaiver(projectSlug, waiverID, "/approve", note)
}

// RejectWaiver rejects a pending waiver request. The note says why and is
// required by the server.
func (c *Client) RejectWaiver(projectSlug, waiverID, note string) (*Waiver, error) {
	return c.decideWaiver(projectSlug, waiverID, "/reject", note)
}

// WithdrawWaiver takes back the caller's own pending waiver request.
func (c *Client) WithdrawWaiver(projectSlug, waiverID string) (*Waiver, error) {
	return c.decideWaiver(projectSlug, waiverID, "/withdraw", "")
}

func (c *Client) decideWaiver(projectSlug, waiverID, action, note string) (*Waiver, error) {
	var body any
	if note != "" {
		body = map[string]string{"note": note}
	}
	var resp Waiver
	path := apiProjectsPrefix + url.PathEscape(projectSlug) + waiverSegment + url.PathEscape(waiverID) + action
	if err := c.do(context.Background(), "POST", path, body, &resp); err != nil {
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

// DeleteReport removes a report and archives the findings only it showed. It
// returns how many findings were archived, from the server's X-Archived-Findings
// header (0 when the header is absent).
func (c *Client) DeleteReport(projectSlug, reportID string) (int, error) {
	header, err := c.doWithHeader(context.Background(), "DELETE",
		apiProjectsPrefix+url.PathEscape(projectSlug)+"/reports/"+url.PathEscape(reportID), nil, nil)
	if err != nil {
		return 0, err
	}
	archived, _ := strconv.Atoi(header.Get("X-Archived-Findings"))
	return archived, nil
}

// UpdateEnvironment sets how an environment is classified. The server replaces
// all three settings, so every one is sent, false included.
func (c *Client) UpdateEnvironment(projectSlug, environmentID string, settings EnvironmentSettings) (*Environment, error) {
	var resp Environment
	path := apiProjectsPrefix + url.PathEscape(projectSlug) + "/environments/" + url.PathEscape(environmentID)
	if err := c.do(context.Background(), "PUT", path, settings, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

// UpdateProject changes a project's name or description. A nil argument leaves that
// field as it is; a pointer to "" clears the description.
func (c *Client) UpdateProject(slug string, name, description *string) (*Project, error) {
	body := map[string]any{}
	if name != nil {
		body["name"] = *name
	}
	if description != nil {
		body["description"] = *description
	}
	var resp Project
	if err := c.do(context.Background(), "PUT", apiProjectsPrefix+url.PathEscape(slug), body, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

// DeleteProject deletes a project and everything under it, and returns what was deleted.
func (c *Client) DeleteProject(slug string) (*Project, error) {
	var resp Project
	if err := c.do(context.Background(), "DELETE", apiProjectsPrefix+url.PathEscape(slug), nil, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

// AddProjectMemberByEmail grants access to the account with this address. An address
// with no account answers like an unknown user id.
func (c *Client) AddProjectMemberByEmail(projectSlug, email, role string) (*ProjectMember, error) {
	var resp ProjectMember
	body := map[string]any{"email": email, "role": role}
	if err := c.do(context.Background(), "POST", apiProjectsPrefix+url.PathEscape(projectSlug)+membersSegment, body, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

// ListUsers lists accounts, optionally those whose address contains emailPart. Session
// admins only.
func (c *Client) ListUsers(emailPart string, limit, offset int32) ([]UserProfile, error) {
	q := url.Values{}
	if emailPart != "" {
		q.Set("email", emailPart)
	}
	if limit > 0 {
		q.Set("limit", strconv.Itoa(int(limit)))
	}
	if offset > 0 {
		q.Set("offset", strconv.Itoa(int(offset)))
	}
	path := "/api/v1/users"
	if len(q) > 0 {
		path += "?" + q.Encode()
	}
	var resp []UserProfile
	if err := c.do(context.Background(), "GET", path, nil, &resp); err != nil {
		return nil, err
	}
	return resp, nil
}

// ChangeUserRole sets an account's role to admin or member. Session admins only.
func (c *Client) ChangeUserRole(userID, role string) (*UserProfile, error) {
	var resp UserProfile
	if err := c.do(context.Background(), "PUT", "/api/v1/users/"+url.PathEscape(userID)+"/role", map[string]string{"role": role}, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

// CreatePasswordResetLink makes a one-time link that lets a locked-out person choose a new
// password. The link is shown once; a new one retires the earlier ones.
func (c *Client) CreatePasswordResetLink(userID string) (*PasswordResetLink, error) {
	var resp PasswordResetLink
	if err := c.do(context.Background(), "POST", "/api/v1/users/"+url.PathEscape(userID)+"/reset-link", nil, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

// DeactivateUser ends an account's access without deleting its history.
func (c *Client) DeactivateUser(userID string) (*UserProfile, error) {
	var resp UserProfile
	if err := c.do(context.Background(), "POST", "/api/v1/users/"+url.PathEscape(userID)+"/deactivate", nil, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

// ReactivateUser lets a deactivated account sign in again.
func (c *Client) ReactivateUser(userID string) (*UserProfile, error) {
	var resp UserProfile
	if err := c.do(context.Background(), "POST", "/api/v1/users/"+url.PathEscape(userID)+"/reactivate", nil, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

// ListInvites lists a project's open invite links. Their tokens are never shown again.
func (c *Client) ListInvites(projectSlug string) ([]Invite, error) {
	var resp []Invite
	if err := c.do(context.Background(), "GET", apiProjectsPrefix+url.PathEscape(projectSlug)+"/invites", nil, &resp); err != nil {
		return nil, err
	}
	return resp, nil
}

// CreateInvite makes a link that adds whoever opens it to the project with this role. An
// empty email lets anyone with the link accept; zero days leaves the server's default.
func (c *Client) CreateInvite(projectSlug, role, email string, expiresInDays int) (*Invite, error) {
	body := map[string]any{"role": role}
	if email != "" {
		body["email"] = email
	}
	if expiresInDays > 0 {
		body["expires_in_days"] = expiresInDays
	}
	var resp Invite
	if err := c.do(context.Background(), "POST", apiProjectsPrefix+url.PathEscape(projectSlug)+"/invites", body, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

// RevokeInvite stops an open invite link from working.
func (c *Client) RevokeInvite(projectSlug, inviteID string) error {
	return c.do(context.Background(), "DELETE", apiProjectsPrefix+url.PathEscape(projectSlug)+"/invites/"+url.PathEscape(inviteID), nil, nil)
}
