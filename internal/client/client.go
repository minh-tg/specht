package client

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
)

type Client struct {
	baseURL    string
	httpClient *http.Client
	token      string
}

func New(baseURL string, opts ...Option) *Client {
	c := &Client{
		baseURL:    strings.TrimRight(baseURL, "/"),
		httpClient: http.DefaultClient,
	}
	for _, o := range opts {
		o(c)
	}
	return c
}

type Option func(*Client)

func WithHTTPClient(hc *http.Client) Option {
	return func(c *Client) {
		c.httpClient = hc
	}
}

func WithToken(token string) Option {
	return func(c *Client) {
		c.token = token
	}
}

func (c *Client) do(method, path string, body, out any) error {
	var reqBody io.Reader
	if body != nil {
		data, err := json.Marshal(body)
		if err != nil {
			return fmt.Errorf("marshal request: %w", err)
		}
		reqBody = bytes.NewReader(data)
	}

	req, err := http.NewRequest(method, c.baseURL+path, reqBody)
	if err != nil {
		return fmt.Errorf("create request: %w", err)
	}

	if c.token != "" {
		req.Header.Set("Authorization", "Bearer "+c.token)
	}

	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("http request: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("read response: %w", err)
	}

	if resp.StatusCode >= 400 {
		var wrapper apiErrorWrapper
		if json.Unmarshal(respBody, &wrapper) == nil && wrapper.Error.Code != "" {
			return &Error{Code: wrapper.Error.Code, Message: wrapper.Error.Message, StatusCode: resp.StatusCode}
		}
		return &Error{
			StatusCode: resp.StatusCode,
			Message:    strings.TrimSpace(string(respBody)),
		}
	}

	if out != nil && len(respBody) > 0 {
		if err := json.Unmarshal(respBody, out); err != nil {
			return fmt.Errorf("decode response: %w", err)
		}
	}

	return nil
}

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
	if err := c.do("GET", "/api/v1/health", nil, &resp); err != nil {
		return "", err
	}
	return resp.Status, nil
}

// Auth.

func (c *Client) Register(email, password string) (*AuthResponse, error) {
	var resp AuthResponse
	if err := c.do("POST", "/api/v1/auth/register", RegisterRequest{Email: email, Password: password}, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

func (c *Client) Login(email, password string) (*AuthResponse, error) {
	var resp AuthResponse
	if err := c.do("POST", "/api/v1/auth/login", LoginRequest{Email: email, Password: password}, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

func (c *Client) Refresh(refreshToken string) (*AuthResponse, error) {
	var resp AuthResponse
	if err := c.do("POST", "/api/v1/auth/refresh", RefreshRequest{RefreshToken: refreshToken}, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

func (c *Client) Logout(refreshToken string) error {
	return c.do("POST", "/api/v1/auth/logout", RefreshRequest{RefreshToken: refreshToken}, nil)
}

func (c *Client) Me() (*UserProfile, error) {
	var resp UserProfile
	if err := c.do("GET", "/api/v1/me", nil, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

// API Keys.

func (c *Client) CreateAPIKey(project, name string) (*APIKey, error) {
	var resp APIKey
	if err := c.do("POST", "/api/v1/auth/apikeys", CreateAPIKeyRequest{Project: project, Name: name}, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

func (c *Client) ListAPIKeys(project string) ([]APIKey, error) {
	var resp []APIKey
	if err := c.do("GET", "/api/v1/auth/apikeys?project="+url.QueryEscape(project), nil, &resp); err != nil {
		return nil, err
	}
	return resp, nil
}

func (c *Client) RevokeAPIKey(project, keyID string) error {
	return c.do("DELETE", "/api/v1/auth/apikeys/"+url.PathEscape(keyID)+"?project="+url.QueryEscape(project), nil, nil)
}

// Projects.

func (c *Client) CreateProject(name, slug, description string) (*Project, error) {
	var resp Project
	if err := c.do("POST", "/api/v1/projects", CreateProjectRequest{Name: name, Slug: slug, Description: description}, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

func (c *Client) ListProjects() ([]Project, error) {
	var resp []Project
	if err := c.do("GET", "/api/v1/projects", nil, &resp); err != nil {
		return nil, err
	}
	return resp, nil
}

func (c *Client) GetProject(slug string) (*Project, error) {
	var resp Project
	if err := c.do("GET", "/api/v1/projects/"+url.PathEscape(slug), nil, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

// Reports.

func (c *Client) IngestReport(payload *IngestPayload) (*IngestResponse, error) {
	var resp IngestResponse
	if err := c.do("POST", "/api/v1/reports", payload, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

func (c *Client) ListReports(projectSlug string, limit, offset int32) ([]Report, error) {
	var resp []Report
	path := "/api/v1/projects/" + url.PathEscape(projectSlug) + "/reports"
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
	if err := c.do("GET", path, nil, &resp); err != nil {
		return nil, err
	}
	return resp, nil
}

func (c *Client) GetReport(reportID string) (*Report, error) {
	var resp Report
	if err := c.do("GET", "/api/v1/reports/"+url.PathEscape(reportID), nil, &resp); err != nil {
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
	path := "/api/v1/projects/" + url.PathEscape(projectSlug) + "/findings"
	if len(q) > 0 {
		path += "?" + q.Encode()
	}
	var resp []Finding
	if err := c.do("GET", path, nil, &resp); err != nil {
		return nil, err
	}
	return resp, nil
}

func (c *Client) GetFinding(findingID string) (*Finding, error) {
	var resp Finding
	if err := c.do("GET", "/api/v1/findings/"+url.PathEscape(findingID), nil, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

func (c *Client) TriageFinding(findingID string, req *TriageRequest) (*TriageResponse, error) {
	var resp TriageResponse
	if err := c.do("PATCH", "/api/v1/findings/"+url.PathEscape(findingID), req, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

func (c *Client) BulkTriage(req *BulkTriageRequest) ([]TriageResponse, error) {
	var resp []TriageResponse
	if err := c.do("POST", "/api/v1/findings/bulk-analysis", req, &resp); err != nil {
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
	path := "/api/v1/findings/" + url.PathEscape(findingID) + "/events"
	if len(q) > 0 {
		path += "?" + q.Encode()
	}
	var resp []FindingEvent
	if err := c.do("GET", path, nil, &resp); err != nil {
		return nil, err
	}
	return resp, nil
}

// Gate.

func (c *Client) GetGateStatus(projectSlug string, severity string) (*GateStatus, error) {
	path := "/api/v1/projects/" + url.PathEscape(projectSlug) + "/gate"
	if severity != "" {
		path += "?severity=" + url.QueryEscape(severity)
	}
	var resp GateStatus
	if err := c.do("GET", path, nil, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

// Environments, Targets, Artifacts.

func (c *Client) ListEnvironments(projectSlug string) ([]Environment, error) {
	var resp []Environment
	if err := c.do("GET", "/api/v1/projects/"+url.PathEscape(projectSlug)+"/environments", nil, &resp); err != nil {
		return nil, err
	}
	return resp, nil
}

func (c *Client) ListTargets(projectSlug string) ([]Target, error) {
	var resp []Target
	if err := c.do("GET", "/api/v1/projects/"+url.PathEscape(projectSlug)+"/targets", nil, &resp); err != nil {
		return nil, err
	}
	return resp, nil
}

func (c *Client) ListArtifacts(projectSlug string) ([]Artifact, error) {
	var resp []Artifact
	if err := c.do("GET", "/api/v1/projects/"+url.PathEscape(projectSlug)+"/artifacts", nil, &resp); err != nil {
		return nil, err
	}
	return resp, nil
}

func (c *Client) GetProjectStats(projectSlug string) (*ProjectStats, error) {
	var resp ProjectStats
	if err := c.do("GET", "/api/v1/projects/"+url.PathEscape(projectSlug)+"/stats", nil, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

// Waivers.

func (c *Client) CreateWaiver(projectSlug string, req *CreateWaiverRequest) (*Waiver, error) {
	var resp Waiver
	if err := c.do("POST", "/api/v1/projects/"+url.PathEscape(projectSlug)+"/waivers", req, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

func (c *Client) ListWaivers(projectSlug string) ([]Waiver, error) {
	var resp []Waiver
	if err := c.do("GET", "/api/v1/projects/"+url.PathEscape(projectSlug)+"/waivers", nil, &resp); err != nil {
		return nil, err
	}
	return resp, nil
}

func (c *Client) GetWaiver(projectSlug, waiverID string) (*WaiverDetail, error) {
	var resp WaiverDetail
	if err := c.do("GET", "/api/v1/projects/"+url.PathEscape(projectSlug)+"/waivers/"+url.PathEscape(waiverID), nil, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

func (c *Client) UpdateWaiver(projectSlug, waiverID string, req *UpdateWaiverRequest) (*Waiver, error) {
	var resp Waiver
	if err := c.do("PUT", "/api/v1/projects/"+url.PathEscape(projectSlug)+"/waivers/"+url.PathEscape(waiverID), req, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

func (c *Client) DeleteWaiver(projectSlug, waiverID string) error {
	return c.do("DELETE", "/api/v1/projects/"+url.PathEscape(projectSlug)+"/waivers/"+url.PathEscape(waiverID), nil, nil)
}

func (c *Client) ToggleWaiver(projectSlug, waiverID string) (*Waiver, error) {
	var resp Waiver
	if err := c.do("POST", "/api/v1/projects/"+url.PathEscape(projectSlug)+"/waivers/"+url.PathEscape(waiverID)+"/toggle", nil, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

func (c *Client) ListWaiverEvents(projectSlug, waiverID string) ([]WaiverEvent, error) {
	var resp []WaiverEvent
	if err := c.do("GET", "/api/v1/projects/"+url.PathEscape(projectSlug)+"/waivers/"+url.PathEscape(waiverID)+"/events", nil, &resp); err != nil {
		return nil, err
	}
	return resp, nil
}

func (c *Client) CheckWaiverMatch(projectSlug, findingID string) (bool, error) {
	var resp CheckWaiverMatchResponse
	if err := c.do("POST", "/api/v1/projects/"+url.PathEscape(projectSlug)+"/waivers/check-match", map[string]string{"finding_id": findingID}, &resp); err != nil {
		return false, err
	}
	return resp.Matched, nil
}
