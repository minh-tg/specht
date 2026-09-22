package usecase

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/minh-tg/specht/internal/auth"
	"github.com/minh-tg/specht/internal/domain"
	"github.com/minh-tg/specht/internal/port"
	"github.com/minh-tg/specht/internal/remediate"
)

// ProjectResponse is the API representation of a project.
type ProjectResponse struct {
	ID          string    `json:"id"`
	Slug        string    `json:"slug"`
	Name        string    `json:"name"`
	Description *string   `json:"description"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

// FindingResponse is the API representation of a finding.
type FindingResponse struct {
	ID              string    `json:"id"`
	ProjectID       string    `json:"project_id"`
	FindingKind     string    `json:"finding_kind"`
	Fingerprint     string    `json:"fingerprint"`
	CurrentTitle    string    `json:"current_title"`
	CurrentSeverity string    `json:"current_severity"`
	CurrentScore    *float64  `json:"current_score"`
	State           string    `json:"state"`
	TriageStatus    string    `json:"triage_status"`
	AnalysisState   string    `json:"analysis_state"`
	GateEffect      string    `json:"gate_effect"`
	FirstSeenAt     time.Time `json:"first_seen_at"`
	LastSeenAt      time.Time `json:"last_seen_at"`
	CreatedAt       time.Time `json:"created_at"`
	UpdatedAt       time.Time `json:"updated_at"`
	// IntroducedByReportID and IntroducedCommitSha materialize
	// introduced-by-change attribution (SOLO-184): the report that first
	// observed the finding and the revision it scanned. Both nil means
	// unattributed — never a guess.
	IntroducedByReportID *string `json:"introduced_by_report_id,omitempty"`
	IntroducedCommitSha  *string `json:"introduced_commit_sha,omitempty"`
	// Context is the latest observed deployment context. Nil when the
	// finding has no linked scan occurrence — missing context is explicit.
	Context *FindingContextResponse `json:"context,omitempty"`
	// Remediation is the source-aware fix guidance from the latest
	// observation. Nil only when the finding has no linked occurrence;
	// a present-but-empty guidance section means the source supplied
	// nothing usable (labeled per kind, never invented).
	Remediation *RemediationResponse `json:"remediation,omitempty"`
	// Location points at the exact package, rule, resource, file, or URL
	// when the latest observation supplies one.
	Location *LocationResponse `json:"location,omitempty"`
	// Suggestion is the reviewable remediation proposal for this finding,
	// built from persisted dimensions and source guidance.
	Suggestion *SuggestionResponse `json:"suggestion,omitempty"`
}

// FindingContextResponse carries the human-readable deployment context of
// a finding's latest observation for detail views and routing.
type FindingContextResponse struct {
	TargetName      string `json:"target_name,omitempty"`
	TargetKind      string `json:"target_kind,omitempty"`
	TargetOwner     string `json:"target_owner,omitempty"`
	EnvironmentName string `json:"environment_name,omitempty"`
	Branch          string `json:"branch,omitempty"`
	CommitSha       string `json:"commit_sha,omitempty"`
	// SourceLink is the full URL to the source code at the observed commit,
	// derived from TargetOwner (provider://owner/repo) + CommitSha + file.
	// evidence source provenance. Empty when no target owner is set.
	SourceLink string `json:"source_link,omitempty"`
}

// RemediationResponse is one finding's fix guidance with its provenance.
type RemediationResponse struct {
	Summary string `json:"summary,omitempty"`
	URL     string `json:"url,omitempty"`
	// Source names the scanner whose observation supplied the guidance.
	Source string `json:"source,omitempty"`
	// Fallback is true when the source supplied nothing and the section
	// is a kind-level label instead of tool guidance.
	Fallback bool `json:"fallback,omitempty"`
}

// LocationResponse points at the affected subject.
type LocationResponse struct {
	File      string `json:"file,omitempty"`
	StartLine int    `json:"start_line,omitempty"`
	EndLine   int    `json:"end_line,omitempty"`
	Resource  string `json:"resource,omitempty"`
	Summary   string `json:"summary,omitempty"`
}

// SuggestionResponse is one reviewable remediation proposal.
type SuggestionResponse struct {
	Action     string `json:"action"`
	Target     string `json:"target,omitempty"`
	Detail     string `json:"detail,omitempty"`
	Confidence string `json:"confidence"`
	Source     string `json:"source,omitempty"`
}

// suggestionFromEvidence builds the remediation suggestion from persisted
// dimensions plus the assembled remediation section. The fix summary and
// URL come from source guidance when present (rem.Fallback marks their
// absence, in which case only dims feed the model).
func suggestionFromEvidence(f port.Finding, dims []port.FindingDimension, tool string, rem *RemediationResponse) *SuggestionResponse {
	dimMap := make(map[string]string, len(dims))
	for _, d := range dims {
		if _, ok := dimMap[d.Key]; !ok {
			dimMap[d.Key] = d.Value
		}
	}
	in := remediate.Input{
		FindingID: f.ID, FindingKind: f.FindingKind, Title: f.CurrentTitle,
		Dims: dimMap, Tool: tool,
	}
	if rem != nil && !rem.Fallback {
		in.FixSummary, in.FixURL = rem.Summary, rem.URL
	}
	s := remediate.Suggest(in)
	return &SuggestionResponse{
		Action: s.Action, Target: s.Target, Detail: s.Detail,
		Confidence: string(s.Confidence), Source: s.Source,
	}
}

// ReportResponse is the API representation of an ingested report.
type ReportResponse struct {
	ID            string  `json:"id"`
	ProjectID     string  `json:"project_id"`
	ToolName      string  `json:"tool_name"`
	ToolVersion   *string `json:"tool_version"`
	ScanType      string  `json:"scan_type"`
	ScanTarget    *string `json:"scan_target"`
	Status        string  `json:"status"`
	TotalFindings *int32  `json:"total_findings"`
	Branch        *string `json:"branch"`
	CommitSha     *string `json:"commit_sha"`
	// BaseRevision is the revision an incremental scan was compared
	// against; ScanMode is full or incremental; ChangedFiles lists the
	// paths an incremental scan covered. Together they keep incremental
	// scans identified and reproducible (SOLO-165).
	BaseRevision *string    `json:"base_revision,omitempty"`
	ScanMode     string     `json:"scan_mode,omitempty"`
	ChangedFiles []string   `json:"changed_files,omitempty"`
	CreatedAt    time.Time  `json:"created_at"`
	CompletedAt  *time.Time `json:"completed_at"`
}

// FindingEvent is the API representation of a finding audit event.
type FindingEvent struct {
	ID        string    `json:"id"`
	FindingID string    `json:"finding_id"`
	UserID    string    `json:"user_id"`
	EventType string    `json:"event_type"`
	OldValue  *string   `json:"old_value,omitempty"`
	NewValue  *string   `json:"new_value,omitempty"`
	Comment   *string   `json:"comment,omitempty"`
	Changes   []byte    `json:"changes,omitempty"`
	CreatedAt time.Time `json:"created_at"`
}

func uuidStr(id string) string {
	return id
}

func timePtr(t time.Time) time.Time {
	return t
}

func timeOpt(t *time.Time) *time.Time {
	return t
}

func strOpt(t *string) *string {
	return t
}

func scoreOpt(n *float64) *float64 {
	return n
}

func intOpt(i *int32) *int32 {
	return i
}

func toProject(p port.Project) ProjectResponse {
	return ProjectResponse{
		ID:          uuidStr(p.ID),
		Slug:        p.Slug,
		Name:        p.Name,
		Description: strOpt(p.Description),
		CreatedAt:   timePtr(p.CreatedAt),
		UpdatedAt:   timePtr(p.UpdatedAt),
	}
}

func toFinding(f port.Finding) FindingResponse {
	return FindingResponse{
		ID:                   uuidStr(f.ID),
		ProjectID:            uuidStr(f.ProjectID),
		FindingKind:          f.FindingKind,
		Fingerprint:          f.Fingerprint,
		CurrentTitle:         f.CurrentTitle,
		CurrentSeverity:      f.CurrentSeverity,
		CurrentScore:         scoreOpt(f.CurrentScore),
		State:                f.State,
		TriageStatus:         f.TriageStatus,
		AnalysisState:        f.AnalysisState,
		GateEffect:           f.GateEffect,
		FirstSeenAt:          timePtr(f.FirstSeenAt),
		LastSeenAt:           timePtr(f.LastSeenAt),
		CreatedAt:            timePtr(f.CreatedAt),
		UpdatedAt:            timePtr(f.UpdatedAt),
		IntroducedByReportID: strOpt(f.IntroducedByReportID),
		IntroducedCommitSha:  strOpt(f.IntroducedCommitSha),
	}
}

func toReport(r port.Report) ReportResponse {
	return ReportResponse{
		ID:            uuidStr(r.ID),
		ProjectID:     uuidStr(r.ProjectID),
		ToolName:      r.ToolName,
		ToolVersion:   strOpt(r.ToolVersion),
		ScanType:      r.ScanType,
		ScanTarget:    strOpt(r.ScanTarget),
		Status:        r.Status,
		TotalFindings: intOpt(r.TotalFindings),
		Branch:        strOpt(r.Branch),
		CommitSha:     strOpt(r.CommitSha),
		BaseRevision:  strOpt(r.BaseRevision),
		ScanMode:      r.ScanMode,
		ChangedFiles:  changedFilesOpt(r.ChangedFiles),
		CreatedAt:     timePtr(r.CreatedAt),
		CompletedAt:   timeOpt(r.CompletedAt),
	}
}

// changedFilesOpt decodes the stored path list; corrupt or empty content
// decodes as nil so readers never see a half-parsed list.
func changedFilesOpt(raw json.RawMessage) []string {
	if len(raw) == 0 {
		return nil
	}
	var files []string
	if err := json.Unmarshal(raw, &files); err != nil {
		return nil
	}
	return files
}

// CreateProject creates a project and makes the creator its admin member,
// establishing the tenant-isolation invariant that every project has an
// admin (H1). Callers pass the authenticated session user ID as creatorID;
// API keys cannot create projects (the route is admin-gated and API keys
// never satisfy global-admin membership rules).
func (u *Usecases) CreateProject(ctx context.Context, name, slug, description, creatorID string) (*ProjectResponse, error) {
	p, err := u.deps.Stores.Projects.Create(ctx, port.CreateProjectInput{
		Slug:                slug,
		Name:                name,
		Description:         description,
		DeploymentThreshold: "high",
		Settings:            []byte("{}"),
	})
	if err != nil {
		return nil, fmt.Errorf("create project %q: %w", slug, err)
	}
	if _, err := u.deps.Stores.Projects.UpsertMember(ctx, p.ID, creatorID, auth.RoleAdmin); err != nil {
		// No transaction spans project creation and member grant, so remove
		// the orphaned project: an admin-less project would be unreachable
		// to every non-global-admin (H1).
		if delErr := u.deleteProjectBySlug(ctx, p.Slug); delErr != nil {
			slog.Error("rollback project after admin-grant failure", "slug", p.Slug, "error", delErr)
		}
		return nil, fmt.Errorf("grant creator admin membership: %w", err)
	}
	resp := toProject(p)
	return &resp, nil
}

// UpdateProject renames a project and/or changes its description. Only
// global admins and project-admin members may mutate a project (the same
// gate as member management); API keys never may. A nil name leaves the
// name unchanged; a nil description leaves the description unchanged while
// a blank description clears it.
func (u *Usecases) UpdateProject(ctx context.Context, slug string, name, description *string) (*ProjectResponse, error) {
	p, err := u.deps.Stores.Projects.GetBySlug(ctx, slug)
	if err != nil {
		return nil, fmt.Errorf("project not found: %w", err)
	}
	if err := u.requireProjectAdmin(ctx, p.ID); err != nil {
		return nil, err
	}
	newName := p.Name
	if name != nil && strings.TrimSpace(*name) != "" {
		newName = strings.TrimSpace(*name)
	}
	newDesc := p.Description
	if description != nil {
		trimmed := strings.TrimSpace(*description)
		if trimmed == "" {
			newDesc = nil
		} else {
			newDesc = &trimmed
		}
	}
	updated, err := u.deps.Stores.Projects.Update(ctx, slug, newName, newDesc)
	if err != nil {
		return nil, fmt.Errorf("update project %q: %w", slug, err)
	}
	resp := toProject(updated)
	return &resp, nil
}

// DeleteProject removes a project and all its data (reports, findings,
// waivers, members, API keys cascade via ON DELETE CASCADE). Gated like
// UpdateProject. Returns the deleted project for audit purposes.
func (u *Usecases) DeleteProject(ctx context.Context, slug string) (*ProjectResponse, error) {
	p, err := u.deps.Stores.Projects.GetBySlug(ctx, slug)
	if err != nil {
		return nil, fmt.Errorf("project not found: %w", err)
	}
	if err := u.requireProjectAdmin(ctx, p.ID); err != nil {
		return nil, err
	}
	deleted, err := u.deps.Stores.Projects.Delete(ctx, slug)
	if err != nil {
		return nil, fmt.Errorf("delete project %q: %w", slug, err)
	}
	resp := toProject(deleted)
	return &resp, nil
}

// deleteProjectBySlug removes a project without access checks. It is the
// compensating action for CreateProject: only the creator flow uses it,
// immediately after creating a project whose admin grant failed.
func (u *Usecases) deleteProjectBySlug(ctx context.Context, slug string) error {
	_, err := u.deps.Stores.Projects.Delete(ctx, slug)
	return err
}

// ListProjects returns the projects the caller's identity may see (H1).
// Global admins see everything; project-scoped API keys see only their own
// project; other session users see only projects they belong to.
func (u *Usecases) ListProjects(ctx context.Context) ([]ProjectResponse, error) {
	ident := auth.ContextIdentity(ctx)
	if ident == nil {
		return nil, ErrProjectAccessDenied
	}
	if ident.IsAPIKey {
		if ident.ProjectID == "" {
			return nil, ErrProjectAccessDenied
		}
		p, err := u.deps.Stores.Projects.GetByID(ctx, ident.ProjectID)
		if err != nil {
			if errors.Is(err, port.ErrNotFound) {
				return []ProjectResponse{}, nil
			}
			return nil, fmt.Errorf("get api key project: %w", err)
		}
		return []ProjectResponse{toProject(p)}, nil
	}
	if ident.Role == auth.RoleAdmin {
		projects, err := u.deps.Stores.Projects.List(ctx)
		if err != nil {
			return nil, fmt.Errorf("list projects: %w", err)
		}
		return toProjects(projects), nil
	}

	// Non-admin session users see only accessible projects (direct or team).
	ids, err := u.deps.Stores.Projects.ListAccessibleProjectIDs(ctx, ident.UserID)
	if err != nil {
		return nil, fmt.Errorf("list member projects: %w", err)
	}
	if len(ids) == 0 {
		return []ProjectResponse{}, nil
	}

	projects, err := u.deps.Stores.Projects.ListByIDs(ctx, ids)
	if err != nil {
		return nil, fmt.Errorf("list projects by ids: %w", err)
	}
	return toProjects(projects), nil
}

func toProjects(projects []port.Project) []ProjectResponse {
	resp := make([]ProjectResponse, len(projects))
	for i, p := range projects {
		resp[i] = toProject(p)
	}
	return resp
}

// GetProject resolves a project by slug for principals authorized to see
// it (H1): global admins, project members, or the project-scoped API key.
// Everyone else — including unauthenticated callers — gets a denial that
// does not disclose whether the slug exists.
func (u *Usecases) GetProject(ctx context.Context, slug string) (*ProjectResponse, error) {
	p, err := u.deps.Stores.Projects.GetBySlug(ctx, slug)
	if err != nil {
		return nil, fmt.Errorf("get project %q: %w", slug, err)
	}
	ident := auth.ContextIdentity(ctx)
	if ident == nil {
		return nil, ErrProjectAccessDenied
	}
	if ident.IsAPIKey {
		if p.ID != ident.ProjectID {
			return nil, ErrProjectAccessDenied
		}
		resp := toProject(p)
		return &resp, nil
	}
	if ident.Role == auth.RoleAdmin {
		resp := toProject(p)
		return &resp, nil
	}
	ok, err := u.deps.Stores.Projects.IsMemberEffective(ctx, p.ID, ident.UserID)
	if err != nil {
		return nil, fmt.Errorf("check membership: %w", err)
	}
	if !ok {
		return nil, ErrProjectAccessDenied
	}
	resp := toProject(p)
	return &resp, nil
}

// FindingFilter scopes a finding list. All fields are optional; empty means
// unfiltered. Environments and Targets match by name against the
// environments/targets linked to a finding's observations.
type FindingFilter struct {
	Severities   []string
	States       []string
	Kinds        []string
	Environments []string
	Targets      []string
}

func (u *Usecases) ListFindings(ctx context.Context, projectSlug string, filter FindingFilter, limit, offset int32) ([]FindingResponse, error) {
	project, err := u.deps.Stores.Projects.GetBySlug(ctx, projectSlug)
	if err != nil {
		return nil, fmt.Errorf(errLookupProjectFormat, projectSlug, err)
	}

	findings, err := u.deps.Stores.Findings.ListByProject(ctx, project.ID, port.ListFindingsParams{
		Severities:   filter.Severities,
		States:       filter.States,
		Kinds:        filter.Kinds,
		Environments: filter.Environments,
		Targets:      filter.Targets,
		Limit:        limit,
		Offset:       offset,
	})
	if err != nil {
		return nil, fmt.Errorf("list findings: %w", err)
	}

	resp := make([]FindingResponse, len(findings))
	for i, f := range findings {
		resp[i] = toFinding(f)
	}
	return resp, nil
}

func (u *Usecases) GetFinding(ctx context.Context, findingID string) (*FindingResponse, error) {
	id, err := uuid.Parse(findingID)
	if err != nil {
		return nil, fmt.Errorf("invalid finding id: %w", err)
	}
	f, err := u.deps.Stores.Findings.GetByID(ctx, id.String())
	if err != nil {
		return nil, fmt.Errorf("get finding: %w", err)
	}
	if err := u.checkFindingProjectIDAccess(ctx, f.ProjectID); err != nil {
		return nil, err
	}
	resp := toFinding(f)
	dc, err := u.deps.Stores.Findings.GetFindingDisplayContext(ctx, id.String())
	if err != nil && !errors.Is(err, port.ErrNotFound) {
		return nil, fmt.Errorf("get finding context: %w", err)
	}
	if err == nil {
		resp.Context = &FindingContextResponse{
			TargetName:      dc.TargetName,
			TargetKind:      dc.TargetKind,
			TargetOwner:     dc.TargetOwner,
			EnvironmentName: dc.EnvironmentName,
			Branch:          dc.Branch,
			CommitSha:       dc.CommitSha,
		}
		resp.Remediation = remediationFromMetadata(dc.Metadata, dc.ToolName, f.FindingKind)
		resp.Location = locationFromDisplay(dc.LocationSummary, dc.Metadata)
		// derive source provenance link from provider:// owner URI.
		if ref, err := domain.ParseRepoRef(dc.TargetOwner); err == nil && ref.Provider != "" {
			var filePath string
			if resp.Location != nil {
				filePath = resp.Location.File
			}
			resp.Context.SourceLink = ref.SourceLink(dc.CommitSha, filePath)
		}
		dims, err := u.deps.Stores.Findings.ListDimensions(ctx, id.String())
		if err != nil {
			return nil, fmt.Errorf("get finding dimensions: %w", err)
		}
		resp.Suggestion = suggestionFromEvidence(f, dims, dc.ToolName, resp.Remediation)
	}
	return &resp, nil
}

// spechtMetadata is the canonical namespace of an occurrence metadata
// document (see buildOccurrenceDocument).
type spechtMetadata struct {
	Specht struct {
		Fix struct {
			Summary     string `json:"Summary"`
			Description string `json:"Description"`
			URL         string `json:"URL"`
			Diff        string `json:"Diff"`
		} `json:"fix"`
		CodeLocation struct {
			File        string `json:"File"`
			StartLine   int    `json:"StartLine"`
			EndLine     int    `json:"EndLine"`
			StartColumn int    `json:"StartColumn"`
			EndColumn   int    `json:"EndColumn"`
		} `json:"code_location"`
		Resource string `json:"resource"`
	} `json:"specht"`
}

// remediationFromMetadata builds the fix guidance section from the latest
// occurrence metadata. Source guidance wins; otherwise a kind-level label
// marks the gap explicitly instead of inventing a fix.
func remediationFromMetadata(metadata json.RawMessage, tool, kind string) *RemediationResponse {
	var doc spechtMetadata
	if len(metadata) > 0 {
		_ = json.Unmarshal(metadata, &doc)
	}
	if doc.Specht.Fix.Summary != "" || doc.Specht.Fix.URL != "" {
		return &RemediationResponse{
			Summary: doc.Specht.Fix.Summary,
			URL:     doc.Specht.Fix.URL,
			Source:  tool,
		}
	}
	return &RemediationResponse{Summary: fixFallback(kind), Source: tool, Fallback: true}
}

// locationFromDisplay points at the affected subject from the latest
// observation summary and code location. Nil when neither exists.
func locationFromDisplay(summary string, metadata json.RawMessage) *LocationResponse {
	var doc spechtMetadata
	if len(metadata) > 0 {
		_ = json.Unmarshal(metadata, &doc)
	}
	loc := &LocationResponse{Summary: summary}
	if doc.Specht.CodeLocation.File != "" {
		loc.File = doc.Specht.CodeLocation.File
		loc.StartLine = doc.Specht.CodeLocation.StartLine
		loc.EndLine = doc.Specht.CodeLocation.EndLine
	}
	if doc.Specht.Resource != "" {
		loc.Resource = doc.Specht.Resource
	}
	if loc.File == "" && loc.Resource == "" && loc.Summary == "" {
		return nil
	}
	return loc
}

// fixFallback labels missing remediation data per kind. These are pointers
// to where guidance lives, never fixes themselves.
func fixFallback(kind string) string {
	switch kind {
	case "sca":
		return "No fixed version reported by the scanner — check the advisory references for upgrade guidance."
	case "sast":
		return "No fix description reported — follow the rule documentation for the secure coding pattern."
	case "iac":
		return "No remediation reported — see the policy guideline for the required configuration."
	case "secret":
		return "Rotate the exposed credential with its provider, revoke the old value, and purge it from history."
	case "dast":
		return "No remediation reported — reproduce against the observed URL and follow the linked references."
	default:
		return "No remediation reported by the scanner for this finding."
	}
}

func (u *Usecases) ListReports(ctx context.Context, projectSlug string, limit, offset int32) ([]ReportResponse, error) {
	project, err := u.deps.Stores.Projects.GetBySlug(ctx, projectSlug)
	if err != nil {
		return nil, fmt.Errorf(errLookupProjectFormat, projectSlug, err)
	}

	reports, err := u.deps.Stores.Reports.ListByProject(ctx, project.ID, limit, offset)
	if err != nil {
		return nil, fmt.Errorf("list reports: %w", err)
	}

	resp := make([]ReportResponse, len(reports))
	for i, r := range reports {
		resp[i] = toReport(r)
	}
	return resp, nil
}

func (u *Usecases) GetReport(ctx context.Context, reportID string) (*ReportResponse, error) {
	r, err := u.deps.Stores.Reports.GetByID(ctx, reportID)
	if err != nil {
		return nil, fmt.Errorf("get report: %w", err)
	}
	if err := u.checkFindingProjectIDAccess(ctx, r.ProjectID); err != nil {
		return nil, err
	}
	resp := toReport(r)
	return &resp, nil
}

// EnvironmentResponse is the API representation of a deployment environment.
type EnvironmentResponse struct {
	ID              string `json:"id"`
	ProjectID       string `json:"project_id"`
	Name            string `json:"name"`
	Tier            string `json:"tier"`
	InternetFacing  bool   `json:"internet_facing"`
	DataSensitivity string `json:"data_sensitivity"`
	CreatedAt       string `json:"created_at"`
}

// TargetResponse is the API representation of a scan target.
type TargetResponse struct {
	ID        string `json:"id"`
	ProjectID string `json:"project_id"`
	Name      string `json:"name"`
	Kind      string `json:"kind"`
	Locator   string `json:"locator,omitempty"`
	CreatedAt string `json:"created_at"`
}

// ArtifactResponse is the API representation of an artifact.
type ArtifactResponse struct {
	ID           string `json:"id"`
	ProjectID    string `json:"project_id"`
	TargetID     string `json:"target_id,omitempty"`
	ArtifactType string `json:"artifact_type"`
	Name         string `json:"name"`
	Version      string `json:"version,omitempty"`
	Digest       string `json:"digest,omitempty"`
	Locator      string `json:"locator,omitempty"`
	CreatedAt    string `json:"created_at"`
}

func toEnvironment(e port.Environment) EnvironmentResponse {
	return EnvironmentResponse{
		ID:        uuidStr(e.ID),
		ProjectID: uuidStr(e.ProjectID),
		Name:      e.Name,
		Tier:      e.Tier,
		CreatedAt: e.CreatedAt.Format(time.RFC3339),
	}
}

func toTarget(t port.Target) TargetResponse {
	var locator string
	if t.Locator != nil {
		locator = *t.Locator
	}
	return TargetResponse{
		ID:        uuidStr(t.ID),
		ProjectID: uuidStr(t.ProjectID),
		Name:      t.Name,
		Kind:      t.Kind,
		Locator:   locator,
		CreatedAt: t.CreatedAt.Format(time.RFC3339),
	}
}

func toArtifact(a port.Artifact) ArtifactResponse {
	var version string
	if a.Version != nil {
		version = *a.Version
	}
	return ArtifactResponse{
		ID:           uuidStr(a.ID),
		ProjectID:    uuidStr(a.ProjectID),
		TargetID:     uuidStr(a.TargetID),
		ArtifactType: a.ArtifactType,
		Name:         a.Name,
		Version:      version,
		CreatedAt:    a.CreatedAt.Format(time.RFC3339),
	}
}

func (u *Usecases) ListEnvironments(ctx context.Context, projectSlug string) ([]EnvironmentResponse, error) {
	project, err := u.deps.Stores.Projects.GetBySlug(ctx, projectSlug)
	if err != nil {
		return nil, fmt.Errorf(errLookupProjectFormat, projectSlug, err)
	}
	envs, err := u.deps.Stores.Environments.List(ctx, project.ID)
	if err != nil {
		return nil, fmt.Errorf("list environments: %w", err)
	}
	resp := make([]EnvironmentResponse, len(envs))
	for i, e := range envs {
		resp[i] = toEnvironment(e)
	}
	return resp, nil
}

func (u *Usecases) ListTargets(ctx context.Context, projectSlug string) ([]TargetResponse, error) {
	project, err := u.deps.Stores.Projects.GetBySlug(ctx, projectSlug)
	if err != nil {
		return nil, fmt.Errorf(errLookupProjectFormat, projectSlug, err)
	}
	targets, err := u.deps.Stores.Targets.List(ctx, project.ID)
	if err != nil {
		return nil, fmt.Errorf("list targets: %w", err)
	}
	resp := make([]TargetResponse, len(targets))
	for i, t := range targets {
		resp[i] = toTarget(t)
	}
	return resp, nil
}

func (u *Usecases) ListArtifacts(ctx context.Context, projectSlug string) ([]ArtifactResponse, error) {
	project, err := u.deps.Stores.Projects.GetBySlug(ctx, projectSlug)
	if err != nil {
		return nil, fmt.Errorf(errLookupProjectFormat, projectSlug, err)
	}
	artifacts, err := u.deps.Stores.Artifacts.List(ctx, project.ID)
	if err != nil {
		return nil, fmt.Errorf("list artifacts: %w", err)
	}
	resp := make([]ArtifactResponse, len(artifacts))
	for i, a := range artifacts {
		resp[i] = toArtifact(a)
	}
	return resp, nil
}
