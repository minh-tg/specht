package usecase

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/xMinhx/specht/internal/db/sqlc"
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
}

// ReportResponse is the API representation of an ingested report.
type ReportResponse struct {
	ID            string     `json:"id"`
	ProjectID     string     `json:"project_id"`
	ToolName      string     `json:"tool_name"`
	ToolVersion   *string    `json:"tool_version"`
	ScanType      string     `json:"scan_type"`
	ScanTarget    *string    `json:"scan_target"`
	Status        string     `json:"status"`
	TotalFindings *int32     `json:"total_findings"`
	Branch        *string    `json:"branch"`
	CommitSha     *string    `json:"commit_sha"`
	CreatedAt     time.Time  `json:"created_at"`
	CompletedAt   *time.Time `json:"completed_at"`
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

func uuidStr(id pgtype.UUID) string {
	if !id.Valid {
		return ""
	}
	return uuid.UUID(id.Bytes).String()
}

func timePtr(t pgtype.Timestamptz) time.Time {
	return t.Time
}

func timeOpt(t pgtype.Timestamptz) *time.Time {
	if !t.Valid {
		return nil
	}
	return &t.Time
}

func strOpt(t pgtype.Text) *string {
	if !t.Valid {
		return nil
	}
	return &t.String
}

func scoreOpt(n pgtype.Numeric) *float64 {
	if !n.Valid {
		return nil
	}
	f, _ := n.Float64Value()
	if !f.Valid {
		return nil
	}
	return &f.Float64
}

func intOpt(i pgtype.Int4) *int32 {
	if !i.Valid {
		return nil
	}
	return &i.Int32
}

func toProject(p sqlc.Project) ProjectResponse {
	return ProjectResponse{
		ID:          uuidStr(p.ID),
		Slug:        p.Slug,
		Name:        p.Name,
		Description: strOpt(p.Description),
		CreatedAt:   timePtr(p.CreatedAt),
		UpdatedAt:   timePtr(p.UpdatedAt),
	}
}

func toFinding(f sqlc.Finding) FindingResponse {
	return FindingResponse{
		ID:              uuidStr(f.ID),
		ProjectID:       uuidStr(f.ProjectID),
		FindingKind:     f.FindingKind,
		Fingerprint:     f.Fingerprint,
		CurrentTitle:    f.CurrentTitle,
		CurrentSeverity: f.CurrentSeverity,
		CurrentScore:    scoreOpt(f.CurrentScore),
		State:           f.State,
		TriageStatus:    f.TriageStatus,
		AnalysisState:   f.AnalysisState,
		GateEffect:      f.GateEffect,
		FirstSeenAt:     timePtr(f.FirstSeenAt),
		LastSeenAt:      timePtr(f.LastSeenAt),
		CreatedAt:       timePtr(f.CreatedAt),
		UpdatedAt:       timePtr(f.UpdatedAt),
	}
}

func toReport(r sqlc.Report) ReportResponse {
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
		CreatedAt:     timePtr(r.CreatedAt),
		CompletedAt:   timeOpt(r.CompletedAt),
	}
}

func (u *Usecases) CreateProject(ctx context.Context, name, slug, description string) (*ProjectResponse, error) {
	p, err := u.deps.Repos.Projects.Create(ctx, sqlc.CreateProjectParams{
		Slug:                slug,
		Name:                name,
		Description:         pgtype.Text{String: description, Valid: description != ""},
		DeploymentThreshold: "high",
		Settings:            []byte("{}"),
	})
	if err != nil {
		return nil, fmt.Errorf("create project %q: %w", slug, err)
	}
	resp := toProject(p)
	return &resp, nil
}

func (u *Usecases) ListProjects(ctx context.Context) ([]ProjectResponse, error) {
	projects, err := u.deps.Repos.Projects.List(ctx)
	if err != nil {
		return nil, fmt.Errorf("list projects: %w", err)
	}
	resp := make([]ProjectResponse, len(projects))
	for i, p := range projects {
		resp[i] = toProject(p)
	}
	return resp, nil
}

func (u *Usecases) GetProject(ctx context.Context, slug string) (*ProjectResponse, error) {
	p, err := u.deps.Repos.Projects.GetBySlug(ctx, slug)
	if err != nil {
		return nil, fmt.Errorf("get project %q: %w", slug, err)
	}
	resp := toProject(p)
	return &resp, nil
}

func (u *Usecases) ListFindings(ctx context.Context, projectSlug string, severities, states, kinds []string, limit, offset int32) ([]FindingResponse, error) {
	project, err := u.deps.Repos.Projects.GetBySlug(ctx, projectSlug)
	if err != nil {
		return nil, fmt.Errorf("lookup project %q: %w", projectSlug, err)
	}

	findings, err := u.deps.Repos.Findings.ListByProject(ctx, project.ID, severities, states, kinds, limit, offset)
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
	f, err := u.deps.Repos.Findings.GetByID(ctx, pgtype.UUID{Bytes: id, Valid: true})
	if err != nil {
		return nil, fmt.Errorf("get finding: %w", err)
	}
	if err := checkFindingProjectIDAccess(ctx, f.ProjectID); err != nil {
		return nil, err
	}
	resp := toFinding(f)
	return &resp, nil
}

func (u *Usecases) ListReports(ctx context.Context, projectSlug string, limit, offset int32) ([]ReportResponse, error) {
	project, err := u.deps.Repos.Projects.GetBySlug(ctx, projectSlug)
	if err != nil {
		return nil, fmt.Errorf("lookup project %q: %w", projectSlug, err)
	}

	reports, err := u.deps.Repos.Reports.ListByProject(ctx, project.ID, limit, offset)
	if err != nil {
		return nil, fmt.Errorf("list reports: %w", err)
	}

	resp := make([]ReportResponse, len(reports))
	for i, r := range reports {
		resp[i] = toReport(r)
	}
	return resp, nil
}

func (u *Usecases) GetReport(ctx context.Context, reportID pgtype.UUID) (*ReportResponse, error) {
	r, err := u.deps.Repos.Reports.GetByID(ctx, reportID)
	if err != nil {
		return nil, fmt.Errorf("get report: %w", err)
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

func toEnvironment(e sqlc.Environment) EnvironmentResponse {
	return EnvironmentResponse{
		ID:              uuidStr(e.ID),
		ProjectID:       uuidStr(e.ProjectID),
		Name:            e.Name,
		Tier:            e.Tier,
		InternetFacing:  e.InternetFacing,
		DataSensitivity: e.DataSensitivity,
		CreatedAt:       e.CreatedAt.Time.Format(time.RFC3339),
	}
}

func toTarget(t sqlc.Target) TargetResponse {
	return TargetResponse{
		ID:        uuidStr(t.ID),
		ProjectID: uuidStr(t.ProjectID),
		Name:      t.Name,
		Kind:      t.Kind,
		Locator:   t.Locator.String,
		CreatedAt: t.CreatedAt.Time.Format(time.RFC3339),
	}
}

func toArtifact(a sqlc.Artifact) ArtifactResponse {
	return ArtifactResponse{
		ID:           uuidStr(a.ID),
		ProjectID:    uuidStr(a.ProjectID),
		TargetID:     uuidStr(a.TargetID),
		ArtifactType: a.ArtifactType,
		Name:         a.Name,
		Version:      a.Version.String,
		Digest:       a.Digest.String,
		Locator:      a.Locator.String,
		CreatedAt:    a.CreatedAt.Time.Format(time.RFC3339),
	}
}

func (u *Usecases) ListEnvironments(ctx context.Context, projectSlug string) ([]EnvironmentResponse, error) {
	project, err := u.deps.Repos.Projects.GetBySlug(ctx, projectSlug)
	if err != nil {
		return nil, fmt.Errorf("lookup project %q: %w", projectSlug, err)
	}
	envs, err := u.deps.Repos.Environments.List(ctx, project.ID)
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
	project, err := u.deps.Repos.Projects.GetBySlug(ctx, projectSlug)
	if err != nil {
		return nil, fmt.Errorf("lookup project %q: %w", projectSlug, err)
	}
	targets, err := u.deps.Repos.Targets.List(ctx, project.ID)
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
	project, err := u.deps.Repos.Projects.GetBySlug(ctx, projectSlug)
	if err != nil {
		return nil, fmt.Errorf("lookup project %q: %w", projectSlug, err)
	}
	artifacts, err := u.deps.Repos.Artifacts.List(ctx, project.ID)
	if err != nil {
		return nil, fmt.Errorf("list artifacts: %w", err)
	}
	resp := make([]ArtifactResponse, len(artifacts))
	for i, a := range artifacts {
		resp[i] = toArtifact(a)
	}
	return resp, nil
}
