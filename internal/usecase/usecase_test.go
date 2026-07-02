package usecase

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"testing"

	"github.com/jackc/pgx/v5/pgtype"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/xMinhx/specht/internal/db/sqlc"
	"github.com/xMinhx/specht/internal/repo"
	"github.com/xMinhx/specht/internal/scanner"
)

type mockProjectRepo struct {
	repo.ProjectRepo
	getBySlugFn func(ctx context.Context, slug string) (sqlc.Project, error)
}

func (m *mockProjectRepo) GetBySlug(ctx context.Context, slug string) (sqlc.Project, error) {
	if m.getBySlugFn == nil {
		return sqlc.Project{}, fmt.Errorf("unexpected call to GetBySlug")
	}
	return m.getBySlugFn(ctx, slug)
}

type mockReportRepo struct {
	repo.ReportRepo
	createFn       func(ctx context.Context, arg repo.CreateReportParams) (sqlc.Report, error)
	updateStatusFn func(ctx context.Context, id, projectID pgtype.UUID, status string, totalFindings int, errorMsg pgtype.Text) (sqlc.Report, error)
}

func (m *mockReportRepo) Create(ctx context.Context, arg repo.CreateReportParams) (sqlc.Report, error) {
	if m.createFn == nil {
		return sqlc.Report{}, fmt.Errorf("unexpected call to Create")
	}
	return m.createFn(ctx, arg)
}

func (m *mockReportRepo) UpdateStatus(ctx context.Context, id, projectID pgtype.UUID, status string, totalFindings int, errorMsg pgtype.Text) (sqlc.Report, error) {
	if m.updateStatusFn == nil {
		return sqlc.Report{}, fmt.Errorf("unexpected call to UpdateStatus")
	}
	return m.updateStatusFn(ctx, id, projectID, status, totalFindings, errorMsg)
}

type mockFindingRepo struct {
	repo.FindingRepo
	upsertFn           func(ctx context.Context, arg repo.UpsertFindingParams) (sqlc.Finding, error)
	createOccurrenceFn func(ctx context.Context, arg repo.CreateOccurrenceParams) (sqlc.FindingOccurrence, error)
	upsertDimensionFn  func(ctx context.Context, arg repo.UpsertDimensionParams) (sqlc.FindingDimension, error)
	listByProjectFn    func(ctx context.Context, projectID pgtype.UUID, severities, states []string, limit, offset int32) ([]sqlc.Finding, error)
}

func (m *mockFindingRepo) Upsert(ctx context.Context, arg repo.UpsertFindingParams) (sqlc.Finding, error) {
	if m.upsertFn == nil {
		return sqlc.Finding{}, fmt.Errorf("unexpected call to Upsert")
	}
	return m.upsertFn(ctx, arg)
}

func (m *mockFindingRepo) CreateOccurrence(ctx context.Context, arg repo.CreateOccurrenceParams) (sqlc.FindingOccurrence, error) {
	if m.createOccurrenceFn == nil {
		return sqlc.FindingOccurrence{}, fmt.Errorf("unexpected call to CreateOccurrence")
	}
	return m.createOccurrenceFn(ctx, arg)
}

func (m *mockFindingRepo) UpsertDimension(ctx context.Context, arg repo.UpsertDimensionParams) (sqlc.FindingDimension, error) {
	if m.upsertDimensionFn == nil {
		return sqlc.FindingDimension{}, fmt.Errorf("unexpected call to UpsertDimension")
	}
	return m.upsertDimensionFn(ctx, arg)
}

func (m *mockFindingRepo) ListByProject(ctx context.Context, projectID pgtype.UUID, severities, states []string, limit, offset int32) ([]sqlc.Finding, error) {
	if m.listByProjectFn == nil {
		return []sqlc.Finding{}, nil
	}
	return m.listByProjectFn(ctx, projectID, severities, states, limit, offset)
}

type mockParser struct {
	name      string
	scanTypes []scanner.ScanType
	parseFn   func(ctx context.Context, input []byte) (*scanner.NormalizedReport, error)
}

func (m *mockParser) Name() string                        { return m.name }
func (m *mockParser) ScanTypes() []scanner.ScanType       { return m.scanTypes }
func (m *mockParser) Parse(ctx context.Context, r io.Reader) (*scanner.NormalizedReport, error) {
	if m.parseFn == nil {
		return nil, fmt.Errorf("unexpected call to Parse")
	}
	input, _ := io.ReadAll(r)
	return m.parseFn(ctx, input)
}

func makeTestRepos() (*mockProjectRepo, *mockReportRepo, *mockFindingRepo) {
	pr := &mockProjectRepo{}
	rr := &mockReportRepo{}
	fr := &mockFindingRepo{}
	return pr, rr, fr
}

func makeProject(valid bool) sqlc.Project {
	if !valid {
		return sqlc.Project{}
	}
	var id pgtype.UUID
	id.Scan("00000000-0000-0000-0000-000000000001")
	return sqlc.Project{
		ID:   id,
		Slug: "my-app",
		Name: "My App",
	}
}

func makeReport() sqlc.Report {
	var id, pid pgtype.UUID
	id.Scan("00000000-0000-0000-0000-000000000010")
	pid.Scan("00000000-0000-0000-0000-000000000001")
	return sqlc.Report{
		ID:        id,
		ProjectID: pid,
		ToolName:  "trivy",
		Status:    "completed",
		TotalFindings: pgtype.Int4{Int32: 2, Valid: true},
	}
}

func makeFinding(idIdx int) sqlc.Finding {
	var id, pid pgtype.UUID
	id.Scan(fmt.Sprintf("00000000-0000-0000-0000-00000000002%d", idIdx))
	pid.Scan("00000000-0000-0000-0000-000000000001")
	return sqlc.Finding{
		ID:        id,
		ProjectID: pid,
		FindingKind: "sca",
		Fingerprint: "fp1",
	}
}

func TestIngestReport_Success(t *testing.T) {
	pr, rr, fr := makeTestRepos()

	pr.getBySlugFn = func(ctx context.Context, slug string) (sqlc.Project, error) {
		return makeProject(true), nil
	}

	rr.createFn = func(ctx context.Context, arg repo.CreateReportParams) (sqlc.Report, error) {
		return makeReport(), nil
	}

	rr.updateStatusFn = func(ctx context.Context, id, projectID pgtype.UUID, status string, totalFindings int, errorMsg pgtype.Text) (sqlc.Report, error) {
		r := makeReport()
		r.Status = status
		return r, nil
	}

	callCount := 0
	fr.upsertFn = func(ctx context.Context, arg repo.UpsertFindingParams) (sqlc.Finding, error) {
		callCount++
		return makeFinding(callCount), nil
	}

	fr.createOccurrenceFn = func(ctx context.Context, arg repo.CreateOccurrenceParams) (sqlc.FindingOccurrence, error) {
		return sqlc.FindingOccurrence{}, nil
	}

	fr.upsertDimensionFn = func(ctx context.Context, arg repo.UpsertDimensionParams) (sqlc.FindingDimension, error) {
		return sqlc.FindingDimension{}, nil
	}

	reg := scanner.NewRegistry()
	reg.Register(&mockParser{
		name:      "trivy",
		scanTypes: []scanner.ScanType{scanner.ScanTypeImage},
		parseFn: func(ctx context.Context, input []byte) (*scanner.NormalizedReport, error) {
			return &scanner.NormalizedReport{
				ScannerName: "trivy",
				ScanType:    scanner.ScanTypeImage,
				Target:      &scanner.TargetInfo{Kind: "container", Identifier: "myapp:latest"},
				Findings: []scanner.NormalizedFinding{
					{
						Fingerprint: "fp1",
						FindingKind: "sca",
						Title:       "CVE-2026-1234",
						Severity:    scanner.SeverityHigh,
						Score:       7.5,
						Dimensions:  []scanner.Dimension{{Key: "vulnerability.id", Value: "CVE-2026-1234"}},
						Display:     map[string]any{"title": "CVE-2026-1234"},
						Metadata:    map[string]any{"cvss": "7.5"},
					},
					{
						Fingerprint: "fp2",
						FindingKind: "sca",
						Title:       "CVE-2026-5678",
						Severity:    scanner.SeverityMedium,
						Score:       5.0,
					},
				},
				ScanScope: map[string]any{"packages": 150},
			}, nil
		},
	})

	uc := New(Deps{
		Repos: &repo.Repos{
			Projects: pr,
			Reports:  rr,
			Findings: fr,
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
	pr.getBySlugFn = func(ctx context.Context, slug string) (sqlc.Project, error) {
		return sqlc.Project{}, fmt.Errorf("not found")
	}

	uc := New(Deps{
		Repos: &repo.Repos{Projects: pr},
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
	pr.getBySlugFn = func(ctx context.Context, slug string) (sqlc.Project, error) {
		return makeProject(true), nil
	}

	uc := New(Deps{
		Repos:    &repo.Repos{Projects: pr},
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
	pr.getBySlugFn = func(ctx context.Context, slug string) (sqlc.Project, error) {
		return makeProject(true), nil
	}

	reg := scanner.NewRegistry()
	reg.Register(&mockParser{
		name:      "trivy",
		scanTypes: []scanner.ScanType{scanner.ScanTypeImage},
		parseFn: func(ctx context.Context, input []byte) (*scanner.NormalizedReport, error) {
			return nil, fmt.Errorf("invalid scan data")
		},
	})

	uc := New(Deps{
		Repos:    &repo.Repos{Projects: pr},
		Registry: reg,
	})
	_, err := uc.IngestReport(context.Background(), IngestReportInput{
		ProjectSlug: "my-app",
		Scanner:     "trivy",
		RawData:     json.RawMessage(`bad data`),
	})
	assert.ErrorContains(t, err, "parse trivy output")
}

func TestIngestReport_ThresholdBreached(t *testing.T) {
	pr, rr, fr := makeTestRepos()

	pr.getBySlugFn = func(ctx context.Context, slug string) (sqlc.Project, error) {
		return makeProject(true), nil
	}

	rr.createFn = func(ctx context.Context, arg repo.CreateReportParams) (sqlc.Report, error) {
		return makeReport(), nil
	}

	rr.updateStatusFn = func(ctx context.Context, id, projectID pgtype.UUID, status string, totalFindings int, errorMsg pgtype.Text) (sqlc.Report, error) {
		r := makeReport()
		r.Status = status
		return r, nil
	}

	fr.upsertFn = func(ctx context.Context, arg repo.UpsertFindingParams) (sqlc.Finding, error) {
		return makeFinding(1), nil
	}

	fr.createOccurrenceFn = func(ctx context.Context, arg repo.CreateOccurrenceParams) (sqlc.FindingOccurrence, error) {
		return sqlc.FindingOccurrence{}, nil
	}

	fr.upsertDimensionFn = func(ctx context.Context, arg repo.UpsertDimensionParams) (sqlc.FindingDimension, error) {
		return sqlc.FindingDimension{}, nil
	}

	fr.listByProjectFn = func(ctx context.Context, projectID pgtype.UUID, severities, states []string, limit, offset int32) ([]sqlc.Finding, error) {
		return []sqlc.Finding{makeFinding(1)}, nil
	}

	reg := scanner.NewRegistry()
	reg.Register(&mockParser{
		name:      "trivy",
		scanTypes: []scanner.ScanType{scanner.ScanTypeImage},
		parseFn: func(ctx context.Context, input []byte) (*scanner.NormalizedReport, error) {
			return &scanner.NormalizedReport{
				ScannerName: "trivy",
				ScanType:    scanner.ScanTypeImage,
				Target:      &scanner.TargetInfo{Kind: "container", Identifier: "myapp:latest"},
				Findings: []scanner.NormalizedFinding{
					{Fingerprint: "fp1", FindingKind: "sca", Title: "CVE-2026-1234", Severity: scanner.SeverityCritical, Score: 9.5},
				},
				ScanScope: map[string]any{},
			}, nil
		},
	})

	uc := New(Deps{
		Repos:    &repo.Repos{Projects: pr, Reports: rr, Findings: fr},
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
