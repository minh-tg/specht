package usecase

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/xMinhx/specht/internal/auth"
	"github.com/xMinhx/specht/internal/repo"
	"github.com/xMinhx/specht/internal/scanner"
)

var ErrDuplicateReport = errors.New("duplicate report")

type IngestReportInput struct {
	ProjectSlug   string
	Scanner       string
	ScannerVersion string
	ParserVersion string
	RawData       json.RawMessage
	Branch        string
	CommitSha     string
	GateSeverity  []string
	GateStatus    []string
}

type IngestReportOutput struct {
	ReportID         string
	TotalFindings    int
	ThresholdBreached bool
}

type Deps struct {
	Repos    *repo.Repos
	Registry *scanner.Registry
	JWTAuth  *auth.JWTAuthenticator
}

type Usecases struct {
	deps Deps
}

func New(deps Deps) *Usecases {
	return &Usecases{deps: deps}
}

func severityStr(s scanner.Severity) string {
	switch s {
	case scanner.SeverityCritical:
		return "critical"
	case scanner.SeverityHigh:
		return "high"
	case scanner.SeverityMedium:
		return "medium"
	case scanner.SeverityLow:
		return "low"
	default:
		return "unknown"
	}
}

func severityRank(s scanner.Severity) int16 {
	return int16(s)
}

func scoreToNumeric(s float64) pgtype.Numeric {
	if s <= 0 {
		return pgtype.Numeric{Valid: false}
	}
	return pgtype.Numeric{Int: big.NewInt(int64(s * 10)), Exp: -1, Valid: true}
}

func textPtr(s string) pgtype.Text {
	if s == "" {
		return pgtype.Text{Valid: false}
	}
	return pgtype.Text{String: s, Valid: true}
}

func now() pgtype.Timestamptz {
	return pgtype.Timestamptz{Time: time.Now(), Valid: true}
}

func defaultGateParams(severities, statuses []string) ([]string, []string) {
	if len(severities) == 0 {
		severities = []string{"high", "critical"}
	}
	if len(statuses) == 0 {
		statuses = []string{"open"}
	}
	return severities, statuses
}

func (u *Usecases) IngestReport(ctx context.Context, input IngestReportInput) (*IngestReportOutput, error) {
	if input.ProjectSlug == "" {
		return nil, fmt.Errorf("project slug is required")
	}
	if input.Scanner == "" {
		return nil, fmt.Errorf("scanner name is required")
	}
	if len(input.RawData) == 0 {
		return nil, fmt.Errorf("raw scan data is required")
	}

	project, err := u.deps.Repos.Projects.GetBySlug(ctx, input.ProjectSlug)
	if err != nil {
		return nil, fmt.Errorf("lookup project %q: %w", input.ProjectSlug, err)
	}

	parser, ok := u.deps.Registry.Get(input.Scanner)
	if !ok {
		return nil, fmt.Errorf("unknown scanner %q", input.Scanner)
	}

	nr, err := parser.Parse(ctx, bytes.NewReader(input.RawData))
	if err != nil {
		return nil, fmt.Errorf("parse %s output: %w", input.Scanner, err)
	}

	rawHash := sha256.Sum256(input.RawData)

	report, err := u.deps.Repos.Reports.Create(ctx, repo.CreateReportParams{
		ProjectID:    project.ID,
		ToolName:     input.Scanner,
		ToolVersion:  textPtr(input.ScannerVersion),
		ScanType:     string(nr.ScanType),
		ScanTarget:   textPtr(nr.Target.Identifier),
		ScanScope:    mustMarshal(nr.ScanScope),
		Branch:       textPtr(input.Branch),
		CommitSha:    textPtr(input.CommitSha),
		RawReportHash: pgtype.Text{String: hex.EncodeToString(rawHash[:]), Valid: true},
		ParserVersion: textPtr(input.ParserVersion),
	})
	if err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == "23505" {
			return nil, ErrDuplicateReport
		}
		return nil, fmt.Errorf("create report: %w", err)
	}

	nowTime := now()

	var total int
	for _, f := range nr.Findings {
		newRank := severityRank(f.Severity)

		var oldRank int16
		var oldGateEffect string
		var oldAnalysisState string

		existing, lookupErr := u.deps.Repos.Findings.GetByFingerprint(ctx, repo.GetByFingerprintParams{
			ProjectID:   project.ID,
			FindingKind: f.FindingKind,
			Fingerprint: f.Fingerprint,
		})
		if lookupErr != nil {
			// New finding — no existing state to compare.
		}
		if lookupErr == nil {
			oldRank = existing.CurrentSeverityRank
			oldGateEffect = existing.GateEffect
			oldAnalysisState = existing.AnalysisState
		}

		upserted, err := u.deps.Repos.Findings.Upsert(ctx, repo.UpsertFindingParams{
			ProjectID:    project.ID,
			FindingKind:  f.FindingKind,
			Fingerprint:  f.Fingerprint,
			CurrentTitle: f.Title,
			Severity:     severityStr(f.Severity),
			SeverityRank: newRank,
			Score:        scoreToNumeric(f.Score),
			FirstSeenAt:  nowTime,
			LastSeenAt:   nowTime,
		})
		if err != nil {
			return nil, fmt.Errorf("upsert finding %q: %w", f.Fingerprint, err)
		}

		_, err = u.deps.Repos.Findings.CreateOccurrence(ctx, repo.CreateOccurrenceParams{
			FindingID:      upserted.ID,
			ReportID:       report.ID,
			Title:          f.Title,
			Description:    textPtr(f.Description),
			Severity:       severityStr(f.Severity),
			SeverityRank:   severityRank(f.Severity),
			Score:          scoreToNumeric(f.Score),
			ToolName:       input.Scanner,
			ToolVersion:    textPtr(input.ScannerVersion),
			ParserVersion:  textPtr(input.ParserVersion),
			LocationSummary: textPtr(f.Location),
			Display:        mustMarshal(f.Display),
			Metadata:       mustMarshal(f.Metadata),
		})
		if err != nil {
			return nil, fmt.Errorf("create occurrence for %q: %w", f.Fingerprint, err)
		}

		for _, d := range f.Dimensions {
			_, err = u.deps.Repos.Findings.UpsertDimension(ctx, repo.UpsertDimensionParams{
				FindingID: upserted.ID,
				Key:       d.Key,
				Value:     d.Value,
				Source:    pgtype.Text{String: input.Scanner, Valid: true},
			})
			if err != nil {
				return nil, fmt.Errorf("upsert dimension for %q: %w", f.Fingerprint, err)
			}
		}

		// Material change detection: only for existing triaged findings
		if lookupErr == nil && (oldAnalysisState != "unanalyzed" || oldGateEffect == "ignore") {
			reviewRequired := false
			eventType := ""

			// Trigger 1: severity increase
			if newRank > oldRank {
				reviewRequired = true
				eventType = "reopened_severity_change"
			}

			// Trigger 2: fix just became available
			if !reviewRequired {
				hasNewFix := false
				for _, d := range f.Dimensions {
					if d.Key == "fixed_version" && d.Value != "" {
						hasNewFix = true
						break
					}
				}
				if hasNewFix {
					hadOldFix, fixErr := u.deps.Repos.Findings.HasDimension(ctx, upserted.ID, "fixed_version")
					if fixErr == nil && !hadOldFix {
						reviewRequired = true
						eventType = "reopened_fix_available"
					}
				}
			}

			if reviewRequired {
				_, err = u.deps.Repos.Findings.UpdateAnalysis(ctx, repo.UpdateAnalysisParams{
					ID:             upserted.ID,
					AnalysisState:  upserted.AnalysisState,
					GateEffect:     upserted.GateEffect,
					ReviewRequired: true,
				})
				if err != nil {
					return nil, fmt.Errorf("set review_required for finding %q: %w", f.Fingerprint, err)
				}

				changes, _ := json.Marshal(map[string]any{
					"old_severity_rank": oldRank,
					"new_severity_rank": newRank,
				})
				_, err = u.deps.Repos.Findings.CreateEvent(ctx, repo.CreateEventParams{
					FindingID: upserted.ID,
					EventType: eventType,
					Changes:   changes,
				})
				if err != nil {
					return nil, fmt.Errorf("log material change event: %w", err)
				}
			}
		}

		total++
	}

	_, err = u.deps.Repos.Reports.UpdateStatus(ctx, report.ID, project.ID, "completed", total, pgtype.Text{Valid: false})
	if err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == "23505" {
			return nil, ErrDuplicateReport
		}
		return nil, fmt.Errorf("update report status: %w", err)
	}

	severities, statuses := defaultGateParams(input.GateSeverity, input.GateStatus)
	gateFindings, err := u.deps.Repos.Findings.ListByProject(ctx, project.ID, severities, statuses, 1, 0)
	if err != nil {
		return nil, fmt.Errorf("gate check: %w", err)
	}

	reportID := uuid.UUID(report.ID.Bytes).String()
	return &IngestReportOutput{
		ReportID:          reportID,
		TotalFindings:     total,
		ThresholdBreached: len(gateFindings) > 0,
	}, nil
}

func mustMarshal(v any) []byte {
	data, err := json.Marshal(v)
	if err != nil {
		panic(err)
	}
	return data
}


