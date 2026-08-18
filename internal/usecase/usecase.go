package usecase

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"math/big"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/xMinhx/specht/internal/auth"
	"github.com/xMinhx/specht/internal/db/sqlc"
	"github.com/xMinhx/specht/internal/finding"
	"github.com/xMinhx/specht/internal/gate"
	"github.com/xMinhx/specht/internal/repo"
	"github.com/xMinhx/specht/internal/scanner"
)

var ErrDuplicateReport = errors.New("duplicate report")

type IngestReportInput struct {
	ProjectSlug     string
	Scanner         string
	ScannerVersion  string
	ParserVersion   string
	RawData         json.RawMessage
	Branch          string
	CommitSha       string
	GateSeverity    []string
	GateStatus      []string
	Environment     string
	ArtifactName    string
	ArtifactVersion string
	ArtifactType    string
}

type IngestReportOutput struct {
	ReportID          string
	TotalFindings     int
	ThresholdBreached bool
}

type Deps struct {
	Repos        *repo.Repos
	Registry     *scanner.Registry
	JWTAuth      *auth.JWTAuthenticator
	InventoryTTL time.Duration
}

type Usecases struct {
	deps     Deps
	gate     gate.Gate
	gateOnce sync.Once
}

func New(deps Deps) *Usecases {
	return &Usecases{deps: deps}
}

func (u *Usecases) initGate() {
	u.gateOnce.Do(func() {
		u.gate = gate.New(
			&gateFindingRepo{r: u.deps.Repos.Findings},
			&gateWaiverRepo{r: u.deps.Repos.Waivers},
		)
	})
}

type gateFindingRepo struct {
	r repo.FindingRepo
}

func (a *gateFindingRepo) ListBlockingFindings(ctx context.Context, projectID string, minSeverityRank int16) ([]gate.Finding, error) {
	pid, err := uuid.Parse(projectID)
	if err != nil {
		return nil, fmt.Errorf("invalid project id: %w", err)
	}
	rows, err := a.r.ListBlockingFindings(ctx, pgtype.UUID{Bytes: pid, Valid: true}, minSeverityRank)
	if err != nil {
		return nil, err
	}
	result := make([]gate.Finding, len(rows))
	for i, r := range rows {
		fc, ctxErr := a.r.GetFindingContext(ctx, r.ID)
		envID := ""
		tgtID := ""
		artID := ""
		if ctxErr == nil {
			if fc.EnvironmentID.Valid {
				envID = uuid.UUID(fc.EnvironmentID.Bytes).String()
			}
			if fc.TargetID.Valid {
				tgtID = uuid.UUID(fc.TargetID.Bytes).String()
			}
			if fc.ArtifactID.Valid {
				artID = uuid.UUID(fc.ArtifactID.Bytes).String()
			}
		}
		result[i] = gate.Finding{
			ID:                  uuid.UUID(r.ID.Bytes).String(),
			CurrentSeverityRank: r.CurrentSeverityRank,
			FindingKind:         r.FindingKind,
			Fingerprint:         r.Fingerprint,
			CurrentTitle:        r.CurrentTitle,
			EnvironmentID:       envID,
			TargetID:            tgtID,
			ArtifactID:          artID,
		}
	}
	return result, nil
}

type gateWaiverRepo struct {
	r repo.WaiverRepo
}

func (a *gateWaiverRepo) ListActiveWaivers(ctx context.Context, projectID string) ([]gate.Waiver, error) {
	pid, err := uuid.Parse(projectID)
	if err != nil {
		return nil, fmt.Errorf("invalid project id: %w", err)
	}
	rows, err := a.r.ListActive(ctx, pgtype.UUID{Bytes: pid, Valid: true})
	if err != nil {
		return nil, err
	}
	result := make([]gate.Waiver, len(rows))
	for i, w := range rows {
		gw := gate.Waiver{
			ID:         uuid.UUID(w.ID.Bytes).String(),
			Conditions: nil,
			Contexts:   nil,
			Targets:    nil,
		}
		conditions, err := a.r.ListConditions(ctx, w.ID)
		if err != nil {
			slog.Warn("list waiver conditions", "waiver_id", w.ID, "error", err)
		}
		for _, c := range conditions {
			gw.Conditions = append(gw.Conditions, gate.WaiverCondition{
				Field:    c.Field,
				Operator: c.Operator,
				Value:    c.Value,
			})
		}
		contexts, err := a.r.ListContexts(ctx, w.ID)
		if err != nil {
			slog.Warn("list waiver contexts", "waiver_id", w.ID, "error", err)
		}
		for _, cx := range contexts {
			envID := ""
			if cx.EnvironmentID.Valid {
				envID = uuid.UUID(cx.EnvironmentID.Bytes).String()
			}
			tgtID := ""
			if cx.TargetID.Valid {
				tgtID = uuid.UUID(cx.TargetID.Bytes).String()
			}
			artID := ""
			if cx.ArtifactID.Valid {
				artID = uuid.UUID(cx.ArtifactID.Bytes).String()
			}
			gw.Contexts = append(gw.Contexts, gate.WaiverContext{
				EnvironmentID: envID,
				TargetID:      tgtID,
				ArtifactID:    artID,
			})
		}
		targets, err := a.r.ListFindingTargets(ctx, w.ID)
		if err != nil {
			slog.Warn("list waiver finding targets", "waiver_id", w.ID, "error", err)
		}
		for _, t := range targets {
			gw.Targets = append(gw.Targets, gate.WaiverTarget{
				FindingID: uuid.UUID(t.FindingID.Bytes).String(),
			})
		}
		result[i] = gw
	}
	return result, nil
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

	sc, ok := u.deps.Registry.Get(input.Scanner)
	if !ok {
		return nil, fmt.Errorf("unknown scanner %q", input.Scanner)
	}

	nr, err := sc.Parse(ctx, input.RawData)
	if err != nil {
		slog.Error("scanner parse failed", "scanner", input.Scanner, "error", err)
		return nil, fmt.Errorf("scanner %s: parse output: %w", input.Scanner, err)
	}

	rawHash := sha256.Sum256(input.RawData)

	var targetID pgtype.UUID
	if nr.Target != nil && nr.Target.Identifier != "" {
		kind := nr.Target.Kind
		if kind == "" {
			kind = string(nr.ScanType)
		}
		t, err := u.deps.Repos.Targets.Upsert(ctx, sqlc.UpsertTargetParams{
			ProjectID: project.ID,
			Name:      nr.Target.Identifier,
			Kind:      kind,
			Locator:   pgtype.Text{String: nr.Target.Identifier, Valid: true},
		})
		if err == nil {
			targetID = t.ID
		}
	}

	var artifactID pgtype.UUID
	artifactName := input.ArtifactName
	if artifactName == "" && nr.Artifact != nil {
		artifactName = nr.Artifact.Identifier
	}
	if artifactName != "" {
		artifactType := input.ArtifactType
		if artifactType == "" && nr.Artifact != nil {
			artifactType = nr.Artifact.Kind
		}
		if artifactType == "" {
			artifactType = string(nr.ScanType)
		}
		var metadata []byte
		if nr.Artifact != nil {
			metadata = mustMarshal(nr.Artifact.Metadata)
		}
		if metadata == nil {
			metadata = []byte("{}")
		}
		a, err := u.deps.Repos.Artifacts.Upsert(ctx, sqlc.UpsertArtifactParams{
			ProjectID:    project.ID,
			TargetID:     targetID,
			ArtifactType: artifactType,
			Name:         artifactName,
			Version:      textPtr(input.ArtifactVersion),
			Digest:       pgtype.Text{Valid: false},
			Locator:      pgtype.Text{Valid: false},
			Metadata:     metadata,
		})
		if err == nil {
			artifactID = a.ID
		}
	}

	var environmentID pgtype.UUID
	if input.Environment != "" {
		e, err := u.deps.Repos.Environments.Upsert(ctx, sqlc.UpsertEnvironmentParams{
			ProjectID:       project.ID,
			Name:            input.Environment,
			Tier:            "development",
			InternetFacing:  false,
			DataSensitivity: "internal",
		})
		if err == nil {
			environmentID = e.ID
		}
	}

	targetIdentifier := ""
	if nr.Target != nil {
		targetIdentifier = nr.Target.Identifier
	}
	scopeHash := sha256.Sum256([]byte(input.Scanner + ":" + targetIdentifier))

	report, err := u.deps.Repos.Reports.Create(ctx, repo.CreateReportParams{
		ProjectID:     project.ID,
		ToolName:      input.Scanner,
		ToolVersion:   textPtr(input.ScannerVersion),
		ScanType:      string(nr.ScanType),
		ScanTarget:    textPtr(nr.Target.Identifier),
		TargetID:      targetID,
		ArtifactID:    artifactID,
		EnvironmentID: environmentID,
		ScanScope:     mustMarshal(nr.ScanScope),
		ScanScopeHash: pgtype.Text{String: hex.EncodeToString(scopeHash[:]), Valid: true},
		Branch:        textPtr(input.Branch),
		CommitSha:     textPtr(input.CommitSha),
		RawData:       input.RawData,
		RawReportHash: pgtype.Text{String: hex.EncodeToString(rawHash[:]), Valid: true},
		ParserVersion: textPtr(input.ParserVersion),
	})
	if err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == "23505" {
			return nil, ErrDuplicateReport
		}
		slog.Error("create report failed", "scanner", input.Scanner, "error", err)
		return nil, fmt.Errorf("scanner %s: create report: %w", input.Scanner, err)
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
			slog.Error("upsert finding failed", "scanner", input.Scanner, "fingerprint", f.Fingerprint, "error", err)
			return nil, fmt.Errorf("scanner %s: upsert finding %q: %w", input.Scanner, f.Fingerprint, err)
		}

		_, err = u.deps.Repos.Findings.CreateOccurrence(ctx, repo.CreateOccurrenceParams{
			FindingID:       upserted.ID,
			ReportID:        report.ID,
			Title:           f.Title,
			Description:     textPtr(f.Description),
			Severity:        severityStr(f.Severity),
			SeverityRank:    severityRank(f.Severity),
			Score:           scoreToNumeric(f.Score),
			ToolName:        input.Scanner,
			ToolVersion:     textPtr(input.ScannerVersion),
			ParserVersion:   textPtr(input.ParserVersion),
			LocationSummary: textPtr(f.Location),
			Display:         mustMarshal(f.Display),
			Metadata:        mustMarshal(f.Metadata),
		})
		if err != nil {
			slog.Error("create occurrence failed", "scanner", input.Scanner, "fingerprint", f.Fingerprint, "error", err)
			return nil, fmt.Errorf("scanner %s: create occurrence for %q: %w", input.Scanner, f.Fingerprint, err)
		}

		for _, d := range f.Dimensions {
			_, err = u.deps.Repos.Findings.UpsertDimension(ctx, repo.UpsertDimensionParams{
				FindingID: upserted.ID,
				Key:       d.Key,
				Value:     d.Value,
				Source:    pgtype.Text{String: input.Scanner, Valid: true},
			})
			if err != nil {
				slog.Error("upsert dimension failed", "scanner", input.Scanner, "fingerprint", f.Fingerprint, "error", err)
				return nil, fmt.Errorf("scanner %s: upsert dimension for %q: %w", input.Scanner, f.Fingerprint, err)
			}
		}

		if lookupErr == nil && (oldAnalysisState != "unanalyzed" || oldGateEffect == "ignore") {
			hasNewFix := false
			for _, d := range f.Dimensions {
				if d.Key == "fixed_version" && d.Value != "" {
					hasNewFix = true
					break
				}
			}

			var hadOldFix bool
			if hasNewFix {
				hadOldFix, _ = u.deps.Repos.Findings.HasDimension(ctx, upserted.ID, "fixed_version")
			}

			change := finding.EvaluateChange(finding.PreviousFinding{
				SeverityRank:  oldRank,
				GateEffect:    finding.GateEffect(oldGateEffect),
				Analysis:      finding.AnalysisState(oldAnalysisState),
				HadFixVersion: hadOldFix,
			}, finding.CurrentFinding{
				SeverityRank: newRank,
				HasNewFix:    hasNewFix,
			})

			if change != nil && change.ReviewRequired {
				_, err = u.deps.Repos.Findings.UpdateAnalysis(ctx, repo.UpdateAnalysisParams{
					ID:             upserted.ID,
					AnalysisState:  upserted.AnalysisState,
					GateEffect:     upserted.GateEffect,
					AnalysisSource: upserted.AnalysisSource,
					ReviewRequired: true,
				})
				if err != nil {
					slog.Error("set review_required failed", "scanner", input.Scanner, "fingerprint", f.Fingerprint, "error", err)
					return nil, fmt.Errorf("scanner %s: set review_required for finding %q: %w", input.Scanner, f.Fingerprint, err)
				}

				changesJSON, _ := json.Marshal(change.Changes)
				_, err = u.deps.Repos.Findings.CreateEvent(ctx, repo.CreateEventParams{
					FindingID: upserted.ID,
					EventType: change.EventType,
					Changes:   changesJSON,
				})
				if err != nil {
					slog.Error("log material change event failed", "scanner", input.Scanner, "fingerprint", f.Fingerprint, "error", err)
					return nil, fmt.Errorf("scanner %s: log material change event: %w", input.Scanner, err)
				}
			}
		}

		total++
	}

	if len(nr.Packages) > 0 {
		err = u.deps.Repos.Inventory.UpsertReportPackages(ctx, report.ID, toInventoryPackageParams(nr.Packages))
		if err != nil {
			slog.Error("persist package inventory failed", "scanner", input.Scanner, "report_id", report.ID, "error", err)
			return nil, fmt.Errorf("scanner %s: persist package inventory: %w", input.Scanner, err)
		}
	}

	_, err = u.deps.Repos.Reports.UpdateStatus(ctx, report.ID, project.ID, "completed", total, pgtype.Text{Valid: false})
	if err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == "23505" {
			return nil, ErrDuplicateReport
		}
		slog.Error("update report status failed", "scanner", input.Scanner, "report_id", report.ID, "error", err)
		return nil, fmt.Errorf("scanner %s: update report status: %w", input.Scanner, err)
	}

	severities, statuses := defaultGateParams(input.GateSeverity, input.GateStatus)
	gateFindings, err := u.deps.Repos.Findings.ListByProject(ctx, project.ID, severities, statuses, nil, 1, 0)
	if err != nil {
		slog.Error("gate check failed", "scanner", input.Scanner, "project", project.ID, "error", err)
		return nil, fmt.Errorf("scanner %s: gate check: %w", input.Scanner, err)
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

// toInventoryPackageParams converts normalized package refs into repo params.
// PURLs pass through verbatim — the DB's (report_id, purl) primary key is what
// collapses duplicates across (and within) reports.
func toInventoryPackageParams(packages []scanner.PackageRef) []repo.UpsertReportPackageParams {
	params := make([]repo.UpsertReportPackageParams, 0, len(packages))
	for _, p := range packages {
		params = append(params, repo.UpsertReportPackageParams{
			PURL:         p.PURL,
			Ecosystem:    textPtr(p.Ecosystem),
			Name:         textPtr(p.Name),
			Version:      textPtr(p.Version),
			ManifestPath: textPtr(p.ManifestPath),
		})
	}
	return params
}
