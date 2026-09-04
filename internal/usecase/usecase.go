// Package usecase implements the application's business use cases: report
// ingestion, finding triage, waiver management, gate evaluation, and the
// read/stat surfaces the HTTP handlers and CLI consume. Use cases
// orchestrate repositories and the scanner registry; they hold no HTTP or
// persistence concerns of their own.
package usecase

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"math/big"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/xMinhx/specht/internal/auth"
	"github.com/xMinhx/specht/internal/gate"
	"github.com/xMinhx/specht/internal/repo"
	"github.com/xMinhx/specht/internal/scanner"
)

// ErrDuplicateReport is returned when a report with the same raw-content hash
// has already been ingested for the project.
var ErrDuplicateReport = errors.New("duplicate report")

// IngestReportInput is a scanner report to ingest for a project.
type IngestReportInput struct {
	ProjectSlug string // slug of the target project
	Scanner     string // registered scanner name, e.g. "trivy"
	// ScannerVersion and ParserVersion are recorded on the report row for
	// provenance.
	ScannerVersion string
	ParserVersion  string
	RawData        json.RawMessage // raw scanner output, byte-for-byte
	Branch         string
	CommitSha      string
	// GateSeverity and GateStatus override which findings count as blocking
	// for the post-ingest threshold check (defaults: high/critical, open).
	GateSeverity []string
	GateStatus   []string
	// Environment, ArtifactName, ArtifactVersion, and ArtifactType attach
	// deployment context to the report. When empty, context is derived from
	// the normalized scanner report when possible.
	Environment     string
	ArtifactName    string
	ArtifactVersion string
	ArtifactType    string
}

// IngestReportOutput reports what a completed ingest produced.
type IngestReportOutput struct {
	ReportID          string
	TotalFindings     int
	ThresholdBreached bool
}

// Deps wires the dependencies a Usecases instance needs. Repos, Registry,
// and JWTAuth are required; InventoryTTL tunes how long scanned inventory is
// considered fresh.
type Deps struct {
	Repos        *repo.Repos
	Registry     *scanner.Registry
	JWTAuth      *auth.JWTAuthenticator
	InventoryTTL time.Duration
}

// Usecases groups the application's use-case methods. It is safe for
// concurrent use: the gate evaluator is built lazily once.
type Usecases struct {
	deps     Deps
	gate     gate.Gate
	gateOnce sync.Once
}

// New builds a Usecases from its dependencies.
func New(deps Deps) *Usecases {
	return &Usecases{deps: deps}
}

func (u *Usecases) initGate() {
	u.gateOnce.Do(func() {
		u.gate = gate.New(
			&gateFindingRepo{r: u.deps.Repos.Findings, reachability: u.deps.Repos.Reachability},
			&gateWaiverRepo{r: u.deps.Repos.Waivers},
		)
	})
}

type gateFindingRepo struct {
	r            repo.FindingRepo
	reachability repo.ReachabilityRepo
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
	// Batch-load the latest reachability assessment for every blocking
	// finding in one query (avoids an N+1 round-trip per blocker).
	ids := make([]pgtype.UUID, len(rows))
	for i, r := range rows {
		ids[i] = r.ID
	}
	latestByFinding := map[string]gate.ReachabilityState{}
	if a.reachability != nil && len(ids) > 0 {
		assessments, err := a.reachability.LatestByFindings(ctx, ids)
		if err != nil {
			return nil, fmt.Errorf("batch load reachability: %w", err)
		}
		for _, as := range assessments {
			latestByFinding[uuid.UUID(as.FindingID.Bytes).String()] = gate.ReachabilityState(as.State)
		}
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
		// No assessment in the batch => unknown (still blocks).
		reachability := latestByFinding[uuid.UUID(r.ID.Bytes).String()]
		if reachability == "" {
			reachability = gate.ReachabilityUnknown
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
			Reachability:        reachability,
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
