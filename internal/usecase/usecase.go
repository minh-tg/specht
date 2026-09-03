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
