// Package usecase implements the application's business use cases: report
// ingestion, finding triage, waiver management, gate evaluation, and the
// read/stat surfaces the HTTP handlers and CLI consume. Use cases
// orchestrate the neutral persistence stores and scanner registry; they hold
// no HTTP or persistence concerns of their own.
package usecase

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/xMinhx/specht/internal/auth"
	"github.com/xMinhx/specht/internal/domain"
	"github.com/xMinhx/specht/internal/gate"
	"github.com/xMinhx/specht/internal/port"
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

// Deps wires the dependencies a Usecases instance needs. Stores, Registry,
// and JWTAuth are required; InventoryTTL tunes how long scanned inventory is
// considered fresh.
type Deps struct {
	Stores       *port.Stores
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
			&gateFindingRepo{stores: u.deps.Stores},
			&gateWaiverRepo{stores: u.deps.Stores},
		)
	})
}

type gateFindingRepo struct {
	stores *port.Stores
}

func (a *gateFindingRepo) ListBlockingFindings(ctx context.Context, projectID string, minSeverityRank int16) ([]gate.Finding, error) {
	if a.stores == nil || a.stores.Findings == nil {
		return nil, fmt.Errorf("finding store unavailable")
	}
	// Batch candidate loader: one round trip returns each candidate with its
	// deployment context and latest reachability, so gate evaluation performs
	// no per-finding GetFindingContext N+1 lookups.
	candidates, err := a.stores.Findings.ListGateCandidates(ctx, projectID, minSeverityRank)
	if err != nil {
		return nil, err
	}

	result := make([]gate.Finding, len(candidates))
	for i, c := range candidates {
		reachability := gate.ReachabilityState(c.Reachability)
		if reachability == "" {
			reachability = gate.ReachabilityUnknown
		}
		result[i] = gate.Finding{
			ID:                  c.ID,
			CurrentSeverityRank: c.CurrentSeverityRank,
			FindingKind:         c.FindingKind,
			Fingerprint:         c.Fingerprint,
			CurrentTitle:        c.CurrentTitle,
			EnvironmentID:       c.Context.EnvironmentID,
			TargetID:            c.Context.TargetID,
			ArtifactID:          c.Context.ArtifactID,
			AnalysisState:       c.AnalysisState,
			Reachability:        reachability,
			Source:              c.FindingKind,
		}
	}
	return result, nil
}

type gateWaiverRepo struct {
	stores *port.Stores
}

func (a *gateWaiverRepo) ListActiveWaivers(ctx context.Context, projectID string) ([]gate.Waiver, error) {
	if a.stores == nil || a.stores.Waivers == nil {
		return nil, fmt.Errorf("waiver store unavailable")
	}
	rows, err := a.stores.Waivers.ListActive(ctx, projectID)
	if err != nil {
		return nil, err
	}
	result := make([]gate.Waiver, len(rows))
	for i, waiver := range rows {
		gw := gate.Waiver{
			ID:         waiver.ID,
			Conditions: nil,
			Contexts:   nil,
			Targets:    nil,
		}
		conditions, err := a.stores.Waivers.ListConditions(ctx, waiver.ID)
		if err != nil {
			slog.Warn("list waiver conditions", "waiver_id", waiver.ID, "error", err)
		}
		for _, condition := range conditions {
			gw.Conditions = append(gw.Conditions, gate.WaiverCondition{
				Field:    condition.Field,
				Operator: condition.Operator,
				Value:    condition.Value,
			})
		}
		contexts, err := a.stores.Waivers.ListContexts(ctx, waiver.ID)
		if err != nil {
			slog.Warn("list waiver contexts", "waiver_id", waiver.ID, "error", err)
		}
		for _, waiverContext := range contexts {
			gw.Contexts = append(gw.Contexts, gate.WaiverContext{
				EnvironmentID: waiverContext.EnvironmentID,
				TargetID:      waiverContext.TargetID,
				ArtifactID:    waiverContext.ArtifactID,
			})
		}
		targets, err := a.stores.Waivers.ListFindingTargets(ctx, waiver.ID)
		if err != nil {
			slog.Warn("list waiver finding targets", "waiver_id", waiver.ID, "error", err)
		}
		for _, target := range targets {
			gw.Targets = append(gw.Targets, gate.WaiverTarget{FindingID: target.FindingID})
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

func scoreToFloat(s float64) float64 {
	if s <= 0 {
		return 0
	}
	return s
}

func textPtr(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}

func now() time.Time {
	return time.Now()
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

// toInventoryPackageParams converts normalized package refs into port values.
// PURLs pass through verbatim — the DB's (report_id, purl) primary key is what
// collapses duplicates across (and within) reports.
func toInventoryPackageParams(packages []domain.PackageRef) []port.PackageRef {
	params := make([]port.PackageRef, 0, len(packages))
	for _, p := range packages {
		params = append(params, port.PackageRef{
			PURL:         p.PURL,
			Ecosystem:    textPtr(p.Ecosystem),
			Name:         textPtr(p.Name),
			Version:      textPtr(p.Version),
			ManifestPath: textPtr(p.ManifestPath),
		})
	}
	return params
}
