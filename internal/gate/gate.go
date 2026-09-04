// Package gate evaluates whether a project's deployment gate should pass:
// blocking findings that are not covered by an active waiver fail the gate.
// The gate consumes findings and waivers through narrow repository
// interfaces, keeping the evaluation logic independent of persistence.
package gate

import (
	"context"
	"fmt"
	"strconv"
	"strings"
)

// Status is the outcome of a gate evaluation.
type Status string

const (
	StatusPass  Status = "pass"
	StatusFail  Status = "fail"
	StatusError Status = "error"
)

// ReachabilityState is a finding's latest human reachability assessment.
// The empty string means no assessment exists (treated as unknown).
type ReachabilityState string

const (
	ReachabilityReachable     ReachabilityState = "reachable"
	ReachabilityNotReachable  ReachabilityState = "not_reachable"
	ReachabilityUnknown       ReachabilityState = "unknown"
	ReachabilityNotApplicable ReachabilityState = "not_applicable"
)

// Decision is the result of a gate evaluation for one project.
type Decision struct {
	// Status is pass when no blocking finding is unwaived, fail when at
	// least one is, or error when the evaluation could not complete.
	Status Status
	// BlockedBy lists the ids of unwaived blocking findings (empty on pass).
	BlockedBy []string
	// BlockedByReachability maps each blocked finding id to its latest
	// reachability state (empty when no assessment exists). It lets callers
	// explain why each finding blocks the gate.
	BlockedByReachability map[string]ReachabilityState
	// WaivedCount is the number of blocking findings an active waiver covers.
	WaivedCount int
	// TotalBlocking is the number of blocking findings considered.
	TotalBlocking int
}

// Finding is the subset of a finding the gate needs to decide whether an
// active waiver applies.
type Finding struct {
	ID                  string
	CurrentSeverityRank int16
	FindingKind         string
	Fingerprint         string
	CurrentTitle        string
	EnvironmentID       string
	TargetID            string
	ArtifactID          string
	// Reachability is the finding's latest human reachability assessment.
	// Empty means none exists (unknown).
	Reachability ReachabilityState
}

// WaiverCondition is a predicate on a finding field: Field is one of
// severity_rank, finding_kind, fingerprint, title_pattern, or cve_id;
// Operator is one of eq, neq, lt, lte, gt, gte, contains, or matches.
type WaiverCondition struct {
	Field    string
	Operator string
	Value    string
}

// WaiverTarget pins a waiver to one specific finding by id.
type WaiverTarget struct {
	FindingID string
}

// WaiverContext scopes a waiver to a deployment context. Empty fields are
// wildcards: a context with only EnvironmentID set applies to any finding in
// that environment regardless of target or artifact.
type WaiverContext struct {
	EnvironmentID string
	TargetID      string
	ArtifactID    string
}

// Waiver is an active waiver policy. A finding is waived when its context
// matches any of Contexts (contexts OR together), its id matches any of
// Targets, and every Condition holds.
type Waiver struct {
	ID         string
	Conditions []WaiverCondition
	Contexts   []WaiverContext
	Targets    []WaiverTarget
}

// FindingsRepo supplies the findings that would block a project's gate.
type FindingsRepo interface {
	// ListBlockingFindings returns findings at or above minSeverityRank that
	// are candidates for blocking the gate (severity and state already
	// filtered by the query).
	ListBlockingFindings(ctx context.Context, projectID string, minSeverityRank int16) ([]Finding, error)
}

// WaiversRepo supplies the active waivers for a project.
type WaiversRepo interface {
	ListActiveWaivers(ctx context.Context, projectID string) ([]Waiver, error)
}

// Gate evaluates deployment-readiness for a project.
type Gate interface {
	// Evaluate returns the gate decision: pass when every blocking finding
	// is waived, fail listing the unwaived blockers otherwise.
	Evaluate(ctx context.Context, projectID string, minSeverityRank int16) (Decision, error)
}

type gate struct {
	findings FindingsRepo
	waivers  WaiversRepo
}

// New builds a Gate over the given finding and waiver sources.
func New(findings FindingsRepo, waivers WaiversRepo) Gate {
	return &gate{findings: findings, waivers: waivers}
}

func (g *gate) Evaluate(ctx context.Context, projectID string, minSeverityRank int16) (Decision, error) {
	findings, err := g.findings.ListBlockingFindings(ctx, projectID, minSeverityRank)
	if err != nil {
		return Decision{Status: StatusError}, fmt.Errorf("list blocking findings: %w", err)
	}

	if len(findings) == 0 {
		return Decision{Status: StatusPass}, nil
	}

	waivers, err := g.waivers.ListActiveWaivers(ctx, projectID)
	if err != nil {
		return Decision{Status: StatusError}, fmt.Errorf("list active waivers: %w", err)
	}

	var blockedBy []string
	blockedByReachability := make(map[string]ReachabilityState, len(findings))
	waivedCount := 0

	for _, f := range findings {
		if IsFindingWaived(f, waivers) {
			waivedCount++
		} else {
			blockedBy = append(blockedBy, f.ID)
			blockedByReachability[f.ID] = f.Reachability
		}
	}

	if len(blockedBy) == 0 {
		return Decision{
			Status:        StatusPass,
			WaivedCount:   waivedCount,
			TotalBlocking: len(findings),
		}, nil
	}

	return Decision{
		Status:                StatusFail,
		BlockedBy:             blockedBy,
		BlockedByReachability: blockedByReachability,
		WaivedCount:           waivedCount,
		TotalBlocking:         len(findings),
	}, nil
}

func contextMatchesContexts(f Finding, contexts []WaiverContext) bool {
	for _, cx := range contexts {
		if cx.EnvironmentID != "" && cx.EnvironmentID != f.EnvironmentID {
			continue
		}
		if cx.TargetID != "" && cx.TargetID != f.TargetID {
			continue
		}
		if cx.ArtifactID != "" && cx.ArtifactID != f.ArtifactID {
			continue
		}
		return true
	}
	return false
}

// IsFindingWaived reports whether a single finding is waived by any of the
// given waivers. It is the single-finding counterpart to Evaluate: a waiver
// applies when the finding's context matches any of the waiver's contexts
// (contexts OR together), its ID matches any explicit target, and every
// condition on the waiver holds. Evaluate and CheckWaiverMatch both build on
// this helper so the two paths can never drift apart.
func IsFindingWaived(f Finding, waivers []Waiver) bool {
	for _, w := range waivers {
		if len(w.Contexts) > 0 && !contextMatchesContexts(f, w.Contexts) {
			continue
		}

		if len(w.Targets) > 0 {
			targetMatch := false
			for _, t := range w.Targets {
				if t.FindingID == f.ID {
					targetMatch = true
					break
				}
			}
			if !targetMatch {
				continue
			}
		}

		allMatch := true
		for _, c := range w.Conditions {
			if !matchCondition(f, c) {
				allMatch = false
				break
			}
		}

		if allMatch {
			return true
		}
	}
	return false
}

func matchCondition(f Finding, c WaiverCondition) bool {
	switch c.Field {
	case "severity_rank":
		threshold, err := strconv.Atoi(c.Value)
		if err != nil {
			return false
		}
		switch c.Operator {
		case "eq":
			return int(f.CurrentSeverityRank) == threshold
		case "neq":
			return int(f.CurrentSeverityRank) != threshold
		case "lt":
			return int(f.CurrentSeverityRank) < threshold
		case "lte":
			return int(f.CurrentSeverityRank) <= threshold
		case "gt":
			return int(f.CurrentSeverityRank) > threshold
		case "gte":
			return int(f.CurrentSeverityRank) >= threshold
		}
	case "finding_kind":
		if c.Operator == "eq" {
			return f.FindingKind == c.Value
		}
		if c.Operator == "neq" {
			return f.FindingKind != c.Value
		}
	case "fingerprint":
		if c.Operator == "eq" {
			return f.Fingerprint == c.Value
		}
		if c.Operator == "neq" {
			return f.Fingerprint != c.Value
		}
	case "title_pattern":
		if c.Operator == "contains" {
			return strings.Contains(f.CurrentTitle, c.Value)
		}
		if c.Operator == "matches" {
			return f.CurrentTitle == c.Value
		}
	case "cve_id":
		if c.Operator == "contains" {
			return strings.Contains(f.Fingerprint, c.Value)
		}
		if c.Operator == "eq" {
			return f.Fingerprint == c.Value
		}
	}
	return false
}
