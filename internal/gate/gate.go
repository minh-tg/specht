package gate

import (
	"context"
	"fmt"
	"strconv"
	"strings"
)

type Status string

const (
	StatusPass  Status = "pass"
	StatusFail  Status = "fail"
	StatusError Status = "error"
)

type Decision struct {
	Status        Status
	BlockedBy     []string
	WaivedCount   int
	TotalBlocking int
}

type Finding struct {
	ID                  string
	CurrentSeverityRank int16
	FindingKind         string
	Fingerprint         string
	CurrentTitle        string
	EnvironmentID       string
	TargetID            string
	ArtifactID          string
}

type WaiverCondition struct {
	Field    string
	Operator string
	Value    string
}

type WaiverTarget struct {
	FindingID string
}

type WaiverContext struct {
	EnvironmentID string
	TargetID      string
	ArtifactID    string
}

type Waiver struct {
	ID         string
	Conditions []WaiverCondition
	Contexts   []WaiverContext
	Targets    []WaiverTarget
}

type FindingsRepo interface {
	ListBlockingFindings(ctx context.Context, projectID string, minSeverityRank int16) ([]Finding, error)
}

type WaiversRepo interface {
	ListActiveWaivers(ctx context.Context, projectID string) ([]Waiver, error)
}

type Gate interface {
	Evaluate(ctx context.Context, projectID string, minSeverityRank int16) (Decision, error)
}

type gate struct {
	findings FindingsRepo
	waivers  WaiversRepo
}

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
	waivedCount := 0

	for _, f := range findings {
		if IsFindingWaived(f, waivers) {
			waivedCount++
		} else {
			blockedBy = append(blockedBy, f.ID)
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
		Status:        StatusFail,
		BlockedBy:     blockedBy,
		WaivedCount:   waivedCount,
		TotalBlocking: len(findings),
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
