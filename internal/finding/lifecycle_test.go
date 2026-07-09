package finding_test

import (
	"testing"

	"github.com/xMinhx/specht/internal/finding"
)

func TestEvaluateChange_ZeroToNonZeroSeverity(t *testing.T) {
	c := finding.EvaluateChange(
		finding.PreviousFinding{Analysis: finding.StateActive},
		finding.CurrentFinding{SeverityRank: 5},
	)
	if c == nil {
		t.Fatal("expected change for 0→5 severity")
	}
	if !c.ReviewRequired {
		t.Error("expected ReviewRequired = true")
	}
	if c.EventType != "reopened_severity_change" {
		t.Errorf("expected reopened_severity_change, got %q", c.EventType)
	}
}

func TestEvaluateChange_NoChange(t *testing.T) {
	c := finding.EvaluateChange(
		finding.PreviousFinding{
			SeverityRank:  3,
			Analysis:      finding.StateActive,
			HadFixVersion: true,
		},
		finding.CurrentFinding{SeverityRank: 3, HasNewFix: false},
	)
	if c != nil {
		t.Errorf("expected nil for no change, got %+v", c)
	}
}

func TestEvaluateChange_IgnoreEffectSeverityIncrease(t *testing.T) {
	c := finding.EvaluateChange(
		finding.PreviousFinding{
			SeverityRank: 2,
			GateEffect:   finding.EffectIgnore,
			Analysis:     finding.StateActive,
		},
		finding.CurrentFinding{SeverityRank: 5},
	)
	if c == nil {
		t.Fatal("expected change for ignored finding with severity increase")
	}
	if c.EventType != "reopened_severity_change" {
		t.Errorf("expected reopened_severity_change, got %q", c.EventType)
	}
}

func TestEvaluateChange_SeverityIncreased(t *testing.T) {
	c := finding.EvaluateChange(
		finding.PreviousFinding{
			SeverityRank: 2,
			Analysis:     finding.StateActive,
		},
		finding.CurrentFinding{SeverityRank: 5},
	)
	if c == nil {
		t.Fatal("expected change, got nil")
	}
	if !c.ReviewRequired {
		t.Error("expected ReviewRequired = true")
	}
	if c.EventType != "reopened_severity_change" {
		t.Errorf("expected reopened_severity_change, got %q", c.EventType)
	}
	if c.Changes["old_severity_rank"] != int16(2) {
		t.Errorf("expected old_severity_rank=2, got %v", c.Changes["old_severity_rank"])
	}
	if c.Changes["new_severity_rank"] != int16(5) {
		t.Errorf("expected new_severity_rank=5, got %v", c.Changes["new_severity_rank"])
	}
}

func TestEvaluateChange_SeverityDecreased(t *testing.T) {
	c := finding.EvaluateChange(
		finding.PreviousFinding{
			SeverityRank: 5,
			Analysis:     finding.StateActive,
		},
		finding.CurrentFinding{SeverityRank: 2},
	)
	if c != nil {
		t.Errorf("expected nil for decreased severity, got %+v", c)
	}
}

func TestEvaluateChange_FixAvailable(t *testing.T) {
	c := finding.EvaluateChange(
		finding.PreviousFinding{
			SeverityRank:  3,
			Analysis:      finding.StateActive,
			HadFixVersion: false,
		},
		finding.CurrentFinding{SeverityRank: 3, HasNewFix: true},
	)
	if c == nil {
		t.Fatal("expected change, got nil")
	}
	if !c.ReviewRequired {
		t.Error("expected ReviewRequired = true")
	}
	if c.EventType != "reopened_fix_available" {
		t.Errorf("expected reopened_fix_available, got %q", c.EventType)
	}
}

func TestEvaluateChange_FixAlreadyExisted(t *testing.T) {
	c := finding.EvaluateChange(
		finding.PreviousFinding{
			SeverityRank:  3,
			Analysis:      finding.StateActive,
			HadFixVersion: true,
		},
		finding.CurrentFinding{SeverityRank: 3, HasNewFix: true},
	)
	if c != nil {
		t.Errorf("expected nil when fix already existed, got %+v", c)
	}
}

func TestEvaluateChange_MutedFinding(t *testing.T) {
	c := finding.EvaluateChange(
		finding.PreviousFinding{
			SeverityRank: 1,
			Analysis:     finding.StateMuted,
		},
		finding.CurrentFinding{SeverityRank: 5},
	)
	if c == nil {
		t.Fatal("expected change for muted finding with severity increase")
	}
	if c.EventType != "reopened_severity_change" {
		t.Errorf("expected reopened_severity_change, got %q", c.EventType)
	}
}

func TestEvaluateChange_ResolvedFindingSeverityIncrease(t *testing.T) {
	c := finding.EvaluateChange(
		finding.PreviousFinding{
			SeverityRank: 2,
			Analysis:     finding.StateResolved,
		},
		finding.CurrentFinding{SeverityRank: 5},
	)
	if c == nil {
		t.Fatal("expected change for resolved finding with severity increase")
	}
	if c.EventType != "reopened_severity_change" {
		t.Errorf("expected reopened_severity_change, got %q", c.EventType)
	}
}

func TestEvaluateChange_ResolvedFindingFixAvailable(t *testing.T) {
	c := finding.EvaluateChange(
		finding.PreviousFinding{
			SeverityRank:  3,
			Analysis:      finding.StateResolved,
			HadFixVersion: false,
		},
		finding.CurrentFinding{SeverityRank: 3, HasNewFix: true},
	)
	if c == nil {
		t.Fatal("expected change for resolved finding with new fix")
	}
	if c.EventType != "reopened_fix_available" {
		t.Errorf("expected reopened_fix_available, got %q", c.EventType)
	}
}
