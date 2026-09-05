package finding_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/xMinhx/specht/internal/finding"
)

func TestParseAnalysisState_Valid(t *testing.T) {
	for _, state := range finding.AllAnalysisStates {
		t.Run(string(state), func(t *testing.T) {
			got, ok := finding.ParseAnalysisState(string(state))
			assert.True(t, ok)
			assert.Equal(t, state, got)
		})
	}
}

func TestParseAnalysisState_Invalid(t *testing.T) {
	for _, s := range []string{"", "active", "muted", "resolved", "open", "fixed", "closed", "APPROVED"} {
		t.Run(s, func(t *testing.T) {
			_, ok := finding.ParseAnalysisState(s)
			assert.False(t, ok, "state %q must be rejected", s)
		})
	}
}

func TestValidateAnalysisState(t *testing.T) {
	assert.True(t, finding.ValidateAnalysisState("unanalyzed"))
	assert.True(t, finding.ValidateAnalysisState("exploitable"))
	assert.True(t, finding.ValidateAnalysisState("wont_fix"))
	assert.False(t, finding.ValidateAnalysisState("active"))
	assert.False(t, finding.ValidateAnalysisState(""))
}

func TestGateEffectFor(t *testing.T) {
	tests := []struct {
		state finding.AnalysisState
		want  finding.GateEffect
	}{
		{finding.StateUnanalyzed, finding.EffectBlock},
		{finding.StateInTriage, finding.EffectBlock},
		{finding.StateExploitable, finding.EffectBlock},
		{finding.StateFalsePos, finding.EffectIgnore},
		{finding.StateNotAffected, finding.EffectIgnore},
		{finding.StateAcceptedRisk, finding.EffectIgnore},
		{finding.StateWontFix, finding.EffectIgnore},
	}
	for _, tt := range tests {
		t.Run(string(tt.state), func(t *testing.T) {
			assert.Equal(t, tt.want, finding.GateEffectFor(tt.state))
		})
	}
}

func TestRequiresReason(t *testing.T) {
	requires := map[finding.AnalysisState]bool{
		finding.StateUnanalyzed:   false,
		finding.StateInTriage:     false,
		finding.StateExploitable:  false,
		finding.StateFalsePos:     true,
		finding.StateNotAffected:  true,
		finding.StateAcceptedRisk: true,
		finding.StateWontFix:      true,
	}
	for state, want := range requires {
		assert.Equal(t, want, finding.RequiresReason(state), string(state))
	}
}

func TestRequiresExpiry(t *testing.T) {
	assert.False(t, finding.RequiresExpiry(finding.StateFalsePos))
	assert.False(t, finding.RequiresExpiry(finding.StateNotAffected))
	assert.True(t, finding.RequiresExpiry(finding.StateAcceptedRisk))
	assert.True(t, finding.RequiresExpiry(finding.StateWontFix))
	assert.False(t, finding.RequiresExpiry(finding.StateUnanalyzed))
	assert.False(t, finding.RequiresExpiry(finding.StateExploitable))
}

func TestEvaluateChange_ZeroToNonZeroSeverity(t *testing.T) {
	c := finding.EvaluateChange(
		finding.PreviousFinding{Analysis: finding.StateUnanalyzed},
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
			Analysis:      finding.StateUnanalyzed,
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
			Analysis:     finding.StateAcceptedRisk,
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
			Analysis:     finding.StateUnanalyzed,
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
			Analysis:     finding.StateUnanalyzed,
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
			Analysis:      finding.StateUnanalyzed,
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
			Analysis:      finding.StateUnanalyzed,
			HadFixVersion: true,
		},
		finding.CurrentFinding{SeverityRank: 3, HasNewFix: true},
	)
	if c != nil {
		t.Errorf("expected nil when fix already existed, got %+v", c)
	}
}

// TestEvaluateChange_AllAnalysisStatesIterates the material-change rule
// across every canonical analysis state to prove EvaluateChange is state
// vocabulary-agnostic: any state that was "previous" reopens on severity
// increase or first-time fix.
func TestEvaluateChange_AllAnalysisStates(t *testing.T) {
	for _, state := range finding.AllAnalysisStates {
		t.Run(string(state), func(t *testing.T) {
			sev := finding.EvaluateChange(
				finding.PreviousFinding{SeverityRank: 1, Analysis: state, HadFixVersion: false},
				finding.CurrentFinding{SeverityRank: 4, HasNewFix: false},
			)
			if sev == nil || !sev.ReviewRequired || sev.EventType != "reopened_severity_change" {
				t.Fatalf("expected severity change for state %q", state)
			}

			fix := finding.EvaluateChange(
				finding.PreviousFinding{SeverityRank: 3, Analysis: state, HadFixVersion: false},
				finding.CurrentFinding{SeverityRank: 3, HasNewFix: true},
			)
			if fix == nil || !fix.ReviewRequired || fix.EventType != "reopened_fix_available" {
				t.Fatalf("expected fix change for state %q", state)
			}

			none := finding.EvaluateChange(
				finding.PreviousFinding{SeverityRank: 3, Analysis: state, HadFixVersion: true},
				finding.CurrentFinding{SeverityRank: 3, HasNewFix: false},
			)
			if none != nil {
				t.Fatalf("expected no change for state %q", state)
			}
		})
	}
}

func TestEvaluateChange_IgnoredFindingNewFix(t *testing.T) {
	c := finding.EvaluateChange(
		finding.PreviousFinding{
			SeverityRank:  3,
			GateEffect:    finding.EffectIgnore,
			Analysis:      finding.StateFalsePos,
			HadFixVersion: false,
		},
		finding.CurrentFinding{SeverityRank: 3, HasNewFix: true},
	)
	if c == nil || c.EventType != "reopened_fix_available" {
		t.Fatalf("expected fix change for ignored finding, got %+v", c)
	}
}
