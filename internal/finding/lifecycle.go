// Package finding models the lifecycle of a single finding: the states an
// analyst can move it through, the technical state a finding is in, and the
// change evaluation that decides when a previously-resolved finding must be
// reopened for review.
//
// This package owns the one lifecycle vocabulary used across the core. The
// database analysis-state check (migration 000009) is the persistence mirror
// of AnalysisState below; the triage use case validates through this package
// before any repository write. Technical state (open/fixed/reopened) is the
// scan-derived occurrence lifecycle and is tracked separately from analyst
// state.
package finding

// AnalysisState is the analyst-driven lifecycle state of a finding. The
// values mirror the database analysis_state CHECK constraint (migration
// 000009); the dormant approval fields are intentionally not modeled here.
type AnalysisState string

const (
	StateUnanalyzed   AnalysisState = "unanalyzed"
	StateInTriage     AnalysisState = "in_triage"
	StateExploitable  AnalysisState = "exploitable"
	StateFalsePos     AnalysisState = "false_positive"
	StateNotAffected  AnalysisState = "not_affected"
	StateAcceptedRisk AnalysisState = "accepted_risk"
	StateWontFix      AnalysisState = "wont_fix"
)

// AllAnalysisStates lists every valid analysis state in canonical order.
var AllAnalysisStates = []AnalysisState{
	StateUnanalyzed,
	StateInTriage,
	StateExploitable,
	StateFalsePos,
	StateNotAffected,
	StateAcceptedRisk,
	StateWontFix,
}

// TechnicalState is the scan-derived occurrence lifecycle of a finding.
type TechnicalState string

const (
	TechOpen     TechnicalState = "open"
	TechFixed    TechnicalState = "fixed"
	TechReopened TechnicalState = "reopened"
)

// ParseAnalysisState validates a state string against the canonical
// vocabulary. It returns (state, true) for a valid state and ("", false)
// otherwise.
func ParseAnalysisState(s string) (AnalysisState, bool) {
	st := AnalysisState(s)
	for _, valid := range AllAnalysisStates {
		if st == valid {
			return st, true
		}
	}
	return "", false
}

// ValidateAnalysisState reports whether s is one of the canonical analysis
// states. It exists so callers that carry untyped strings (HTTP bodies, DB
// rows) can validate at the boundary before persisting.
func ValidateAnalysisState(s string) bool {
	_, ok := ParseAnalysisState(s)
	return ok
}

// GateEffect is how a finding participates in the deployment gate while in a
// given analysis state.
type GateEffect string

const (
	EffectBlock  GateEffect = "block"
	EffectIgnore GateEffect = "ignore"
	EffectNone   GateEffect = ""
)

// GateEffectFor returns the gate effect an analysis state produces:
// false_positive, not_affected, accepted_risk, and wont_fix ignore the gate;
// every other state blocks until waived.
func GateEffectFor(state AnalysisState) GateEffect {
	switch state {
	case StateFalsePos, StateNotAffected, StateAcceptedRisk, StateWontFix:
		return EffectIgnore
	default:
		return EffectBlock
	}
}

// RequiresReason reports whether an analysis state demands an analyst reason
// before it can be persisted.
func RequiresReason(state AnalysisState) bool {
	switch state {
	case StateFalsePos, StateNotAffected, StateAcceptedRisk, StateWontFix:
		return true
	default:
		return false
	}
}

// RequiresExpiry reports whether an analysis state demands an expiry before
// it can be persisted.
func RequiresExpiry(state AnalysisState) bool {
	switch state {
	case StateAcceptedRisk, StateWontFix:
		return true
	default:
		return false
	}
}

// PreviousFinding is the recorded state of a finding before a new scan
// occurrence arrives.
type PreviousFinding struct {
	SeverityRank  int16
	GateEffect    GateEffect
	Analysis      AnalysisState
	HadFixVersion bool
}

// CurrentFinding is the state implied by the newest scan occurrence.
type CurrentFinding struct {
	SeverityRank int16
	HasNewFix    bool
}

// DetectedChange describes a material change between two occurrences of the
// same finding that warrants reopening it for review.
type DetectedChange struct {
	ReviewRequired bool
	EventType      string
	Changes        map[string]any
}

// EvaluateChange compares a finding's previous and current state and reports
// a material change when the severity increased or a fix became available for
// the first time. It returns nil when nothing changed that warrants reopening.
func EvaluateChange(prev PreviousFinding, cur CurrentFinding) *DetectedChange {
	if cur.SeverityRank > prev.SeverityRank {
		return &DetectedChange{
			ReviewRequired: true,
			EventType:      "reopened_severity_change",
			Changes: map[string]any{
				"old_severity_rank": prev.SeverityRank,
				"new_severity_rank": cur.SeverityRank,
			},
		}
	}

	if cur.HasNewFix && !prev.HadFixVersion {
		return &DetectedChange{
			ReviewRequired: true,
			EventType:      "reopened_fix_available",
			Changes: map[string]any{
				"event": "fix_available",
			},
		}
	}

	return nil
}
