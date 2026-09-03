// Package finding models the lifecycle of a single finding: the states an
// analyst can move it through and the change evaluation that decides when a
// previously-resolved finding must be reopened for review.
package finding

// AnalysisState is the analyst-driven lifecycle state of a finding.
type AnalysisState string

const (
	StateUnanalyzed AnalysisState = "unanalyzed"
	StateActive     AnalysisState = "active"
	StateMuted      AnalysisState = "muted"
	StateResolved   AnalysisState = "resolved"
)

// GateEffect is how a finding participates in the deployment gate while in a
// given analysis state.
type GateEffect string

const (
	EffectBlock  GateEffect = "block"
	EffectIgnore GateEffect = "ignore"
	EffectNone   GateEffect = ""
)

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
