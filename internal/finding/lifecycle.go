package finding

type AnalysisState string

const (
	StateUnanalyzed AnalysisState = "unanalyzed"
	StateActive     AnalysisState = "active"
	StateMuted      AnalysisState = "muted"
	StateResolved   AnalysisState = "resolved"
)

type GateEffect string

const (
	EffectBlock  GateEffect = "block"
	EffectIgnore GateEffect = "ignore"
	EffectNone   GateEffect = ""
)

type PreviousFinding struct {
	SeverityRank  int16
	GateEffect    GateEffect
	Analysis      AnalysisState
	HadFixVersion bool
}

type CurrentFinding struct {
	SeverityRank int16
	HasNewFix    bool
}

type DetectedChange struct {
	ReviewRequired bool
	EventType      string
	Changes        map[string]any
}

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
