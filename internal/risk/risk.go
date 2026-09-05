// Package risk implements Specht's explainable risk scoring model: a pure,
// deterministic function from finding signals to a 0-100 score plus a
// per-signal explanation. The model is versioned (ModelVersion); weights
// change only with a version bump so scores stay comparable over time.
//
// v1 signals: severity rank, CVSS, reachability, environment exposure, age,
// and recurrence. Exploit intelligence (KEV/EPSS) is an explicit missing
// signal until exploit intelligence lands — absent inputs contribute nothing and are
// listed in Explanation.Missing rather than silently defaulted.
//
// The score is advisory only: it never accepts, suppresses, or waives a
// finding. Gate and waiver decisions stay in their own policy paths.
package risk

import "fmt"

// ModelVersion identifies the weight set a score was computed with.
const ModelVersion = "v1"

// MaxScore is the top of the 0-100 scale.
const MaxScore = 100

// Weights of model v1. They sum to MaxScore.
const (
	weightSeverity     = 30.0
	weightCVSS         = 15.0
	weightReachability = 15.0
	weightExposure     = 15.0
	weightAge          = 5.0
	weightRecurrence   = 5.0
	weightExploit      = 15.0
)

// Signals carries every model input. Pointer/empty values mean "unknown":
// the signal contributes zero points and appears in Explanation.Missing.
type Signals struct {
	// SeverityRank is the normalized 0-4 severity rank.
	SeverityRank int
	// CVSS is the 0-10 CVSS base score, nil when the scanner gave none.
	CVSS *float64
	// Reachability is reachable, not_reachable, unknown, not_applicable,
	// or empty when unassessed.
	Reachability string
	// EnvTier is production, staging, development, test, or empty.
	EnvTier string
	// InternetFacing adds exposure points on top of the tier.
	InternetFacing bool
	// AgeDays is days since first seen. Negative clamps to zero.
	AgeDays int
	// RecurrenceCount is how often the finding regressed after closure.
	RecurrenceCount int
	// HasKnownExploit is reserved for (KEV/EPSS). Nil today.
	HasKnownExploit *bool
}

// Component explains one signal's contribution to the score.
type Component struct {
	Signal  string  `json:"signal"`
	Weight  float64 `json:"weight"`
	Points  float64 `json:"points"`
	Detail  string  `json:"detail"`
	Missing bool    `json:"missing,omitempty"`
}

// Explanation is the full scoring result: version, total, per-signal
// breakdown, and the signals that were unknown.
type Explanation struct {
	Version    string      `json:"model_version"`
	Score      float64     `json:"score"`
	Max        int         `json:"max_score"`
	Band       string      `json:"band"`
	Components []Component `json:"components"`
	Missing    []string    `json:"missing,omitempty"`
}

// Band maps a score to a human label.
func Band(score float64) string {
	switch {
	case score >= 75:
		return "critical"
	case score >= 50:
		return "high"
	case score >= 25:
		return "medium"
	default:
		return "low"
	}
}

// Score evaluates v1 over the given signals. It is pure: the same signals
// always yield the same explanation.
func Score(s Signals) Explanation {
	e := Explanation{Version: ModelVersion, Max: MaxScore}
	add := func(signal string, weight, points float64, detail string, missing bool) {
		name := signal
		if missing {
			name = signal + " (unknown)"
			e.Missing = append(e.Missing, signal)
		}
		e.Components = append(e.Components, Component{
			Signal: name, Weight: weight, Points: points,
			Detail: detail, Missing: missing,
		})
		e.Score += points
	}

	rank := clampInt(s.SeverityRank, 0, 4)
	add("severity", weightSeverity, float64(rank)/4*weightSeverity,
		fmt.Sprintf("severity rank %d of 4", rank), false)

	if s.CVSS == nil {
		add("cvss", weightCVSS, 0, "no CVSS score reported", true)
	} else {
		v := clampFloat(*s.CVSS, 0, 10)
		add("cvss", weightCVSS, v/10*weightCVSS,
			fmt.Sprintf("CVSS base score %.1f of 10", v), false)
	}

	switch s.Reachability {
	case "reachable":
		add("reachability", weightReachability, weightReachability, "confirmed reachable", false)
	case "not_reachable":
		add("reachability", weightReachability, 0, "confirmed not reachable", false)
	case "not_applicable":
		add("reachability", weightReachability, 0, "reachability not applicable", false)
	case "unknown":
		add("reachability", weightReachability, weightReachability/2, "reachability unassessed", false)
	default:
		add("reachability", weightReachability, 0, "no reachability assessment", true)
	}

	switch s.EnvTier {
	case "production":
		pts := 10.0
		detail := "production environment"
		if s.InternetFacing {
			pts += 5
			detail += ", internet-facing"
		}
		add("exposure", weightExposure, pts, detail, false)
	case "staging":
		add("exposure", weightExposure, 6, "staging environment", false)
	case "development":
		add("exposure", weightExposure, 3, "development environment", false)
	case "test":
		add("exposure", weightExposure, 1, "test environment", false)
	default:
		add("exposure", weightExposure, 0, "unknown environment", true)
	}

	age := clampInt(s.AgeDays, 0, 90)
	add("age", weightAge, float64(age)/90*weightAge,
		fmt.Sprintf("open %d days", clampInt(s.AgeDays, 0, 1<<30)), false)

	rec := clampInt(s.RecurrenceCount, 0, 5)
	add("recurrence", weightRecurrence, float64(rec)/5*weightRecurrence,
		fmt.Sprintf("regressed %d time(s)", clampInt(s.RecurrenceCount, 0, 1<<30)), false)

	if s.HasKnownExploit == nil {
		add("exploit", weightExploit, 0, "no exploit intelligence yet", true)
	} else if *s.HasKnownExploit {
		add("exploit", weightExploit, weightExploit, "known exploit in the wild", false)
	} else {
		add("exploit", weightExploit, 0, "no known exploit", false)
	}

	if e.Score > MaxScore {
		e.Score = MaxScore
	}
	e.Band = Band(e.Score)
	return e
}

func clampInt(v, lo, hi int) int {
	if v < lo {
		return lo
	}
	if v > hi {
		return hi
	}
	return v
}

func clampFloat(v, lo, hi float64) float64 {
	if v < lo {
		return lo
	}
	if v > hi {
		return hi
	}
	return v
}
