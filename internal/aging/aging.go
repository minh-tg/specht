// Package aging computes finding age, SLA position, and age buckets as a
// pure function of timestamps: deterministic for the same inputs, safe
// across timezones (all math in UTC dates).
//
// SLA policy v1 (days to remediate by severity rank): critical 7, high 30,
// medium 90, low 180, unknown 90. The table is a versioned constant;
// per-project overrides are future work, not silent config.
//
// Buckets describe open risk age: new (<7d), aging (7-29d), stale (30-89d),
// debt (90d+). SLA applies to open/reopened findings only; resolved, muted,
// or otherwise closed states never report overdue.
package aging

import "time"

// SLA days by severity rank (0 unknown, 1 low, 2 medium, 3 high, 4 critical).
func SLADays(rank int) int {
	switch rank {
	case 4:
		return 7
	case 3:
		return 30
	case 2:
		return 90
	case 1:
		return 180
	default:
		return 90
	}
}

// Buckets for open risk age.
const (
	BucketNew    = "new"
	BucketAging  = "aging"
	BucketStale  = "stale"
	BucketDebt   = "debt"
	NewMaxDays   = 7
	AgingMaxDays = 30
	StaleMaxDays = 90
)

// Bucket maps age in days to an age bucket.
func Bucket(ageDays int) string {
	switch {
	case ageDays < NewMaxDays:
		return BucketNew
	case ageDays < AgingMaxDays:
		return BucketAging
	case ageDays < StaleMaxDays:
		return BucketStale
	default:
		return BucketDebt
	}
}

// Classification is one finding's aging verdict.
type Classification struct {
	AgeDays  int       `json:"age_days"`
	Bucket   string    `json:"bucket"`
	SLADays  int       `json:"sla_days"`
	DueDate  time.Time `json:"due_date"`
	Overdue  bool      `json:"overdue"`
	Reopened bool      `json:"reopened"`
}

// OpenState reports whether SLA applies to the finding state.
func OpenState(state string) bool {
	return state == "open" || state == "reopened"
}

// Classify evaluates one finding at now. firstSeen and now are truncated
// to UTC dates so the same instants give the same age in any timezone.
func Classify(firstSeen, now time.Time, severityRank int, state string, reopened bool) Classification {
	start := firstSeen.UTC().Truncate(24 * time.Hour)
	end := now.UTC().Truncate(24 * time.Hour)
	age := int(end.Sub(start).Hours() / 24)
	if age < 0 {
		age = 0
	}
	sla := SLADays(severityRank)
	due := start.AddDate(0, 0, sla)
	return Classification{
		AgeDays:  age,
		Bucket:   Bucket(age),
		SLADays:  sla,
		DueDate:  due,
		Overdue:  OpenState(state) && !end.Before(due),
		Reopened: reopened,
	}
}
