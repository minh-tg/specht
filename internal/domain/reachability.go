package domain

// ReachabilityHint carries a scanner/plugin observation about whether a
// finding is reachable. It is observation evidence only: the authoritative
// assessment is the four-state ReachabilityState used by the gate and
// reachability APIs (defined in the gate package as the core policy
// vocabulary). A scanner or source plugin may provide evidence but cannot
// override analyst reachability.
type ReachabilityHint struct {
	// State is the hint's semantic reading. Sources that only know whether a
	// call path exists (e.g. OSV's experimental boolean) map to reachable /
	// not_reachable; sources that cannot tell map to unknown.
	State ReachabilityState
	// Evidence is a human-readable justification the scanner produced.
	Evidence string
	// Source names the producer of the hint (e.g. "osv").
	Source string
}

// ReachabilityState is the canonical four-state reachability vocabulary.
// The empty string is not a valid stored state; persistence maps it to
// unknown.
type ReachabilityState string

const (
	ReachabilityReachable     ReachabilityState = "reachable"
	ReachabilityNotReachable  ReachabilityState = "not_reachable"
	ReachabilityUnknown       ReachabilityState = "unknown"
	ReachabilityNotApplicable ReachabilityState = "not_applicable"
)

// NormalizeReachabilityState returns the state itself when it is one of the
// four canonical values, and ReachabilityUnknown for the empty string or any
// other value.
func NormalizeReachabilityState(state ReachabilityState) ReachabilityState {
	switch state {
	case ReachabilityReachable, ReachabilityNotReachable, ReachabilityUnknown, ReachabilityNotApplicable:
		return state
	default:
		return ReachabilityUnknown
	}
}

// ValidReachabilityState reports whether state is one of the four canonical
// reachability states.
func ValidReachabilityState(state ReachabilityState) bool {
	return NormalizeReachabilityState(state) == state
}
