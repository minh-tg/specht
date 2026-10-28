package parseutil

import "github.com/minh-tg/specht/internal/domain"

// RuleRun is what one SARIF run says about its own coverage. SARIF parsers
// fill it from the run so ExaminedFromRuns can turn it into examination keys.
type RuleRun struct {
	// Kind is the finding kind the run's results become.
	Kind string
	// RuleIDs are the rules the run lists in its tool component. A producer
	// lists the rules it loaded, so a listed rule with no result for a file
	// was run over it and found nothing.
	RuleIDs []string
	// Files are the artifacts the run lists, cleaned like result paths. A run
	// with no artifacts gives no way to tell which files it scanned, so it
	// proves nothing.
	Files []string
	// Failed is set when the run says it did not finish: an invocation that
	// reports executionSuccessful false or an error notification. Such a run
	// proves nothing.
	Failed bool
	// Unproven are rule ids that had a result the parser dropped, such as one
	// the producer suppressed. A suppressed result is not a fixed one.
	Unproven map[string]bool
}

// ExaminedFromRuns builds the examination keys of a SARIF document.
//
// Each key carries the number of its run, and a rule proves a finding absent
// only together with a file key of the same run. A run that lists rule R1 and
// file a says nothing about file b listed by another run, so a document that
// merges several runs (CodeQL over several languages, SARIF merged from
// several tools) proves a rule only for the files its own run scanned.
//
// A run with no file list proves nothing. SARIF from Semgrep carries none, and
// a rule list alone cannot show the rule ran over a file: the scan may have
// covered one directory, or a rule's own path filter may skip the file, and a
// finding hidden that way is not fixed. Rules and files are stored per run
// rather than as rule and file pairs, so a report carries at most the sum of
// its runs' rules and files, never their product.
func ExaminedFromRuns(runs []RuleRun) []string {
	var keys []string
	for n, run := range runs {
		if run.Failed || len(run.Files) == 0 {
			continue
		}
		proved := false
		for _, id := range run.RuleIDs {
			if id == "" || run.Unproven[id] {
				continue
			}
			proved = true
			keys = append(keys, domain.ExaminedRunRule(n, run.Kind, id))
		}
		if !proved {
			continue
		}
		for _, f := range run.Files {
			keys = append(keys, domain.ExaminedRunFile(n, f))
		}
	}
	return domain.NormalizeExaminedKeys(keys)
}
