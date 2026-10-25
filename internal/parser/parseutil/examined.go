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
	// with no artifacts gives no way to tell which files it scanned.
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
// A rule listed by a run that finished proves the rule ran. When any run lists
// its scanned files, every rule key also needs the finding's file to be among
// them, so a rule that ran over other files proves nothing about a file the run
// never listed. A run with no file list proves the rule for every file: SARIF
// from Semgrep carries none, and the rule list is all the output says.
func ExaminedFromRuns(runs []RuleRun) []string {
	var keys []string
	listsFiles := false
	for _, run := range runs {
		if run.Failed {
			continue
		}
		for _, id := range run.RuleIDs {
			if id == "" || run.Unproven[id] {
				continue
			}
			keys = append(keys, domain.ExaminedRule(run.Kind, id))
		}
		if len(run.Files) > 0 {
			listsFiles = true
			for _, f := range run.Files {
				keys = append(keys, domain.ExaminedFile(f))
			}
		}
	}
	if listsFiles {
		keys = append(keys, domain.ExaminedFilesScope)
	}
	return domain.NormalizeExaminedKeys(keys)
}
